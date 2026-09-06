// Tmux session identities, pure output parsers, and the concrete subprocess
// client for Zedra-owned sessions. Production discovers `tmux` on PATH; the
// ignored lifecycle tests (`test(host): cover tmux session lifecycle`) inject
// a binary path and a private `-L` socket instead.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, ensure, Context as _, Result};
use data_encoding::HEXLOWER;

use crate::agent::utils::{command_output_with_timeout, shell_quote};

/// Namespace prefix for tmux sessions created and terminated by Zedra.
pub const OWNED_SESSION_PREFIX: &str = "zedra-pi-";

/// Proven `list-panes` format for process fields: exactly 4 `|`-separated fields.
pub const PROCESS_PANE_FORMAT: &str =
    "#{pane_id}|#{pane_current_command}|#{pane_dead}|#{pane_dead_status}";

/// Proven `list-panes` format for display fields: id first, path/start command last,
/// title may contain `|`.
pub const METADATA_PANE_FORMAT: &str =
    "#{pane_id}|#{pane_title}|#{pane_current_path}|#{pane_start_command}";

/// Encode a Pi session ID into the owned tmux session name.
pub fn owned_session_name(session_id: &str) -> Result<String> {
    ensure!(!session_id.is_empty(), "empty Pi session id");
    Ok(format!(
        "{OWNED_SESSION_PREFIX}{}",
        HEXLOWER.encode(session_id.as_bytes())
    ))
}

/// Decode an owned session name back to its Pi session ID.
/// Every foreign or malformed name is untracked and yields `None`.
pub fn session_id_from_name(name: &str) -> Option<String> {
    let encoded = name.strip_prefix(OWNED_SESSION_PREFIX)?;
    if encoded.is_empty() {
        return None;
    }
    let bytes = HEXLOWER.decode(encoded.as_bytes()).ok()?;
    let session_id = String::from_utf8(bytes).ok()?;
    if session_id.is_empty() {
        return None;
    }
    Some(session_id)
}

/// Whether a tmux session name belongs to Zedra's owned namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOwnership {
    Owned { session_id: String },
    Untracked,
}

/// Classify a tmux session name; a valid owned name wins over every foreign one.
pub fn session_ownership(name: &str) -> SessionOwnership {
    match session_id_from_name(name) {
        Some(session_id) => SessionOwnership::Owned { session_id },
        None => SessionOwnership::Untracked,
    }
}

/// A tmux release such as `3.3a`, ordered so later releases compare greater.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TmuxVersion {
    numbers: Vec<u64>,
    suffix: Option<char>,
}

/// Lowest tmux release Zedra's shared agent sessions require.
pub fn min_supported_version() -> TmuxVersion {
    TmuxVersion {
        numbers: vec![3, 3],
        suffix: Some('a'),
    }
}

impl std::fmt::Display for TmuxVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let numbers = self
            .numbers
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".");
        write!(f, "{numbers}")?;
        if let Some(suffix) = self.suffix {
            write!(f, "{suffix}")?;
        }
        Ok(())
    }
}

/// Parse `tmux -V` output such as `tmux 3.3a`; `next-3.x` counts as that release.
pub fn parse_version(output: &str) -> Result<TmuxVersion> {
    let unexpected = || format!("unrecognized `tmux -V` output: {output:?}");
    let rest = output
        .trim()
        .strip_prefix("tmux ")
        .with_context(unexpected)?
        .trim();
    let rest = rest.strip_prefix("next-").unwrap_or(rest);
    // Single trailing lowercase letter is the point-release suffix; 3.3 < 3.3a.
    let (numbers, suffix) = match rest.chars().next_back() {
        Some(last) if last.is_ascii_lowercase() => (&rest[..rest.len() - 1], Some(last)),
        _ => (rest, None),
    };
    let parsed = numbers
        .split('.')
        .map(|part| part.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .with_context(unexpected)?;
    Ok(TmuxVersion {
        numbers: parsed,
        suffix,
    })
}

/// Parse `tmux -V` output and require at least the supported minimum.
pub fn supported_version(output: &str) -> Result<TmuxVersion> {
    let version = parse_version(output)?;
    ensure!(
        version >= min_supported_version(),
        "tmux {} is too old; shared agent sessions require tmux {} or newer",
        version,
        min_supported_version()
    );
    Ok(version)
}

/// Process fields for one pane, from the proven process listing format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneProcess {
    pub pane_id: String,
    pub current_command: String,
    pub dead: bool,
    pub exit_code: Option<u32>,
}

/// Parse one process record; live panes carry an empty `pane_dead_status`.
pub fn parse_pane_process(line: &str) -> Result<PaneProcess> {
    let fields: Vec<&str> = line.split('|').collect();
    ensure!(
        fields.len() == 4,
        "malformed pane process record: expected 4 fields, got {}",
        fields.len()
    );
    let dead = match fields[2] {
        "0" => false,
        "1" => true,
        other => bail!("malformed pane_dead value {other:?}"),
    };
    let exit_code = match fields[3] {
        "" => None,
        status => Some(
            status
                .parse::<u32>()
                .with_context(|| format!("malformed pane_dead_status value {status:?}"))?,
        ),
    };
    Ok(PaneProcess {
        pane_id: fields[0].to_string(),
        current_command: fields[1].to_string(),
        dead,
        exit_code,
    })
}

/// Display metadata for one pane, from the proven metadata listing format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneMetadata {
    pub pane_id: String,
    pub title: String,
    pub current_path: String,
    pub start_command: String,
}

/// Parse one metadata record: id at the first `|`, path/start command at the last
/// two, and the pipe-tolerant title as the remainder. Fields may be empty.
pub fn parse_pane_metadata(line: &str) -> Result<PaneMetadata> {
    let (pane_id, tail) = line
        .split_once('|')
        .context("malformed pane metadata record: no pane id")?;
    let (head, start_command) = tail
        .rsplit_once('|')
        .context("malformed pane metadata record: missing start command")?;
    let (title, current_path) = head
        .rsplit_once('|')
        .context("malformed pane metadata record: missing current path")?;
    Ok(PaneMetadata {
        pane_id: pane_id.to_string(),
        title: title.to_string(),
        current_path: current_path.to_string(),
        start_command: start_command.to_string(),
    })
}
// ---------------------------------------------------------------------------
// Owned pane records and the concrete tmux client
// ---------------------------------------------------------------------------

/// One Zedra-owned session's live pane state, from [`TmuxClient::list_sessions`].
#[derive(Debug, Clone)]
pub struct OwnedPane {
    pub session_id: String,
    pub process: PaneProcess,
    pub metadata: PaneMetadata,
}

// ---------------------------------------------------------------------------
// Subprocess client: concrete tmux operations on Zedra-owned sessions
// ---------------------------------------------------------------------------

/// Subprocess deadline for every tmux client call; tmux calls are local and
/// fast, so a hung binary must never stall a resume or listing.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// A discovered tmux client on a private socket.
///
/// Production constructs this with [`TmuxClient::discover`]; tests inject a
/// binary path and socket name so they never touch the developer's server.
#[derive(Debug, Clone)]
pub struct TmuxClient {
    binary: PathBuf,
    socket: Option<String>,
    version: TmuxVersion,
}

impl TmuxClient {
    /// Discover `tmux` on `PATH` and verify it supports shared sessions.
    ///
    /// Returns the exact error a caller can surface, covering a missing
    /// binary, unparsable `tmux -V` output, and releases below the minimum.
    pub fn discover() -> Result<Self> {
        ensure!(
            crate::agent::utils::command_on_path("tmux"),
            "tmux is not installed or not on PATH; install tmux {} or newer for shared agent sessions",
            min_supported_version()
        );
        let client = Self::with_socket("tmux", None)?;
        tracing::info!(version = %client.version, "tmux: client ready");
        Ok(client)
    }

    /// Construct with an explicit binary path and optional private socket name.
    /// Used directly by tests; the ignored lifecycle tests pass `-L` names.
    pub fn with_socket(binary: impl AsRef<Path>, socket: Option<&str>) -> Result<Self> {
        let mut client = Self {
            binary: binary.as_ref().to_path_buf(),
            socket: socket.map(str::to_string),
            version: min_supported_version(),
        };
        client.probe_version()?;
        Ok(client)
    }

    /// Verified tmux release, from the discovery probe.
    pub fn version(&self) -> &TmuxVersion {
        &self.version
    }

    /// Exact argv for a tmux subcommand: binary, private-socket selection,
    /// then the subcommand and its arguments.
    fn argv(&self, args: &[&str]) -> Vec<String> {
        let mut argv = vec![self.binary.to_string_lossy().into_owned()];
        if let Some(socket) = &self.socket {
            argv.push("-L".to_string());
            argv.push(socket.clone());
        }
        argv.extend(args.iter().map(|arg| arg.to_string()));
        argv
    }

    fn probe_version(&mut self) -> Result<()> {
        let output = self.run(&["-V"], "probe the tmux version")?;
        self.version = supported_version(self.text(&output, "-V")?.as_str())?;
        Ok(())
    }

    fn text(&self, output: &std::process::Output, what: &str) -> Result<String> {
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            output.status.success(),
            "tmux {what} failed with {}: {}",
            output.status,
            stderr.trim()
        );
        String::from_utf8(output.stdout.clone())
            .with_context(|| format!("tmux {what} produced non-UTF-8 output"))
    }

    fn run(&self, args: &[&str], what: &str) -> Result<std::process::Output> {
        let argv = self.argv(args);
        let (program, rest) = argv.split_first().context("tmux argv is never empty")?;
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        command_output_with_timeout(program, &rest, None, COMMAND_TIMEOUT)
            .map_err(|error| anyhow::anyhow!("{error}"))
            .with_context(|| format!("tmux {what}"))
    }

    /// A successful run's decoded stdout; failures carry stderr context.
    fn run_ok(&self, args: &[&str], what: &str) -> Result<String> {
        let output = self.run(args, what)?;
        self.text(&output, what)
    }

    /// Prepare or attach to the owned session for `session_id`.
    ///
    /// Runs `new-session -d -A` headless: an existing target ignores the inner
    /// command, so concurrent prepares start exactly one inner process. Sets
    /// session-scoped `mouse on` and `window-size largest` afterwards.
    /// Returns the command a terminal should run to attach.
    pub fn prepare_session(
        &self,
        session_id: &str,
        workdir: &Path,
        resume_command: &str,
    ) -> Result<String> {
        let name = owned_session_name(session_id)?;
        let workdir = workdir.to_str().context("workdir is not UTF-8")?;
        let args = [
            "new-session",
            "-d",
            "-A",
            "-s",
            &name,
            "-c",
            workdir,
            resume_command,
        ];
        let output = self.run(&args, "prepare the shared session")?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let already_prepared = !output.status.success()
            && output.status.code() == Some(1)
            && stderr.contains("open terminal failed: not a terminal");
        // Headless attach races on an existing session fail with exactly this
        // message; the winner already created or attached the session.
        ensure!(
            output.status.success() || already_prepared,
            "tmux prepare the shared session failed with {}: {}",
            output.status,
            stderr.trim()
        );
        // A fresh socket can transiently fail to connect while the server
        // (started by this very call) is still binding; one retry resolves it.
        if !output.status.success() {
            let retry = self.run(&args, "prepare the shared session (retry)")?;
            ensure!(
                retry.status.success(),
                "tmux prepare the shared session failed (retry): {}",
                String::from_utf8_lossy(&retry.stderr).trim()
            );
        }
        // Session-scoped options: other sessions keep their own values.
        self.run_ok(&["set-option", "-t", &name, "mouse", "on"], "set mouse")?;
        self.run_ok(
            &["set-option", "-t", &name, "window-size", "largest"],
            "set window-size",
        )?;
        Ok(self.attach_command(&name))
    }

    /// List the Zedra-owned sessions on this socket with their first pane's
    /// process and metadata state. Foreign and malformed sessions are untracked
    /// and omitted; an owned session whose pane data cannot be read is skipped
    /// rather than poisoning the whole listing.
    pub fn list_sessions(&self) -> Result<Vec<OwnedPane>> {
        let Some(session_text) = self.list_session_names()? else {
            return Ok(Vec::new());
        };
        let mut sessions = Vec::new();
        for name in session_text.lines() {
            let name = name.trim();
            let SessionOwnership::Owned { session_id } = session_ownership(name) else {
                continue;
            };
            let Ok(process_text) = self.run_ok(
                &["list-panes", "-t", name, "-F", PROCESS_PANE_FORMAT],
                "list panes",
            ) else {
                continue;
            };
            let Ok(metadata_text) = self.run_ok(
                &["list-panes", "-t", name, "-F", METADATA_PANE_FORMAT],
                "list panes",
            ) else {
                continue;
            };
            let Some(process_line) = process_text.lines().next() else {
                continue;
            };
            let Ok(process) = parse_pane_process(process_line) else {
                continue;
            };
            let Some(metadata_line) = metadata_text.lines().next() else {
                continue;
            };
            let Ok(metadata) = parse_pane_metadata(metadata_line) else {
                continue;
            };
            sessions.push(OwnedPane {
                session_id,
                process,
                metadata,
            });
        }
        Ok(sessions)
    }

    /// The no-server case is the documented "available capability, empty list"
    /// signal, not an error.
    fn list_session_names(&self) -> Result<Option<String>> {
        let output = self.run(&["list-sessions", "-F", "#{session_name}"], "list sessions")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if Self::is_no_server(&stderr) {
                return Ok(None);
            }
            anyhow::bail!(
                "tmux list sessions failed with {}: {}",
                output.status,
                stderr.trim()
            );
        }
        String::from_utf8(output.stdout.clone())
            .map(Some)
            .context("tmux list sessions produced non-UTF-8 output")
    }

    /// Both proven fresh-socket stderr variants mean no server, not a broken
    /// client: "no server running on <path>" and "error connecting to <path>
    /// (No such file or directory)".
    fn is_no_server(stderr: &str) -> bool {
        stderr.contains("no server running on ")
            || stderr.contains("error connecting to ")
                && stderr.contains("No such file or directory")
    }

    /// Terminate the owned session rebuilt from `(slug, session_id)`.
    ///
    /// Accepts only the owning slug and an owned-namespace target derived by
    /// the codec — never a raw tmux name. An already-vanished session counts
    /// as terminated.
    pub fn terminate_session(&self, slug: &str, session_id: &str) -> Result<()> {
        // The `zedra-pi-` prefix is Pi's namespace; another agent needs its own.
        ensure!(
            slug == "pi",
            "agent {slug:?} does not own shared tmux sessions"
        );
        let name = owned_session_name(session_id)?;
        let output = self.run(
            &["kill-session", "-t", &name],
            "terminate the shared session",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Concurrent termination or a dead server already did the work.
            ensure!(
                stderr.contains("can't find session:"),
                "tmux terminate the shared session failed with {}: {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    /// The command a terminal runs to attach: exec tmux, optionally select the
    /// private socket, attach the owned target, and exit with tmux's status so
    /// a failed attach does not leave a login shell behind.
    pub fn attach_command(&self, name: &str) -> String {
        let binary = shell_quote(&self.binary.to_string_lossy());
        let socket = self
            .socket
            .as_deref()
            .map(|socket| format!("-L {} ", shell_quote(socket)))
            .unwrap_or_default();
        format!(
            "exec {binary} {socket}attach-session -t {} || exit $?",
            shell_quote(name)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "3f9d3b52-6a1d-4c4f-9a2b-8f0e5d1c7a10";

    #[test]
    fn owned_names_round_trip_arbitrary_ids() {
        for id in [
            UUID,
            "with space",
            "with\ttab",
            "quote'and\"double",
            "shell;$meta|chars&`",
            "ünïcödé-セッション-🚀",
            "0",
        ] {
            let name = owned_session_name(id).unwrap();
            assert!(name.starts_with(OWNED_SESSION_PREFIX));
            let payload = &name[OWNED_SESSION_PREFIX.len()..];
            assert!(!payload.is_empty());
            assert!(
                payload
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "payload: {payload}"
            );
            assert_eq!(session_id_from_name(&name).as_deref(), Some(id));
        }
    }

    #[test]
    fn owned_names_reject_empty_ids() {
        assert!(owned_session_name("").is_err());
        assert_eq!(session_id_from_name(OWNED_SESSION_PREFIX), None);
    }

    #[test]
    fn owned_names_are_collision_free_and_stable() {
        let encoded = ["ab", "abc", "ba"].map(|id| owned_session_name(id).unwrap());
        assert_ne!(encoded[0], encoded[1]);
        assert_ne!(encoded[0], encoded[2]);
        let id = "ünïcödé";
        let name = owned_session_name(id).unwrap();
        let decoded = session_id_from_name(&name).unwrap();
        assert_eq!(owned_session_name(&decoded).unwrap(), name);
    }

    #[test]
    fn foreign_and_malformed_names_are_untracked() {
        for name in [
            "main",
            "zsh-0",
            "zedra-pi",
            "zedra-π-aaaa",
            " zedra-pi-61",
            "zedra-pi-61 ",
            "zedra-pi-",     // empty payload
            "zedra-pi-abc",  // odd length
            "zedra-pi-zzzz", // not hex
            "zedra-pi-ABCD", // uppercase hex
            "zedra-pi-ff",   // invalid UTF-8
            "zedra-pi-6 1",  // non-hex byte
        ] {
            assert_eq!(session_id_from_name(name), None, "name: {name:?}");
            assert_eq!(session_ownership(name), SessionOwnership::Untracked);
        }
    }

    #[test]
    fn ownership_precedence_favors_valid_owned_names() {
        let name = owned_session_name(UUID).unwrap();
        assert_eq!(
            session_ownership(&name),
            SessionOwnership::Owned {
                session_id: UUID.to_string()
            }
        );
    }

    #[test]
    fn listing_formats_match_the_proven_two_call_contract() {
        assert_eq!(
            PROCESS_PANE_FORMAT,
            "#{pane_id}|#{pane_current_command}|#{pane_dead}|#{pane_dead_status}"
        );
        assert_eq!(
            METADATA_PANE_FORMAT,
            "#{pane_id}|#{pane_title}|#{pane_current_path}|#{pane_start_command}"
        );
    }

    #[test]
    fn version_ordering_matches_tmux_releases() {
        let min = min_supported_version();
        assert_eq!(parse_version("tmux 3.3a").unwrap(), min);
        assert!(parse_version("tmux 3.3").unwrap() < min);
        assert!(parse_version("tmux 3.3b").unwrap() > min);
        assert!(parse_version("tmux 3.4").unwrap() > min);
        assert!(parse_version("tmux 4.0").unwrap() > parse_version("tmux 3.10").unwrap());
        assert!(parse_version("tmux 3.10").unwrap() > parse_version("tmux 3.9").unwrap());
        assert_eq!(parse_version(" tmux 3.3a\n").unwrap(), min);
        assert_eq!(
            parse_version("tmux next-3.5").unwrap(),
            parse_version("tmux 3.5").unwrap()
        );
    }

    #[test]
    fn version_rejects_unparseable_output() {
        for output in [
            "tmux master",
            "tmux 3.A",
            "tmux 3.a",
            "tmux 3.3a next",
            "",
            "open terminal failed: not a terminal",
        ] {
            assert!(parse_version(output).is_err(), "output: {output:?}");
        }
    }
    #[test]
    fn supported_version_enforces_minimum() {
        assert_eq!(
            supported_version("tmux 3.3a").unwrap(),
            min_supported_version()
        );
        assert!(supported_version("tmux 3.4").is_ok());
        assert!(supported_version("tmux next-3.5").is_ok());
        assert!(supported_version("tmux 3.3").is_err());
        assert!(supported_version("tmux 3.2").is_err());
        assert!(supported_version("tmux 2.9").is_err());
        assert!(supported_version("tmux 3").is_err());
        assert!(supported_version("tmux master").is_err());
    }

    #[test]
    fn pane_process_records_parse_live_and_dead_panes() {
        let live = parse_pane_process("%0|zsh|0|").unwrap();
        assert_eq!(live.pane_id, "%0");
        assert_eq!(live.current_command, "zsh");
        assert!(!live.dead);
        assert_eq!(live.exit_code, None);

        let dead = parse_pane_process("%1|pi|1|7").unwrap();
        assert!(dead.dead);
        assert_eq!(dead.exit_code, Some(7));

        let signaled = parse_pane_process("%2|python3|1|137").unwrap();
        assert_eq!(signaled.exit_code, Some(137));
    }

    #[test]
    fn pane_process_records_reject_malformed_input() {
        for line in [
            "",
            "%0|zsh",
            "%0|zsh|0",
            "%0|zsh|0||extra",
            "%0|zsh|true|",
            "%0|zsh|0|code",
        ] {
            assert!(parse_pane_process(line).is_err(), "line: {line:?}");
        }
    }

    #[test]
    fn pane_metadata_records_parse_with_pipe_titles() {
        let plain = parse_pane_metadata("%0|host|/tmp/proof|pi resume").unwrap();
        assert_eq!(plain.pane_id, "%0");
        assert_eq!(plain.title, "host");
        assert_eq!(plain.current_path, "/tmp/proof");
        assert_eq!(plain.start_command, "pi resume");

        let piped = parse_pane_metadata("%1|a|b|title|/home/u|\"pi resume\"").unwrap();
        assert_eq!(piped.title, "a|b|title");
        assert_eq!(piped.current_path, "/home/u");
        assert_eq!(piped.start_command, "\"pi resume\"");

        let empty = parse_pane_metadata("%2|||").unwrap();
        assert_eq!(empty.pane_id, "%2");
        assert_eq!(empty.title, "");
        assert_eq!(empty.current_path, "");
        assert_eq!(empty.start_command, "");
    }

    #[test]
    fn pane_metadata_records_reject_malformed_input() {
        for line in ["", "%0", "%0|title", "%0|title|path"] {
            assert!(parse_pane_metadata(line).is_err(), "line: {line:?}");
        }
    }

    #[test]
    fn argv_construction_carries_socket_and_subcommand() {
        let default = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: None,
            version: min_supported_version(),
        };
        assert_eq!(
            default.argv(&["list-sessions"]),
            ["/usr/bin/tmux", "list-sessions"]
        );

        let private = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: Some("proof".to_string()),
            version: min_supported_version(),
        };
        assert_eq!(
            private.argv(&["kill-session", "-t", "zedra-pi-61"]),
            [
                "/usr/bin/tmux",
                "-L",
                "proof",
                "kill-session",
                "-t",
                "zedra-pi-61"
            ]
        );
    }

    #[test]
    fn prepare_session_argv_is_exact() {
        let client = TmuxClient {
            binary: PathBuf::from("/opt/tmux"),
            socket: Some("private".to_string()),
            version: min_supported_version(),
        };
        // `prepare_session` delegates argv to `run`/`argv`; asserting the exact
        // array here pins the create-or-attach form without spawning tmux.
        let args = [
            "new-session",
            "-d",
            "-A",
            "-s",
            &owned_session_name("session-1").unwrap(),
            "-c",
            "/tmp/proof/workdir",
            "pi resume abc",
        ];
        assert_eq!(
            client.argv(&args),
            [
                "/opt/tmux",
                "-L",
                "private",
                "new-session",
                "-d",
                "-A",
                "-s",
                "zedra-pi-73657373696f6e2d31",
                "-c",
                "/tmp/proof/workdir",
                "pi resume abc"
            ]
        );
    }

    #[test]
    fn set_option_argv_matches_proven_forms() {
        let client = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: Some("proof".to_string()),
            version: min_supported_version(),
        };
        assert_eq!(
            client.argv(&["set-option", "-t", "zedra-pi-61", "mouse", "on"]),
            [
                "/usr/bin/tmux",
                "-L",
                "proof",
                "set-option",
                "-t",
                "zedra-pi-61",
                "mouse",
                "on"
            ]
        );
        assert_eq!(
            client.argv(&["set-option", "-t", "zedra-pi-61", "window-size", "largest"]),
            [
                "/usr/bin/tmux",
                "-L",
                "proof",
                "set-option",
                "-t",
                "zedra-pi-61",
                "window-size",
                "largest"
            ]
        );
    }

    #[test]
    fn attach_command_quotes_binary_socket_and_target() {
        let default = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: None,
            version: min_supported_version(),
        };
        assert_eq!(
            default.attach_command("zedra-pi-61"),
            "exec /usr/bin/tmux attach-session -t zedra-pi-61 || exit $?"
        );

        let spaced_binary = TmuxClient {
            binary: PathBuf::from("/opt/My Tmux/tmux"),
            socket: Some("private socket".to_string()),
            version: min_supported_version(),
        };
        assert_eq!(
            spaced_binary.attach_command("zedra-pi-61"),
            "exec '/opt/My Tmux/tmux' -L 'private socket' attach-session -t zedra-pi-61 || exit $?"
        );

        let quoted = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: None,
            version: min_supported_version(),
        };
        assert_eq!(
            quoted.attach_command("zedra-pi-6f'27"),
            "exec /usr/bin/tmux attach-session -t 'zedra-pi-6f'\\''27' || exit $?"
        );
    }

    #[test]
    fn no_server_detection_covers_both_proven_variants() {
        assert!(TmuxClient::is_no_server(
            "no server running on /tmp/tmux-0/proof"
        ));
        assert!(TmuxClient::is_no_server(
            "error connecting to /tmp/tmux-0/proof (No such file or directory)"
        ));
        assert!(!TmuxClient::is_no_server("can't find session: zedra-pi-61"));
        assert!(!TmuxClient::is_no_server("socket corrupted"));
    }

    #[test]
    fn list_sessions_skips_foreign_and_malformed_names() {
        // Pure classification re-check over mixed names: owned names survive,
        // foreign and malformed names never reach pane listing.
        let names = [
            "zedra-pi-73657373696f6e",
            "main",
            "zedra-pi-",
            "ZEDRA-PI-73657373696F6E",
            "zedra-pi-zzz",
        ];
        let owned: Vec<&str> = names
            .iter()
            .filter(|name| matches!(session_ownership(name), SessionOwnership::Owned { .. }))
            .copied()
            .collect();
        assert_eq!(owned, ["zedra-pi-73657373696f6e"]);
    }

    #[test]
    fn prepare_session_rejects_empty_session_ids_before_spawn() {
        let client = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: None,
            version: min_supported_version(),
        };
        let error = client
            .prepare_session("", Path::new("/tmp/workdir"), "pi resume x")
            .unwrap_err();
        assert!(error.to_string().contains("empty Pi session id"));
    }

    #[test]
    fn terminate_session_refuses_foreign_slugs_and_empty_ids() {
        let client = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: None,
            version: min_supported_version(),
        };
        let error = client.terminate_session("claude", UUID).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not own shared tmux sessions"));

        let error = client.terminate_session("pi", "").unwrap_err();
        assert!(error.to_string().contains("empty Pi session id"));
    }

    #[test]
    fn list_sessions_error_propagates_when_binary_missing() {
        // A missing binary fails at the subprocess boundary and must surface,
        // not silently degrade to an empty owned list.
        let binaryless = TmuxClient {
            binary: PathBuf::from("/nonexistent/tmux-for-zedra-test"),
            socket: Some("definitely-missing-socket".to_string()),
            version: min_supported_version(),
        };
        let error = binaryless.list_sessions().unwrap_err();
        assert!(
            error.to_string().contains("list sessions"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn list_sessions_classifies_proven_no_server_stderr() {
        // The two proven fresh-socket stderr variants classify as no-server,
        // which `list_session_names` maps to `Ok(None)` -> empty owned list.
        for stderr in [
            "no server running on /tmp/tmux-0/proof",
            "error connecting to /tmp/tmux-0/proof (No such file or directory)",
        ] {
            assert!(TmuxClient::is_no_server(stderr), "stderr: {stderr:?}");
        }
    }
}
