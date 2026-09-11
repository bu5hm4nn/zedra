// Tmux session identities, pure output parsers, and the concrete subprocess
// client for Zedra-owned and conservatively detected non-owned sessions.
// Production discovers `tmux` on PATH; tests can inject a private server.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, ensure, Context as _, Result};
use data_encoding::HEXLOWER;

use crate::agent::utils::{command_output_with_timeout, shell_quote};

/// Namespace prefix for tmux sessions created and terminated by Zedra.
pub const OWNED_SESSION_PREFIX: &str = "zedra-";

/// Proven `list-panes` format for process fields: exactly 4 `|`-separated fields.
pub const PROCESS_PANE_FORMAT: &str =
    "#{pane_id}|#{pane_current_command}|#{pane_dead}|#{pane_dead_status}";

/// Proven `list-panes` format for display fields: id first, path/start command last,
/// title may contain `|`.
pub const METADATA_PANE_FORMAT: &str =
    "#{pane_id}|#{pane_title}|#{pane_current_path}|#{pane_start_command}";

/// Session name first; attached-client count and activity are parsed from the
/// right so names may contain `|`.
pub const SESSION_FORMAT: &str = "#{session_name}|#{session_attached}|#{session_activity}";

/// Encode an agent/session identity into its owned tmux session name.
pub fn owned_session_name(slug: &str, session_id: &str) -> Result<String> {
    validate_slug(slug)?;
    ensure!(!session_id.is_empty(), "empty agent session id");
    Ok(format!(
        "{OWNED_SESSION_PREFIX}{slug}-{}",
        HEXLOWER.encode(session_id.as_bytes())
    ))
}

fn validate_slug(slug: &str) -> Result<()> {
    ensure!(
        !slug.is_empty()
            && slug.split('-').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            }),
        "invalid agent slug: {slug:?}"
    );
    Ok(())
}

/// Whether a tmux session name belongs to Zedra's owned namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOwnership {
    Owned { slug: String, session_id: String },
    Untracked,
}

/// Classify a tmux session name; every foreign or malformed name is untracked.
pub fn session_ownership(name: &str) -> SessionOwnership {
    let Some((slug, encoded)) = name
        .strip_prefix(OWNED_SESSION_PREFIX)
        .and_then(|rest| rest.rsplit_once('-'))
    else {
        return SessionOwnership::Untracked;
    };
    if validate_slug(slug).is_err()
        || encoded.is_empty()
        || encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return SessionOwnership::Untracked;
    }
    let Some(session_id) = HEXLOWER
        .decode(encoded.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|session_id| !session_id.is_empty())
    else {
        return SessionOwnership::Untracked;
    };
    SessionOwnership::Owned {
        slug: slug.to_string(),
        session_id,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct TmuxSessionRecord {
    name: String,
    attached_clients: u32,
    activity_unix_seconds: i64,
}

fn parse_session_record(line: &str) -> Result<TmuxSessionRecord> {
    let (head, activity) = line
        .rsplit_once('|')
        .context("malformed tmux session record: missing activity")?;
    let (name, attached_clients) = head
        .rsplit_once('|')
        .context("malformed tmux session record: missing attached-client count")?;
    ensure!(
        !name.is_empty(),
        "malformed tmux session record: empty name"
    );
    Ok(TmuxSessionRecord {
        name: name.to_string(),
        attached_clients: attached_clients
            .parse()
            .with_context(|| format!("malformed session_attached value {attached_clients:?}"))?,
        activity_unix_seconds: activity
            .parse()
            .with_context(|| format!("malformed session_activity value {activity:?}"))?,
    })
}
// ---------------------------------------------------------------------------
// Owned pane records and the concrete tmux client
// ---------------------------------------------------------------------------

/// One Zedra-owned session's live pane state, from [`TmuxClient::list_sessions`].
#[derive(Debug, Clone)]
pub struct OwnedPane {
    pub slug: String,
    pub session_id: String,
    pub process: PaneProcess,
    pub metadata: PaneMetadata,
}

/// A non-owned tmux session containing one coherent registered agent kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetectedTmuxSession {
    pub name: String,
    pub agent_slug: String,
    pub identity_command: String,
    pub pane_title: String,
    pub current_path: String,
    pub start_command: String,
    pub attached_clients: u32,
    pub activity_unix_seconds: i64,
}

// ---------------------------------------------------------------------------
// Subprocess client: concrete tmux operations on the selected server
// ---------------------------------------------------------------------------

/// Subprocess deadline for every tmux client call; tmux calls are local and
/// fast, so a hung binary must never stall a resume or listing.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// How a tmux client selects its server.
#[derive(Debug, Clone)]
enum TmuxSocket {
    Default,
    Name(String),
    Path(PathBuf),
}

/// A discovered tmux client.
///
/// Production constructs this with [`TmuxClient::discover`]; tests inject a
/// binary path and socket name so they never touch the developer's server.
#[derive(Debug, Clone)]
pub struct TmuxClient {
    binary: PathBuf,
    socket: TmuxSocket,
    version: TmuxVersion,
}

impl TmuxClient {
    /// Discover `tmux` on `PATH` and verify it supports shared sessions.
    ///
    /// Returns the exact error a caller can surface, covering an invalid
    /// configured socket, missing binary, unparsable `tmux -V` output, and
    /// releases below the minimum.
    pub fn discover() -> Result<Self> {
        let socket = Self::configured_socket(crate::global_config::get().tmux.socket.as_deref())?;
        ensure!(
            crate::agent::utils::command_on_path("tmux"),
            "tmux is not installed or not on PATH; install tmux {} or newer for shared agent sessions",
            min_supported_version()
        );
        let mut client = Self {
            binary: PathBuf::from("tmux"),
            socket,
            version: min_supported_version(),
        };
        client.probe_version()?;
        tracing::info!(version = %client.version, "tmux: client ready");
        Ok(client)
    }

    fn configured_socket(socket: Option<&Path>) -> Result<TmuxSocket> {
        match socket {
            None => Ok(TmuxSocket::Default),
            Some(path) if !path.as_os_str().is_empty() && path.is_absolute() => {
                Ok(TmuxSocket::Path(path.to_path_buf()))
            }
            Some(path) => anyhow::bail!(
                "tmux.socket must be a non-empty absolute path: {}",
                path.display()
            ),
        }
    }

    /// Construct with an explicit binary path and optional private socket name.
    /// Used directly by tests; the ignored lifecycle tests pass `-L` names.
    pub fn with_socket(binary: impl AsRef<Path>, socket: Option<&str>) -> Result<Self> {
        let mut client = Self {
            binary: binary.as_ref().to_path_buf(),
            socket: socket
                .map(|socket| TmuxSocket::Name(socket.to_string()))
                .unwrap_or(TmuxSocket::Default),
            version: min_supported_version(),
        };
        client.probe_version()?;
        Ok(client)
    }

    /// Verified tmux release, from the discovery probe.
    pub fn version(&self) -> &TmuxVersion {
        &self.version
    }

    /// Exact argv for a tmux subcommand: binary, socket selection, then the
    /// subcommand and its arguments.
    fn argv(&self, args: &[&str]) -> Vec<String> {
        let mut argv = vec![self.binary.to_string_lossy().into_owned()];
        match &self.socket {
            TmuxSocket::Default => {}
            TmuxSocket::Name(name) => {
                argv.push("-L".to_string());
                argv.push(name.clone());
            }
            TmuxSocket::Path(path) => {
                argv.push("-S".to_string());
                argv.push(path.to_string_lossy().into_owned());
            }
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

    /// Prepare or attach to the owned session for `(slug, session_id)`.
    ///
    /// Runs `new-session -d -A` headless: an existing target ignores the inner
    /// command, so concurrent prepares start exactly one inner process. Sets
    /// session-scoped `mouse on` and `window-size largest` afterwards.
    /// Returns the command a terminal should run to attach.
    pub fn prepare_session(
        &self,
        slug: &str,
        session_id: &str,
        workdir: &Path,
        resume_command: &str,
    ) -> Result<String> {
        let name = owned_session_name(slug, session_id)?;
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
        // One retry resolves a fresh-socket connect race; an already-prepared
        // target answers identically on every call and must not be retried.
        if !output.status.success() && !already_prepared {
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

    /// List one agent's Zedra-owned sessions on this socket with their first
    /// pane's process and metadata state. Other agent namespaces, foreign
    /// sessions, and malformed sessions are skipped before pane inspection; an
    /// owned session whose pane data cannot be read is also skipped.
    pub fn list_sessions(&self, requested_slug: &str) -> Result<Vec<OwnedPane>> {
        validate_slug(requested_slug)?;
        let Some(session_text) = self.list_session_names()? else {
            return Ok(Vec::new());
        };
        let mut sessions = Vec::new();
        for name in session_text.lines() {
            let name = name.trim();
            let SessionOwnership::Owned { slug, session_id } = session_ownership(name) else {
                continue;
            };
            if slug != requested_slug {
                continue;
            }
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
                slug,
                session_id,
                process,
                metadata,
            });
        }
        Ok(sessions)
    }

    /// List non-owned sessions whose live panes identify one coherent agent.
    pub(crate) fn list_detected_sessions(&self) -> Result<Vec<DetectedTmuxSession>> {
        let Some(records) = self.list_session_records()? else {
            return Ok(Vec::new());
        };
        let mut sessions = Vec::new();
        for record in records {
            if record.name.starts_with(OWNED_SESSION_PREFIX) {
                continue;
            }
            if let Ok(Some(session)) = self.detect_session(&record) {
                sessions.push(session);
            }
        }
        Ok(sessions)
    }

    /// Revalidate a detected session and return its exact attach command.
    pub fn prepare_detected_attach(&self, name: &str) -> Result<(String, Option<String>)> {
        self.validate_detected_name(name)?;
        ensure!(
            self.session_exists(name)?,
            "tmux session {name:?} no longer exists"
        );
        let record = TmuxSessionRecord {
            name: name.to_string(),
            attached_clients: 0,
            activity_unix_seconds: 0,
        };
        let session = match self.detect_session(&record) {
            Ok(Some(session)) => session,
            Ok(None) => {
                ensure!(
                    self.session_exists(name)?,
                    "tmux session {name:?} no longer exists"
                );
                bail!("tmux session {name:?} no longer contains a detected agent")
            }
            Err(error) => {
                ensure!(
                    self.session_exists(name)?,
                    "tmux session {name:?} no longer exists"
                );
                return Err(error);
            }
        };
        let target = format!("={}", session.name);
        Ok((
            self.attach_command_with_shell_target(&shell_quote_always(&target)),
            Some(session.identity_command),
        ))
    }

    /// Revalidate and terminate one exact non-owned detected session.
    pub fn terminate_detected_session(&self, name: &str) -> Result<()> {
        self.validate_detected_name(name)?;
        if !self.session_exists(name)? {
            return Ok(());
        }
        let record = TmuxSessionRecord {
            name: name.to_string(),
            attached_clients: 0,
            activity_unix_seconds: 0,
        };
        match self.detect_session(&record) {
            Ok(Some(_)) => {}
            Ok(None) => {
                if !self.session_exists(name)? {
                    return Ok(());
                }
                bail!("tmux session {name:?} no longer contains a detected agent")
            }
            Err(error) => {
                if !self.session_exists(name)? {
                    return Ok(());
                }
                return Err(error);
            }
        }
        let target = format!("={name}");
        let output = self.run(
            &["kill-session", "-t", &target],
            "terminate the detected session",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            ensure!(
                stderr.contains("can't find session:") || Self::is_no_server(&stderr),
                "tmux terminate the detected session failed with {}: {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    fn validate_detected_name(&self, name: &str) -> Result<()> {
        ensure!(!name.is_empty(), "empty tmux session name");
        ensure!(
            !name.starts_with(OWNED_SESSION_PREFIX),
            "tmux session names beginning with {OWNED_SESSION_PREFIX:?} are reserved"
        );
        Ok(())
    }

    fn session_exists(&self, name: &str) -> Result<bool> {
        Ok(self
            .list_session_names()?
            .is_some_and(|session_text| session_text.lines().any(|candidate| candidate == name)))
    }

    fn detect_session(&self, record: &TmuxSessionRecord) -> Result<Option<DetectedTmuxSession>> {
        let target = format!("={}", record.name);
        let process_text = self.run_ok(
            &["list-panes", "-s", "-t", &target, "-F", PROCESS_PANE_FORMAT],
            "list detected session panes",
        )?;
        let metadata_text = self.run_ok(
            &[
                "list-panes",
                "-s",
                "-t",
                &target,
                "-F",
                METADATA_PANE_FORMAT,
            ],
            "list detected session panes",
        )?;

        let processes = process_text
            .lines()
            .map(parse_pane_process)
            .collect::<Result<Vec<_>>>()?;
        let metadata = metadata_text
            .lines()
            .map(parse_pane_metadata)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            processes.len() == metadata.len(),
            "tmux pane process and metadata counts differ"
        );

        let mut process_ids = HashSet::with_capacity(processes.len());
        ensure!(
            processes
                .iter()
                .all(|process| process_ids.insert(process.pane_id.as_str())),
            "tmux pane process records contain duplicate ids"
        );
        let mut metadata_by_id = HashMap::with_capacity(metadata.len());
        for pane in &metadata {
            ensure!(
                metadata_by_id.insert(pane.pane_id.as_str(), pane).is_none(),
                "tmux pane metadata records contain duplicate ids"
            );
        }
        ensure!(
            processes
                .iter()
                .all(|process| metadata_by_id.contains_key(process.pane_id.as_str())),
            "tmux pane process and metadata ids differ"
        );

        let mut selected: Option<(&str, &str, &PaneMetadata)> = None;
        for process in &processes {
            if process.dead {
                continue;
            }
            let pane_metadata = metadata_by_id
                .get(process.pane_id.as_str())
                .context("tmux pane metadata disappeared while pairing records")?;
            let current_command = process.current_command.trim();
            let detected = (!current_command.is_empty())
                .then(|| crate::agent::detect::detect_command(current_command))
                .flatten()
                .map(|slug| (slug, current_command));
            let detected = detected.or_else(|| {
                let start_command = pane_metadata.start_command.trim();
                (!start_command.is_empty())
                    .then(|| crate::agent::detect::detect_command(start_command))
                    .flatten()
                    .map(|slug| (slug, start_command))
            });
            let Some((slug, identity_command)) = detected else {
                continue;
            };
            if selected.is_some_and(|(selected_slug, _, _)| selected_slug != slug) {
                return Ok(None);
            }
            selected.get_or_insert((slug, identity_command, pane_metadata));
        }
        let Some((agent_slug, identity_command, pane)) = selected else {
            return Ok(None);
        };
        Ok(Some(DetectedTmuxSession {
            name: record.name.clone(),
            agent_slug: agent_slug.to_string(),
            identity_command: identity_command.to_string(),
            pane_title: pane.title.clone(),
            current_path: pane.current_path.clone(),
            start_command: pane.start_command.clone(),
            attached_clients: record.attached_clients,
            activity_unix_seconds: record.activity_unix_seconds,
        }))
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

    fn list_session_records(&self) -> Result<Option<Vec<TmuxSessionRecord>>> {
        let output = self.run(&["list-sessions", "-F", SESSION_FORMAT], "list sessions")?;
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
        let text = String::from_utf8(output.stdout)
            .context("tmux list sessions produced non-UTF-8 output")?;
        text.lines()
            .map(parse_session_record)
            .collect::<Result<Vec<_>>>()
            .map(Some)
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
    /// Accepts only an owned-namespace target derived by the codec — never a
    /// raw tmux name. The RPC layer validates actor capability. An
    /// already-vanished session counts as terminated.
    pub fn terminate_session(&self, slug: &str, session_id: &str) -> Result<()> {
        let name = owned_session_name(slug, session_id)?;
        let output = self.run(
            &["kill-session", "-t", &name],
            "terminate the shared session",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            ensure!(
                stderr.contains("can't find session:") || Self::is_no_server(&stderr),
                "tmux terminate the shared session failed with {}: {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    /// The command a terminal runs to attach: exec tmux, select the configured
    /// server, attach the supplied target, and exit with tmux's status so a
    /// failed attach does not leave a login shell behind.
    pub fn attach_command(&self, name: &str) -> String {
        self.attach_command_with_shell_target(&shell_quote(name))
    }

    fn attach_command_with_shell_target(&self, target: &str) -> String {
        let binary = shell_quote(&self.binary.to_string_lossy());
        let socket = match &self.socket {
            TmuxSocket::Default => String::new(),
            TmuxSocket::Name(name) => format!("-L {} ", shell_quote(name)),
            TmuxSocket::Path(path) => {
                format!("-S {} ", shell_quote(&path.to_string_lossy()))
            }
        };
        format!("exec {binary} {socket}attach-session -t {target} || exit $?")
    }
}

fn shell_quote_always(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "3f9d3b52-6a1d-4c4f-9a2b-8f0e5d1c7a10";

    #[test]
    fn owned_names_round_trip_agent_and_arbitrary_session_ids() {
        for slug in ["pi", "omp", "agent-with-hyphen"] {
            for id in [
                UUID,
                "with space",
                "with\ttab",
                "quote'and\"double",
                "shell;$meta|chars&`",
                "ünïcödé-セッション-🚀",
                "0",
            ] {
                let name = owned_session_name(slug, id).unwrap();
                let SessionOwnership::Owned {
                    slug: decoded_slug,
                    session_id,
                } = session_ownership(&name)
                else {
                    panic!("owned name must decode: {name}");
                };
                assert_eq!(decoded_slug, slug);
                assert_eq!(session_id, id);
                assert_eq!(
                    owned_session_name(&decoded_slug, &session_id).unwrap(),
                    name
                );
            }
        }
        assert_eq!(
            owned_session_name("pi", "session-1").unwrap(),
            "zedra-pi-73657373696f6e2d31"
        );
        assert_eq!(
            owned_session_name("omp", "session-1").unwrap(),
            "zedra-omp-73657373696f6e2d31"
        );
    }

    #[test]
    fn owned_names_reject_invalid_slugs_and_empty_ids() {
        for slug in ["", "-pi", "pi-", "pi--omp", "Pi", "pi_omp", "π"] {
            assert!(owned_session_name(slug, UUID).is_err(), "slug: {slug:?}");
        }
        assert!(owned_session_name("pi", "").is_err());
    }

    #[test]
    fn owned_names_are_collision_free() {
        let encoded = [
            owned_session_name("pi", "ab").unwrap(),
            owned_session_name("pi", "abc").unwrap(),
            owned_session_name("pi", "ba").unwrap(),
            owned_session_name("omp", "ab").unwrap(),
        ];
        for (index, name) in encoded.iter().enumerate() {
            assert!(!encoded[index + 1..].contains(name));
        }
    }

    #[test]
    fn foreign_and_malformed_names_are_untracked() {
        for name in [
            "main",
            "zsh-0",
            "zedra",
            "zedra-pi",
            "zedra--61",
            "zedra--pi-61",
            "zedra-pi--61",
            "zedra-Pi-61",
            "zedra-pi_omp-61",
            "zedra-π-aaaa",
            " zedra-pi-61",
            "zedra-pi-61 ",
            "zedra-pi-",
            "zedra-pi-abc",
            "zedra-pi-zzzz",
            "zedra-pi-ABCD",
            "zedra-pi-ff",
            "zedra-pi-6 1",
        ] {
            assert_eq!(session_ownership(name), SessionOwnership::Untracked);
        }
    }

    #[test]
    fn ownership_decodes_slug_and_session_id() {
        let name = owned_session_name("agent-with-hyphen", UUID).unwrap();
        assert_eq!(
            session_ownership(&name),
            SessionOwnership::Owned {
                slug: "agent-with-hyphen".to_string(),
                session_id: UUID.to_string(),
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
        assert_eq!(
            SESSION_FORMAT,
            "#{session_name}|#{session_attached}|#{session_activity}"
        );
    }

    #[test]
    fn session_records_preserve_pipe_names_and_parse_presence() {
        assert_eq!(
            parse_session_record("cars|review|3|1726000000").unwrap(),
            TmuxSessionRecord {
                name: "cars|review".into(),
                attached_clients: 3,
                activity_unix_seconds: 1_726_000_000,
            }
        );
    }

    #[test]
    fn session_records_reject_malformed_output() {
        for line in [
            "",
            "name",
            "name|1",
            "|1|1726000000",
            "name|many|1726000000",
            "name|1|recent",
        ] {
            assert!(parse_session_record(line).is_err(), "line: {line:?}");
        }
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
            socket: TmuxSocket::Default,
            version: min_supported_version(),
        };
        assert_eq!(
            default.argv(&["list-sessions"]),
            ["/usr/bin/tmux", "list-sessions"]
        );

        let private = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: TmuxSocket::Name("proof".to_string()),
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
    fn configured_path_argv_uses_server_socket() {
        let client = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: TmuxSocket::Path(PathBuf::from("/run/zedra/tmux.sock")),
            version: min_supported_version(),
        };
        assert_eq!(
            client.argv(&["-V"]),
            ["/usr/bin/tmux", "-S", "/run/zedra/tmux.sock", "-V"]
        );
        assert_eq!(
            client.argv(&["kill-session", "-t", "zedra-pi-61"]),
            [
                "/usr/bin/tmux",
                "-S",
                "/run/zedra/tmux.sock",
                "kill-session",
                "-t",
                "zedra-pi-61"
            ]
        );
    }

    #[test]
    fn configured_socket_rejects_empty_and_relative_paths() {
        for path in [Path::new(""), Path::new("relative/tmux.sock")] {
            let error = TmuxClient::configured_socket(Some(path)).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "tmux.socket must be a non-empty absolute path: {}",
                    path.display()
                )
            );
        }
    }

    #[test]
    fn prepare_session_argv_is_exact() {
        let client = TmuxClient {
            binary: PathBuf::from("/opt/tmux"),
            socket: TmuxSocket::Name("private".to_string()),
            version: min_supported_version(),
        };
        // `prepare_session` delegates argv to `run`/`argv`; asserting the exact
        // array here pins the create-or-attach form without spawning tmux.
        let args = [
            "new-session",
            "-d",
            "-A",
            "-s",
            &owned_session_name("pi", "session-1").unwrap(),
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
            socket: TmuxSocket::Name("proof".to_string()),
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
            socket: TmuxSocket::Default,
            version: min_supported_version(),
        };
        assert_eq!(
            default.attach_command("zedra-pi-61"),
            "exec /usr/bin/tmux attach-session -t zedra-pi-61 || exit $?"
        );

        let spaced_binary = TmuxClient {
            binary: PathBuf::from("/opt/My Tmux/tmux"),
            socket: TmuxSocket::Name("private socket".to_string()),
            version: min_supported_version(),
        };
        assert_eq!(
            spaced_binary.attach_command("zedra-pi-61"),
            "exec '/opt/My Tmux/tmux' -L 'private socket' attach-session -t zedra-pi-61 || exit $?"
        );

        let quoted = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: TmuxSocket::Default,
            version: min_supported_version(),
        };
        assert_eq!(
            quoted.attach_command("zedra-pi-6f'27"),
            "exec /usr/bin/tmux attach-session -t 'zedra-pi-6f'\\''27' || exit $?"
        );
        let path_socket = TmuxClient {
            binary: PathBuf::from("/usr/bin/tmux"),
            socket: TmuxSocket::Path(PathBuf::from("/tmp/Zedra's Socket/tmux.sock")),
            version: min_supported_version(),
        };
        assert_eq!(
            path_socket.attach_command("zedra-pi-61"),
            "exec /usr/bin/tmux -S '/tmp/Zedra'\\''s Socket/tmux.sock' attach-session -t zedra-pi-61 || exit $?"
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
        let names = [
            "zedra-pi-73657373696f6e",
            "zedra-omp-73657373696f6e",
            "main",
            "zedra-pi-",
            "ZEDRA-PI-73657373696F6E",
            "zedra-pi-zzz",
        ];
        let owned: Vec<(&str, &str)> = names
            .iter()
            .filter_map(|name| match session_ownership(name) {
                SessionOwnership::Owned { slug, .. } => Some((
                    *name,
                    match slug.as_str() {
                        "pi" => "pi",
                        "omp" => "omp",
                        _ => unreachable!(),
                    },
                )),
                SessionOwnership::Untracked => None,
            })
            .collect();
        assert_eq!(
            owned,
            [
                ("zedra-pi-73657373696f6e", "pi"),
                ("zedra-omp-73657373696f6e", "omp"),
            ]
        );
    }

    #[test]
    fn tmux_operations_reject_invalid_identity_before_spawn() {
        let client = TmuxClient {
            binary: PathBuf::from("/nonexistent/tmux-for-zedra-test"),
            socket: TmuxSocket::Default,
            version: min_supported_version(),
        };
        assert!(client
            .prepare_session("Pi", UUID, Path::new("/tmp/workdir"), "pi resume x")
            .unwrap_err()
            .to_string()
            .contains("invalid agent slug"));
        assert!(client
            .prepare_session("pi", "", Path::new("/tmp/workdir"), "pi resume x")
            .unwrap_err()
            .to_string()
            .contains("empty agent session id"));
        assert!(client
            .list_sessions("pi--omp")
            .unwrap_err()
            .to_string()
            .contains("invalid agent slug"));
        assert!(client
            .terminate_session("-pi", UUID)
            .unwrap_err()
            .to_string()
            .contains("invalid agent slug"));
        assert!(client
            .terminate_session("omp", "")
            .unwrap_err()
            .to_string()
            .contains("empty agent session id"));
    }

    #[test]
    fn list_sessions_error_propagates_when_binary_missing() {
        // A missing binary fails at the subprocess boundary and must surface,
        // not silently degrade to an empty owned list.
        let binaryless = TmuxClient {
            binary: PathBuf::from("/nonexistent/tmux-for-zedra-test"),
            socket: TmuxSocket::Name("definitely-missing-socket".to_string()),
            version: min_supported_version(),
        };
        let error = binaryless.list_sessions("pi").unwrap_err();
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

    /// Executable stub `tmux` binary for subprocess tests; never a real server.
    fn stub_tmux(name: &str, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("zedra-{name}-{}", std::process::id()));
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn list_sessions_filters_slug_before_pane_calls() {
        let pi_name = owned_session_name("pi", "same-id").unwrap();
        let omp_name = owned_session_name("omp", "same-id").unwrap();
        let script = format!(
            "#!/bin/sh\ncase \"$3\" in\n-V) echo 'tmux 3.5' ;;\nlist-sessions) printf '%s\\n' '{pi_name}' '{omp_name}' ;;\nlist-panes)\n  if [ \"$5\" = '{omp_name}' ]; then : > \"$0.marker\"; exit 1; fi\n  case \"$7\" in\n    *pane_current_command*) echo '%1|sh|0|' ;;\n    *) echo '%1|title|/tmp|sh' ;;\n  esac\n  ;;\nesac\nexit 0\n"
        );
        let stub = stub_tmux("slug-filter", &script);
        let marker = PathBuf::from(format!("{}.marker", stub.to_string_lossy()));
        let client = TmuxClient::with_socket(&stub, Some("stub")).expect("stub probes -V");
        let panes = client.list_sessions("pi").expect("list Pi sessions");
        assert_eq!(panes.len(), 1);
        assert_eq!(panes[0].slug, "pi");
        assert_eq!(panes[0].session_id, "same-id");
        assert!(
            !marker.exists(),
            "another agent namespace reached list-panes"
        );
        let _ = std::fs::remove_file(&stub);
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn prepare_session_accepts_already_prepared_session() {
        // The proven already-prepared answer (rc 1 + "not a terminal") must
        // succeed; the retry sees the same answer and would fail the prepare.
        let stub = stub_tmux(
            "already-prepared",
            "#!/bin/sh\ncase \"$3\" in\n-V) echo 'tmux 3.5' ;;\nnew-session) echo 'open terminal failed: not a terminal' >&2; exit 1 ;;\nesac\nexit 0\n",
        );
        let binary = stub.clone();
        let client = TmuxClient::with_socket(&binary, Some("stub")).expect("stub probes -V");
        let attach = client
            .prepare_session("pi", UUID, Path::new("/tmp/workdir"), "pi resume")
            .expect("already-prepared prepare must succeed");
        assert!(attach.contains("attach-session -t zedra-pi-"));
        let _ = std::fs::remove_file(&stub);
    }

    #[test]
    fn terminate_session_accepts_no_server_as_terminated() {
        // With `exit-empty on`, kill-session of the last owned session exits
        // the server; a second terminate then sees "no server running" and
        // must count as already terminated, like "can't find session:".
        let stub = stub_tmux(
            "no-server-terminate",
            "#!/bin/sh\ncase \"$3\" in\n-V) echo 'tmux 3.5' ;;\nkill-session) echo 'no server running on /tmp/tmux-0/stub' >&2; exit 1 ;;\nesac\nexit 0\n",
        );
        let binary = stub.clone();
        let client = TmuxClient::with_socket(&binary, Some("stub")).expect("stub probes -V");
        client
            .terminate_session("pi", UUID)
            .expect("no-server terminate must count as already terminated");
        let _ = std::fs::remove_file(&stub);
    }

    #[test]
    fn detected_sessions_scan_all_live_panes_and_exclude_reserved_names() {
        let script = "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) printf '%s\n' 'cars_us|2|1726000001' 'single|3|1726000002' 'shell-only|0|1726000003' 'zedra-malformed|0|1726000004' 'zedra-pi-61|0|1726000005' 'bad-query|0|1726000006' 'bad-record|0|1726000007' ;;
list-panes)
  case \"$6\" in '=zedra-'*) : > \"$0.reserved\"; exit 1 ;; esac
  if [ \"$6\" = '=bad-query' ]; then echo 'pane query failed' >&2; exit 9; fi
  case \"$6:$8\" in
    '=cars_us:'*pane_current_command*) printf '%s\n' '%1|pi|0|' '%2|sh|0|' '%3|claude|1|0' '%4|pi|0|' ;;
    '=cars_us:'*) printf '%s\n' '%2|two|/tmp|omp --resume session' '%1|one|/tmp|sh' '%4|four|/tmp|sh' '%3|dead|/tmp|claude' ;;
    '=single:'*pane_current_command*) printf '%s\n' '%5|sh|0|' '%6|claude|0|' ;;
    '=single:'*) printf '%s\n' '%5|five|/tmp|claude --continue' '%6|six|/tmp|omp --resume ignored' ;;
    '=shell-only:'*pane_current_command*) echo '%7|zsh|0|' ;;
    '=shell-only:'*) echo '%7|shell|/tmp|zsh' ;;
    '=bad-record:'*pane_current_command*) echo '%8|pi|0|' ;;
    '=bad-record:'*) echo '%9|bad|/tmp|pi' ;;
  esac
  ;;
esac
exit 0
";
        let stub = stub_tmux("detected-list", script);
        let marker = PathBuf::from(format!("{}.reserved", stub.to_string_lossy()));
        let client = TmuxClient::with_socket(&stub, Some("stub")).expect("stub probes -V");

        let sessions = client
            .list_detected_sessions()
            .expect("detected session listing");
        assert_eq!(
            sessions,
            [DetectedTmuxSession {
                name: "single".to_string(),
                agent_slug: "claude".to_string(),
                identity_command: "claude --continue".to_string(),
                pane_title: "five".to_string(),
                current_path: "/tmp".to_string(),
                start_command: "claude --continue".to_string(),
                attached_clients: 3,
                activity_unix_seconds: 1_726_000_002,
            }]
        );
        assert!(!marker.exists(), "reserved namespace reached list-panes");

        let _ = std::fs::remove_file(&stub);
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn detected_attach_always_quotes_simple_exact_target() {
        let stub = stub_tmux(
            "detected-simple-attach",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) echo 'cars_us' ;;
list-panes)
  [ \"$6\" = '=cars_us' ] || exit 7
  case \"$8\" in
    *pane_current_command*) echo '%1|pi|0|' ;;
    *) echo '%1|title|/tmp|sh' ;;
  esac
  ;;
esac
exit 0
",
        );
        let client = TmuxClient::with_socket(&stub, Some("stub")).expect("stub probes -V");

        let (attach, identity) = client
            .prepare_detected_attach("cars_us")
            .expect("prepare simple attach");

        assert_eq!(identity.as_deref(), Some("pi"));
        assert_eq!(
            attach,
            format!(
                "exec {} -L stub attach-session -t '=cars_us' || exit $?",
                shell_quote(&stub.to_string_lossy())
            )
        );

        let _ = std::fs::remove_file(&stub);
    }

    #[test]
    fn detected_attach_and_terminate_use_exact_argv_targets() {
        let name = "cars us;$HOME'quoted";
        let script = format!(
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) printf '%s\\n' {name} ;;
list-panes)
  [ \"$6\" = {target} ] || exit 7
  case \"$8\" in
    *pane_current_command*) echo '%1|pi|0|' ;;
    *) echo '%1|title|/tmp|sh' ;;
  esac
  ;;
kill-session)
  [ \"$5\" = {target} ] || exit 8
  printf '%s' \"$5\" > \"$0.killed\"
  ;;
esac
exit 0
",
            name = shell_quote(name),
            target = shell_quote(&format!("={name}")),
        );
        let stub = stub_tmux("detected-exact", &script);
        let marker = PathBuf::from(format!("{}.killed", stub.to_string_lossy()));
        let client =
            TmuxClient::with_socket(&stub, Some("private socket")).expect("stub probes -V");

        let (attach, identity) = client
            .prepare_detected_attach(name)
            .expect("prepare exact attach");
        assert_eq!(identity.as_deref(), Some("pi"));
        assert_eq!(
            attach,
            format!(
                "exec {} -L 'private socket' attach-session -t '=cars us;$HOME'\\''quoted' || exit $?",
                shell_quote(&stub.to_string_lossy())
            )
        );
        client
            .terminate_detected_session(name)
            .expect("terminate exact target");
        assert_eq!(
            std::fs::read_to_string(&marker).expect("kill marker"),
            format!("={name}")
        );

        let _ = std::fs::remove_file(&stub);
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn detected_targets_revalidate_presence_and_agent_identity() {
        let absent = stub_tmux(
            "detected-absent",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) echo 'gone-suffix' ;;
esac
exit 0
",
        );
        let client = TmuxClient::with_socket(&absent, Some("stub")).expect("stub probes -V");
        assert!(client
            .prepare_detected_attach("gone")
            .unwrap_err()
            .to_string()
            .contains("no longer exists"));
        client
            .terminate_detected_session("gone")
            .expect("disappeared target is terminated");

        let unsupported = stub_tmux(
            "detected-unsupported",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) echo 'plain-shell' ;;
list-panes)
  case \"$8\" in
    *pane_current_command*) echo '%1|zsh|0|' ;;
    *) echo '%1|title|/tmp|zsh' ;;
  esac
  ;;
kill-session) : > \"$0.killed\" ;;
esac
exit 0
",
        );
        let marker = PathBuf::from(format!("{}.killed", unsupported.to_string_lossy()));
        let client = TmuxClient::with_socket(&unsupported, Some("stub")).expect("stub probes -V");
        for result in [
            client.prepare_detected_attach("plain-shell").map(|_| ()),
            client.terminate_detected_session("plain-shell"),
        ] {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("no longer contains a detected agent"));
        }
        assert!(!marker.exists(), "unsupported target reached kill-session");
        for name in ["", "zedra-pi-61", "zedra-malformed"] {
            assert!(client.prepare_detected_attach(name).is_err());
            assert!(client.terminate_detected_session(name).is_err());
        }

        let _ = std::fs::remove_file(&absent);
        let _ = std::fs::remove_file(&unsupported);
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn detected_listing_treats_no_server_as_empty_and_surfaces_failures() {
        let no_server = stub_tmux(
            "detected-no-server",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions)
  echo 'no server running on /tmp/tmux-0/stub' >&2
  exit 1
  ;;
esac
exit 0
",
        );
        let client = TmuxClient::with_socket(&no_server, Some("stub")).expect("stub probes -V");
        assert_eq!(
            client.list_detected_sessions().expect("no server is empty"),
            Vec::new()
        );

        assert!(client.prepare_detected_attach("gone").is_err());
        client
            .terminate_detected_session("gone")
            .expect("no server means the target is already terminated");
        let broken = stub_tmux(
            "detected-broken-server",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions)
  echo 'socket corrupted' >&2
  exit 2
  ;;
esac
exit 0
",
        );
        let client = TmuxClient::with_socket(&broken, Some("stub")).expect("stub probes -V");
        let error = client.list_detected_sessions().unwrap_err();
        assert!(
            error.to_string().contains("socket corrupted"),
            "unexpected error: {error:#}"
        );

        let missing = TmuxClient {
            binary: PathBuf::from("/nonexistent/tmux-for-zedra-detected-test"),
            socket: TmuxSocket::Default,
            version: min_supported_version(),
        };
        assert!(missing.list_detected_sessions().is_err());

        let _ = std::fs::remove_file(&no_server);
        let _ = std::fs::remove_file(&broken);
    }

    #[test]
    fn detected_targets_handle_disappearance_during_revalidation() {
        let stub = stub_tmux(
            "detected-racy",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) [ -e \"$0.live\" ] && echo 'racy' ;;
list-panes)
  rm -f \"$0.live\"
  echo \"can't find session: racy\" >&2
  exit 1
  ;;
kill-session) : > \"$0.killed\" ;;
esac
exit 0
",
        );
        let live = PathBuf::from(format!("{}.live", stub.to_string_lossy()));
        let killed = PathBuf::from(format!("{}.killed", stub.to_string_lossy()));
        let client = TmuxClient::with_socket(&stub, Some("stub")).expect("stub probes -V");

        std::fs::write(&live, "").unwrap();
        let error = client.prepare_detected_attach("racy").unwrap_err();
        assert!(
            error.to_string().contains("no longer exists"),
            "unexpected error: {error:#}"
        );

        std::fs::write(&live, "").unwrap();
        client
            .terminate_detected_session("racy")
            .expect("disappearance during termination counts as success");
        assert!(!killed.exists(), "disappeared target reached kill-session");

        let _ = std::fs::remove_file(&stub);
        let _ = std::fs::remove_file(&live);
        let _ = std::fs::remove_file(&killed);
    }

    #[test]
    fn detected_termination_accepts_disappearance_at_kill() {
        let stub = stub_tmux(
            "detected-kill-race",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) echo 'kill-race' ;;
list-panes)
  case \"$8\" in
    *pane_current_command*) echo '%1|pi|0|' ;;
    *) echo '%1|title|/tmp|sh' ;;
  esac
  ;;
kill-session)
  [ \"$5\" = '=kill-race' ] || exit 8
  echo \"can't find session: kill-race\" >&2
  exit 1
  ;;
esac
exit 0
",
        );
        let client = TmuxClient::with_socket(&stub, Some("stub")).expect("stub probes -V");
        client
            .terminate_detected_session("kill-race")
            .expect("disappearance at kill counts as success");
        let _ = std::fs::remove_file(&stub);
    }

    #[test]
    fn detected_termination_surfaces_unexpected_kill_failure() {
        let stub = stub_tmux(
            "detected-kill-failure",
            "#!/bin/sh
case \"$3\" in
-V) echo 'tmux 3.5' ;;
list-sessions) echo 'kill-failure' ;;
list-panes)
  case \"$8\" in
    *pane_current_command*) echo '%1|pi|0|' ;;
    *) echo '%1|title|/tmp|sh' ;;
  esac
  ;;
kill-session)
  echo 'permission denied' >&2
  exit 4
  ;;
esac
exit 0
",
        );
        let client = TmuxClient::with_socket(&stub, Some("stub")).expect("stub probes -V");
        let error = client
            .terminate_detected_session("kill-failure")
            .unwrap_err();
        assert!(
            error.to_string().contains("permission denied"),
            "unexpected error: {error:#}"
        );
        let _ = std::fs::remove_file(&stub);
    }
}
