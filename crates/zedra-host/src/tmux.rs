// Owned tmux session identities and pure parsers for tmux output.
// Subprocess operations live with the session operations built on top of this module.

use anyhow::{bail, ensure, Context, Result};
use data_encoding::HEXLOWER;

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
}
