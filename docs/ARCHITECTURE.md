# Architecture

## System Overview

```
Mobile (zedra)                               Desktop (zedra-host)
+-------------------+                       +-------------------+
| GPUI + Metal/wgpu |                       | RPC Daemon        |
| Workspace views   |  iroh (QUIC/TLS 1.3) | SessionRegistry   |
| Terminal, Editor   | <====================> | PTY, Git, FS      |
| QR Scanner        |  NAT traversal/relay  | AI Prompt relay   |
+-------------------+                       +-------------------+
```

## Crates

| Crate | Role |
|-------|------|
| `zedra-rpc` | Protocol types, QR pairing codec. No deps on other zedra crates |
| `zedra-telemetry` | Typed Event enum + TelemetryBackend trait. Pure, no platform deps |
| `zedra-terminal` | Remote terminal view (alacritty VTE + GPUI rendering). No zedra deps — channels attached by app |
| `zedra-session` | Client session (iroh connection, RPC, auto-reconnect). Deps: `zedra-rpc`, `zedra-telemetry` |
| `zedra` | Mobile editor app (iOS + Android cdylib). Deps: `zedra-session`, `zedra-terminal`, `zedra-rpc`, `zedra-telemetry` |
| `zedra-host` | Desktop daemon + CLI. Deps: `zedra-rpc`, `zedra-telemetry` |

```
zedra-rpc          zedra-telemetry        zedra-terminal
(protocol)         (telemetry)            (terminal view, standalone)
    ↑  ↑               ↑  ↑                      ↑
    │  │               │  │                       │
    │  └───────┐   ┌───┘  │                       │
    │          │   │      │                       │
zedra-session  zedra-host │                       │
(client)       (daemon)   │                       │
    ↑                     │                       │
    └─────────────────────┴───────────────────────┘
                    zedra (mobile app)
```

## Transport Layer

All connectivity via iroh (QUIC/TLS 1.3). Path selection (LAN, hole-punch, relay) is automatic.

- **ALPN**: `zedra/rpc/3`
- **Host identity**: persistent Ed25519 keypair at `~/.config/zedra/identity.key`, used as iroh Endpoint secret key
- **Client identity**: persistent Ed25519 keypair in app data directory, used for PKI auth
- **Relay**: iroh-relay servers for NAT traversal fallback

### QR Pairing (`zedra-rpc/src/pairing.rs`)

QR encodes: `zedra://zedra<BASE32LOWER(postcard(ZedraPairingTicket))>`

`ZedraPairingTicket` contains: endpoint ID, relay URL, direct addrs, handshake key, session ID. Metadata (hostname, etc.) discovered post-connection via `SyncSession` RPC.

## RPC Protocol (`zedra-rpc/src/proto.rs`)

Type-safe RPC via irpc with postcard binary serialization over QUIC.

### Auth Flow

```
First pairing:   Register → Connect(None) → Challenge → AuthProve → Ok(SyncSessionResult) → RPC
Token resume:    Connect(session_token) → Ok(SyncSessionResult) → RPC
PKI reconnect:   Connect(None) → Challenge → AuthProve → Ok(SyncSessionResult) → RPC
```

- **Register**: HMAC-SHA256(handshake_key, pubkey||timestamp) proves QR possession
- **AuthProve**: client signs challenge nonce with Ed25519 key
- **Connect**: universal connection initiator; optionally includes `session_token` for fast resume
- **Authenticate**: deprecated/reserved append-only enum variant; not used by current clients

### RPC Methods

| Category   | Methods |
|------------|---------|
| Auth/bootstrap | `Register`, `Connect`, `AuthProve`, `SyncSession` |
| Health     | `Ping` |
| Session    | `GetSessionInfo`, `ListSessions`, `SubscribeHostInfo` |
| Filesystem | `FsList`, `FsRead`, `FsWrite`, `FsStat`, `FsDocsTree`, `FsWatch`, `FsUnwatch` |
| Terminal   | `TermCreate`, `TermAttach` (bidi stream), `TermResize`, `TermClose`, `TermList`, `TermReorder` |
| Git        | `GitStatus`, `GitDiff`, `GitLog`, `GitCommit`, `GitStage`, `GitUnstage`, `GitBranches`, `GitCheckout` |
| AI         | `AiPrompt` |
| LSP        | `LspDiagnostics`, `LspHover` |
| Events     | `Subscribe` (server-streaming: `HostEvent`) |
| Reserved   | `Authenticate` (deprecated auth challenge request), `SwitchSession` (does not switch the active dispatch session) |

`SwitchSession` remains in the append-only protocol surface, but it is not a
supported active workspace-switching mechanism. The current host handler returns
an explicit unsupported error because the authenticated dispatch worker remains
bound to the original session.

## Host Daemon (`zedra-host`)

### Startup

1. Load/generate host identity
2. Bind iroh Endpoint
3. Print QR code
4. Run accept loop (spawns handler per connection)

### Session Registry

Sessions persist independently of connections. PTYs keep running during disconnect. Terminals buffer output for replay on reconnect.

### Shared agent sessions (tmux)

For a shared-capable actor resuming a known session ID, tmux owns the agent PTY
instead of a bare `TermSession` child. Pi and OMP currently opt in through
`AgentActor::supports_shared_sessions()`. The host combines the registered actor
slug with the session ID into
`zedra-<slug>-<hex(session_id)>` (`crates/zedra-host/src/tmux.rs`) and runs that
actor's `resume_launch_command` in the pane. By default, Pi produces
`pi --session {quoted}` and OMP produces the exact `omp --resume {quoted}`,
where `{quoted}` is the shell-quoted session ID.

```
 registered actor + (slug, session_id)
                  │
                  │ resume_launch_command(session_id)
                  ▼
 tmux session zedra-<slug>-<hex(session_id)>
 ┌──────────────────────────────────────────┐
 │ pane: actor-owned resume command         │
 └────────────────────┬─────────────────────┘
     independent      │ tmux clients
   ┌──────────────┬───┴──────────────────┐
   │ macOS / SSH  │ Zedra TermSession A  │ Zedra TermSession B (card)
   └──────────────┴──────────────────────┘
```

tmux is authoritative for process liveness, pane metadata, and shared terminal
attachment. Each actor's own history store stays authoritative for persisted
sessions. Polls and destructive operations use the full `(slug, session_id)`
identity, so equal Pi and OMP session IDs select different tmux targets.

Foreign tmux sessions use a separate custom-session capability rather than the
owned `(slug, session_id)` path. The host scans the selected tmux server,
conservatively exposes only non-`zedra-*` sessions whose live panes identify at
least one registered actor, and revalidates the byte-exact name before attach
or termination. These sessions remain non-owned: actor detection supplies
display and optional terminal identity only, never a provider session ID or an
agent-history record. The Resume Session surface presents them in a distinct
`Tmux sessions` section ahead of the unchanged Pi/OMP history. Every `zedra-*`
name remains reserved for the ownership codec and is excluded from custom
discovery, including malformed encoded names.

- One Zedra client stays active per `ServerSession` (`SessionOccupied`
  otherwise), but each terminal card in that client is an independent tmux
  client. Several cards and manual tmux clients can attach to one shared pane.
  Simultaneous multi-device Zedra attachment is a future protocol/registry
  change, not a tmux one.
- Closing a Zedra terminal card removes only that tmux client. Terminating from
  the app kills the matching slug-bearing tmux session, its agent process, and
  every attached client without affecting another actor's same-ID session.
- `zedra-host` restart preserves the tmux server and its sessions. By default,
  tmux stores its socket under `/tmp`, so recreating a container destroys it.
  A global `tmux.socket` can select a persistent socket on a mounted volume;
  every SSH or manual client must use that same path. Owned sessions are
  re-discovered through the ownership codec; eligible foreign sessions are
  re-detected through the separate custom-session capability.
- Missing or old tmux prevents known-session shared resumes without falling
  back to a direct PTY. Persisted history remains available. Fresh agent
  launches remain direct because their provider session ID is not known before
  spawn.
- A Zedra card collects scrollback only from its attachment time; older pane
  output remains in tmux copy mode. Pane title and cwd come from sanitized tmux
  metadata and are display-only.

## Session Client (`zedra-session`)

### Connection Flow

1. Create iroh Endpoint with persistent client identity
2. `endpoint.connect(addr, ZEDRA_ALPN)`
3. `Register` only on first pairing
4. `Connect(session_token)` fast path, or `Connect(None) → Challenge → AuthProve` PKI fallback
5. Read the piggybacked `SyncSessionResult` from `ConnectResult::Ok` or `AuthProveResult::Ok`
6. `TermAttach` bidi stream per terminal (replay missed output via `last_seq`)
7. Spawn path watcher (tracks direct vs relay, RTT)

`SyncSession` remains available as a mid-session state refresh, but current
connect bootstrap does not require a separate `SyncSession` round trip.

### Auto-Reconnect

On connection drop: exponential backoff (1s, 2s, 4s, max 3 attempts). Reuses stored credentials. Terminal output buffers survive reconnect.

### Session → UI Bridge

See repo conventions in `AGENTS.md` and `docs/CONVENTIONS.md`. Summary:

```
Session (Tokio) → ConnectEvent via mpsc → cx.spawn loop → SessionState Entity → WorkspaceState Entity → Views
```

On the first successful sync, `Workspace` keeps the connecting UI in the Sync
phase until drawer bootstrap data is fetched: the file explorer root listing
and git status are refreshed before the initial terminal is opened or created.
On reconnect, the same drawer refresh is triggered in the background so terminal
reattach and user interaction are not blocked by file/git refresh latency.

### Appearance / theming

App settings live in `crates/zedra/src/settings.rs`. `ThemeState` is the appearance-specific part of those settings: it owns the user’s `ThemePreference` and a `ThemeBundle` (UI palette, editor theme, terminal theme). GPUI views read tokens through `theme::palette(cx)`; editor and terminal entities sync their sub-bundles on `ThemeStateEvent::Changed`. New UI must follow `docs/THEMING.md`—do not hardcode colors in views.

## Security

| Layer | Mechanism |
|-------|-----------|
| Transport | QUIC/TLS 1.3 (iroh, Ed25519 keys) |
| Identity | Ed25519 keypair per device |
| Pairing | QR out-of-band key exchange + HMAC registration |
| Session auth | PKI challenge-response + session tokens |
| Relay | Forwards encrypted QUIC packets only |
