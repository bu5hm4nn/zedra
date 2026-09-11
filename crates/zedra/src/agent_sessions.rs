use futures::{FutureExt, StreamExt, future, pin_mut};
use gpui::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use tracing::error;
use zedra_rpc::proto::{AgentSessionSummary, TmuxSessionListResult, TmuxSessionSummary};
use zedra_session::SessionHandle;

use crate::agent_ui::{
    AgentSessionRow, SharedSessionPollHandle, flatten_session_sections, group_sessions_by_day,
    merge_shared_sessions, new_session_list_state, render_virtualized_agent_session_list,
    reset_session_list_state, spawn_shared_session_poll,
};
use crate::fonts;
use crate::platform_bridge::{self, HapticFeedback};
use crate::theme;
use crate::ui::{
    chevron_back_button, subscreen_empty_text, subscreen_padded_body, subscreen_page_unscrolled,
    subscreen_refresh_button,
};
use crate::workspace_action;
use crate::workspace_state::{AgentSharedSessions, WorkspaceState};

#[derive(Clone, Debug)]
enum LoadState {
    Loading,
    Ready,
    Error(String),
}

const TMUX_SESSION_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct TmuxSessionPollHandle {
    wake: Rc<RefCell<futures::channel::mpsc::Sender<()>>>,
}

impl TmuxSessionPollHandle {
    fn request_refresh(&self) {
        let _ = self.wake.borrow_mut().try_send(());
    }
}

struct TmuxPollApply {
    rows_changed: bool,
    error_to_log: Option<String>,
}

fn apply_tmux_poll_result(
    sessions: &mut Vec<TmuxSessionSummary>,
    error_stretch: &mut Option<String>,
    supported: bool,
    result: Result<TmuxSessionListResult, String>,
) -> TmuxPollApply {
    if !supported {
        let rows_changed = !sessions.is_empty();
        sessions.clear();
        *error_stretch = None;
        return TmuxPollApply {
            rows_changed,
            error_to_log: None,
        };
    }

    match result {
        Ok(result) => {
            let next_sessions = if result.available {
                result.sessions
            } else {
                Vec::new()
            };
            let rows_changed = *sessions != next_sessions;
            *sessions = next_sessions;
            *error_stretch = None;
            TmuxPollApply {
                rows_changed,
                error_to_log: None,
            }
        }
        Err(error) => {
            let error_to_log =
                (error_stretch.as_deref() != Some(error.as_str())).then(|| error.clone());
            *error_stretch = Some(error);
            TmuxPollApply {
                rows_changed: false,
                error_to_log,
            }
        }
    }
}

pub struct AgentSessions {
    session_handle: SessionHandle,
    workspace_state: Entity<WorkspaceState>,
    /// Persisted rows from the last load, for re-merging with fresh shares.
    sessions: Vec<AgentSessionSummary>,
    rows: Rc<Vec<AgentSessionRow>>,
    list_state: ListState,
    load_state: LoadState,
    loading_epoch: u64,
    shared_poll: SharedSessionPollHandle,
    /// Last available custom-session listing, retained across transport errors.
    tmux_sessions: Vec<TmuxSessionSummary>,
    /// Transport error already logged for the current unchanged failure stretch.
    tmux_error_stretch: Option<String>,
    tmux_poll: TmuxSessionPollHandle,
    _tmux_poll_task: Task<()>,
    _tasks: Vec<Task<()>>,
}

impl AgentSessions {
    pub fn new(
        session_handle: SessionHandle,
        workspace_state: Entity<WorkspaceState>,
        cx: &mut Context<Self>,
    ) -> Self {
        let (poll_task, poll_handle) = spawn_shared_session_poll(
            session_handle.clone(),
            workspace_state.clone(),
            Vec::new(),
            |this, cx| this.rebuild_rows(cx),
            cx,
        );
        let (tmux_poll_task, tmux_poll) = spawn_tmux_session_poll(session_handle.clone(), cx);
        let mut view = Self {
            session_handle,
            workspace_state,
            sessions: Vec::new(),
            rows: Rc::new(Vec::new()),
            list_state: new_session_list_state(0),
            load_state: LoadState::Loading,
            loading_epoch: 0,
            shared_poll: poll_handle,
            tmux_sessions: Vec::new(),
            tmux_error_stretch: None,
            tmux_poll,
            _tmux_poll_task: tmux_poll_task,
            _tasks: vec![poll_task],
        };
        view.load(false, cx);
        view
    }

    fn load(&mut self, refresh: bool, cx: &mut Context<Self>) {
        self.loading_epoch = self.loading_epoch.wrapping_add(1);
        let epoch = self.loading_epoch;
        self.set_rows(Vec::new());
        self.load_state = LoadState::Loading;
        cx.notify();

        let handle = self.session_handle.clone();
        let task = cx.spawn(async move |this, cx| {
            let mut sessions = Vec::new();
            let mut errors = Vec::new();
            let mut poll_targets = None;
            match handle.agent_list(refresh).await {
                Ok(agents) => {
                    // Fan out per-agent history scans so one slow agent doesn't
                    // gate the rest. The live coordinator polls these distinct
                    // host-returned targets sequentially.
                    let mut slugs = Vec::new();
                    for agent in agents.into_iter().filter(|agent| agent.shows_detail) {
                        if !slugs.iter().any(|slug| slug == &agent.slug) {
                            slugs.push(agent.slug);
                        }
                    }
                    poll_targets = Some(slugs.clone());
                    let results = futures::future::join_all(slugs.into_iter().map(|slug| {
                        let handle = handle.clone();
                        async move {
                            let result = handle.agent_sessions(slug.clone(), refresh, 0).await;
                            (slug, result)
                        }
                    }))
                    .await;
                    for (slug, result) in results {
                        match result {
                            Ok(mut rows) => sessions.append(&mut rows),
                            Err(err) => errors.push(format!("{slug}: {err}")),
                        }
                    }
                }
                Err(err) => errors.push(err.to_string()),
            }
            let _ = this.update(cx, |this, cx| {
                if this.loading_epoch != epoch {
                    return;
                }
                if let Some(targets) = poll_targets {
                    this.shared_poll.set_targets(targets);
                }
                this.sessions = sessions;
                this.rebuild_rows(cx);
                this.load_state = if errors.is_empty() {
                    LoadState::Ready
                } else if this.sessions.is_empty() {
                    LoadState::Error(errors.join("; "))
                } else {
                    error!("agent sessions partial failure: {}", errors.join("; "));
                    LoadState::Ready
                };
                cx.notify();
            });
        });
        self._tasks.push(task);
    }

    /// `ListState` caches row measurements, so it must be reset whenever the
    /// row set changes or heights carry over from the previous load.
    fn set_rows(&mut self, rows: Vec<AgentSessionRow>) {
        reset_session_list_state(&self.list_state, rows.len());
        self.rows = Rc::new(rows);
    }

    /// Manual refresh: reload history and nudge both live-session polls.
    fn refresh(&mut self, cx: &mut Context<Self>) {
        self.shared_poll.request_refresh();
        self.tmux_poll.request_refresh();
        self.load(true, cx);
    }

    /// Re-derive custom rows followed by persisted history and its live snapshot.
    fn rebuild_rows(&mut self, cx: &mut Context<Self>) {
        let snapshots = self.workspace_state.read(cx).shared_sessions.clone();
        let rows = build_session_rows(self.sessions.clone(), &snapshots, &self.tmux_sessions);
        if rows.len() == self.rows.len() {
            self.rows = Rc::new(rows);
        } else {
            self.set_rows(rows);
        }
        cx.notify();
    }
}

fn build_session_rows(
    sessions: Vec<AgentSessionSummary>,
    snapshots: &[AgentSharedSessions],
    tmux_sessions: &[TmuxSessionSummary],
) -> Vec<AgentSessionRow> {
    let history_rows = flatten_session_sections(group_sessions_by_day(merge_shared_sessions(
        sessions, snapshots,
    )));
    if tmux_sessions.is_empty() {
        return history_rows;
    }

    let mut rows = Vec::with_capacity(1 + tmux_sessions.len() + history_rows.len());
    rows.push(AgentSessionRow::Header("Tmux sessions".into()));
    rows.extend(tmux_sessions.iter().cloned().map(AgentSessionRow::Tmux));
    rows.extend(history_rows);
    rows
}

fn spawn_tmux_session_poll(
    session_handle: SessionHandle,
    cx: &mut Context<AgentSessions>,
) -> (Task<()>, TmuxSessionPollHandle) {
    let (wake, mut wake_rx) = futures::channel::mpsc::channel::<()>(1);
    let wake = Rc::new(RefCell::new(wake));
    let poll_wake = Rc::clone(&wake);
    let task = cx.spawn(async move |this, cx| {
        loop {
            let result = if session_handle.tmux_sessions_supported() {
                session_handle
                    .tmux_session_list()
                    .await
                    .map_err(|err| err.to_string())
            } else {
                Err(String::new())
            };
            let supported = session_handle.tmux_sessions_supported();
            let applied = this.update(cx, |this, cx| {
                let apply = apply_tmux_poll_result(
                    &mut this.tmux_sessions,
                    &mut this.tmux_error_stretch,
                    supported,
                    result,
                );
                if let Some(error) = apply.error_to_log {
                    error!("custom tmux session poll failed: {error}");
                }
                if apply.rows_changed {
                    this.rebuild_rows(cx);
                }
            });
            if applied.is_err() || !supported {
                break;
            }

            let sleep = cx
                .background_executor()
                .timer(TMUX_SESSION_POLL_INTERVAL)
                .fuse();
            let refresh = wake_rx.next().fuse();
            pin_mut!(sleep, refresh);
            match future::select(sleep, refresh).await {
                future::Either::Left(_) => {}
                future::Either::Right((Some(()), _)) => continue,
                future::Either::Right((None, _)) => break,
            }
        }
    });
    (task, TmuxSessionPollHandle { wake: poll_wake })
}

impl Render for AgentSessions {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let body: AnyElement = match &self.load_state {
            LoadState::Loading => {
                subscreen_padded_body(subscreen_empty_text("Loading…", cx)).into_any_element()
            }
            LoadState::Error(message) => {
                subscreen_padded_body(subscreen_empty_text(message.clone(), cx)).into_any_element()
            }
            LoadState::Ready if self.rows.is_empty() => subscreen_padded_body(
                subscreen_empty_text("No sessions found for this workspace.", cx),
            )
            .into_any_element(),
            LoadState::Ready => render_virtualized_agent_session_list(
                Rc::clone(&self.rows),
                self.list_state.clone(),
                true,
            )
            .into_any_element(),
        };
        let header = render_session_header(cx).into_any_element();
        subscreen_page_unscrolled("agent-sessions", rgb(theme::bg_primary(cx)), header, body)
    }
}

fn render_session_header(cx: &mut Context<AgentSessions>) -> impl IntoElement {
    div()
        .id("agent-sessions-header")
        .min_w_0()
        .px(px(theme::SUBSCREEN_PADDING_X))
        .pt(px(theme::SPACING_XS))
        .pb(px(theme::SPACING_SM))
        .child(
            div()
                .id("agent-sessions-header-inner")
                .relative()
                .min_w_0()
                .child(
                    div()
                        .min_w_0()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap(px(theme::SPACING_MD))
                        .child(back_button(cx))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .flex()
                                .flex_col()
                                .gap(px(0.0))
                                .child(
                                    div()
                                        .text_size(px(theme::FONT_HEADING))
                                        .font_family(fonts::HEADING_FONT_FAMILY)
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(theme::text_primary(cx)))
                                        .child("Agent history"),
                                )
                                .child(
                                    div()
                                        .text_size(px(theme::FONT_BODY))
                                        .text_color(rgb(theme::text_muted(cx)))
                                        .child("Sessions across agents. Press to resume"),
                                ),
                        ),
                )
                .child(subscreen_refresh_button(
                    "agent-sessions-refresh-btn",
                    cx,
                    |this, _event, _window, cx| this.refresh(cx),
                )),
        )
}

fn back_button(cx: &mut Context<AgentSessions>) -> Stateful<Div> {
    chevron_back_button(
        "agent-sessions-back-btn",
        cx,
        |_this, _event, window, cx| {
            platform_bridge::trigger_haptic(HapticFeedback::ImpactLight);
            window.dispatch_action(workspace_action::NavigateBack.boxed_clone(), cx);
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AgentSessionRow, AgentSessionSummary, TmuxSessionListResult, TmuxSessionSummary,
        apply_tmux_poll_result, build_session_rows,
    };
    use chrono::Utc;
    use zedra_rpc::proto::{AgentResumeSummary, TmuxClientCounts};

    fn tmux(name: &str, slug: &str) -> TmuxSessionSummary {
        TmuxSessionSummary {
            name: name.into(),
            agent_slug: slug.into(),
            title: format!("{name} title"),
            last_activity_at: Some(Utc::now()),
            git_branch: None,
            transcript_size_bytes: None,
            clients: TmuxClientCounts::default(),
        }
    }

    fn list(available: bool, sessions: Vec<TmuxSessionSummary>) -> TmuxSessionListResult {
        TmuxSessionListResult {
            available,
            version: available.then_some("3.4").unwrap_or_default().into(),
            sessions,
            error: (!available).then(|| "tmux unavailable".into()),
        }
    }

    fn history(slug: &str, id: &str) -> AgentSessionSummary {
        AgentSessionSummary {
            slug: slug.into(),
            session_id: id.into(),
            title: None,
            cwd: None,
            created_at: Some(Utc::now()),
            last_activity_at: Some(Utc::now()),
            resume: AgentResumeSummary {
                available: true,
                unavailable_reason: None,
                action_id: None,
            },
            git: None,
            usage: None,
            transcript_size_bytes: None,
        }
    }

    #[test]
    fn tmux_poll_keeps_last_success_across_unchanged_transport_error_stretch() {
        let cars = tmux("cars_us", "pi");
        let mut sessions = Vec::new();
        let mut error_stretch = None;

        let applied = apply_tmux_poll_result(
            &mut sessions,
            &mut error_stretch,
            true,
            Ok(list(true, vec![cars.clone()])),
        );
        assert!(applied.rows_changed);
        assert!(applied.error_to_log.is_none());
        assert_eq!(sessions, [cars.clone()]);

        let first_error = apply_tmux_poll_result(
            &mut sessions,
            &mut error_stretch,
            true,
            Err("connection reset".into()),
        );
        assert_eq!(
            first_error.error_to_log.as_deref(),
            Some("connection reset")
        );
        assert_eq!(sessions, [cars.clone()]);

        let repeated_error = apply_tmux_poll_result(
            &mut sessions,
            &mut error_stretch,
            true,
            Err("connection reset".into()),
        );
        assert!(repeated_error.error_to_log.is_none());
        assert_eq!(sessions, [cars]);
    }

    #[test]
    fn tmux_poll_success_unavailable_and_downgrade_replace_only_custom_state() {
        let mut sessions = vec![tmux("old", "pi")];
        let mut error_stretch = Some("offline".into());
        let claude = tmux("claude-work", "claude");

        let replacement = apply_tmux_poll_result(
            &mut sessions,
            &mut error_stretch,
            true,
            Ok(list(true, vec![claude.clone()])),
        );
        assert!(replacement.rows_changed);
        assert_eq!(sessions, [claude]);
        assert!(error_stretch.is_none());

        let unavailable = apply_tmux_poll_result(
            &mut sessions,
            &mut error_stretch,
            true,
            Ok(list(false, Vec::new())),
        );
        assert!(unavailable.rows_changed);
        assert!(sessions.is_empty());

        sessions.push(tmux("rediscovered", "omp"));
        error_stretch = Some("stale".into());
        let downgraded = apply_tmux_poll_result(
            &mut sessions,
            &mut error_stretch,
            false,
            Err("custom tmux sessions are unsupported by host".into()),
        );
        assert!(downgraded.rows_changed);
        assert!(downgraded.error_to_log.is_none());
        assert!(sessions.is_empty());
        assert!(error_stretch.is_none());
    }

    #[test]
    fn rebuild_prepends_tmux_section_without_fabricating_history() {
        let persisted = history("pi", "persisted");
        let custom = vec![tmux("cars_us", "pi"), tmux("pair", "omp")];
        let rows = build_session_rows(vec![persisted.clone()], &[], &custom);

        match &rows[..] {
            [
                AgentSessionRow::Header(label),
                AgentSessionRow::Tmux(first),
                AgentSessionRow::Tmux(second),
                AgentSessionRow::Header(_),
                AgentSessionRow::Session(item),
            ] => {
                assert_eq!(label.to_string(), "Tmux sessions");
                assert_eq!(first, &custom[0]);
                assert_eq!(second, &custom[1]);
                assert_eq!(item.session, persisted);
            }
            _ => panic!("unexpected custom/history row structure"),
        }

        let custom_only = build_session_rows(Vec::new(), &[], &custom);
        assert_eq!(custom_only.len(), 3);
        assert!(
            custom_only
                .iter()
                .all(|row| !matches!(row, AgentSessionRow::Session(_)))
        );

        let history_only = build_session_rows(vec![history("omp", "history")], &[], &[]);
        assert!(matches!(&history_only[0], AgentSessionRow::Header(_)));
        assert!(matches!(&history_only[1], AgentSessionRow::Session(_)));
    }
}
