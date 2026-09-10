//! Shared agent cards, session list, and display helpers (not navigation-stack views).
use chrono::{DateTime, Utc};
use futures::{FutureExt, StreamExt, future, pin_mut};
use gpui::prelude::FluentBuilder;
use gpui::*;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;
use zedra_rpc::proto::{
    AgentInfoField, AgentSessionSummary, AgentSetupState, AgentShareSession, AgentSummary,
    AgentUsageSnapshot, TmuxSessionSummary,
};
use zedra_session::SessionHandle;

use crate::fonts;
use crate::platform_bridge::{self, HapticFeedback};
use crate::workspace_state::{AgentSharedSessions, WorkspaceState};
use crate::{theme, workspace_action};

// Enough offscreen rows to keep fast mobile scrolls smooth without measuring
// every session up front.
const SESSION_LIST_OVERDRAW_PX: f32 = 800.0;
const SESSION_LIST_BOTTOM_INSET: f32 = 30.0;

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

pub fn cli_version_display(agent: &AgentSummary) -> String {
    if agent.cli.available {
        agent
            .cli
            .version
            .clone()
            .unwrap_or_else(|| "Checking…".to_string())
    } else {
        agent
            .cli
            .error
            .clone()
            .unwrap_or_else(|| "Not installed".to_string())
    }
}

pub fn setup_label(state: AgentSetupState) -> &'static str {
    match state {
        AgentSetupState::MissingCli => "Missing CLI",
        AgentSetupState::NotConfigured => "Not configured",
        AgentSetupState::SkillsOnly => "Skills only",
        AgentSetupState::HooksReady => "Hooks ready",
        AgentSetupState::Error => "Error",
    }
}

// ---------------------------------------------------------------------------
// Shared tmux sessions
// ---------------------------------------------------------------------------

/// Interval between tmux snapshots while a sessions view is open.
const SHARED_SESSION_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// One persisted session row plus its live tmux share, when listed.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentSessionItem {
    pub session: AgentSessionSummary,
    pub shared: Option<AgentShareSession>,
}

/// Pair persisted history with live tmux snapshots by `(slug, session_id)`.
/// Rows keep their order and timestamps; unmatched shares are never fabricated.
pub fn merge_shared_sessions(
    sessions: Vec<AgentSessionSummary>,
    snapshots: &[AgentSharedSessions],
) -> Vec<AgentSessionItem> {
    sessions
        .into_iter()
        .map(|session| {
            let shared = snapshots
                .iter()
                .filter(|snapshot| snapshot.available && snapshot.slug == session.slug)
                .flat_map(|snapshot| snapshot.sessions.iter())
                .find(|share| share.session_id == session.session_id)
                .cloned();
            AgentSessionItem { session, shared }
        })
        .collect()
}

/// Badge state for one shared tmux session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedSessionStatus {
    Live,
    Ended(Option<u32>),
}

impl SharedSessionStatus {
    pub fn label(&self) -> String {
        match self {
            Self::Live => "Live".to_string(),
            Self::Ended(None) => "Ended".to_string(),
            Self::Ended(Some(code)) => format!("Ended (code {code})"),
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}

/// Pure live/dead → badge mapping for a session card.
pub fn shared_session_status(shared: &AgentShareSession) -> SharedSessionStatus {
    if shared.dead {
        SharedSessionStatus::Ended(shared.exit_code)
    } else {
        SharedSessionStatus::Live
    }
}

#[derive(Debug)]
struct SharedSessionPollControl {
    targets: Vec<String>,
    target_revision: u64,
    refresh_revision: u64,
}

impl SharedSessionPollControl {
    fn new(targets: Vec<String>) -> Self {
        Self {
            targets: distinct_slugs(targets),
            target_revision: 0,
            refresh_revision: 0,
        }
    }

    fn set_targets(&mut self, targets: Vec<String>) -> bool {
        let targets = distinct_slugs(targets);
        if self.targets == targets {
            return false;
        }
        self.targets = targets;
        self.target_revision = self.target_revision.wrapping_add(1);
        true
    }

    fn request_refresh(&mut self) {
        self.refresh_revision = self.refresh_revision.wrapping_add(1);
    }
}

#[derive(Debug)]
struct SharedSessionPollState {
    targets: Vec<String>,
    target_revision: u64,
    refresh_revision: u64,
    parked: HashSet<String>,
}

impl SharedSessionPollState {
    fn new(control: &SharedSessionPollControl) -> Self {
        Self {
            targets: control.targets.clone(),
            target_revision: control.target_revision,
            refresh_revision: control.refresh_revision,
            parked: HashSet::new(),
        }
    }

    fn sync(&mut self, control: &SharedSessionPollControl) {
        if self.target_revision != control.target_revision {
            self.targets.clone_from(&control.targets);
            self.target_revision = control.target_revision;
            self.parked.clear();
        }
        if self.refresh_revision != control.refresh_revision {
            self.refresh_revision = control.refresh_revision;
            self.parked.clear();
        }
    }

    fn pollable_targets(&self) -> Vec<String> {
        self.targets
            .iter()
            .filter(|slug| !self.parked.contains(*slug))
            .cloned()
            .collect()
    }

    fn contains_target(&self, slug: &str) -> bool {
        self.targets.iter().any(|target| target == slug)
    }

    fn park_all(&mut self) {
        self.parked.extend(self.targets.iter().cloned());
    }
}

fn distinct_slugs(slugs: Vec<String>) -> Vec<String> {
    let mut distinct = Vec::with_capacity(slugs.len());
    for slug in slugs {
        if !distinct.iter().any(|existing| existing == &slug) {
            distinct.push(slug);
        }
    }
    distinct
}

/// Handle for changing poll targets or waking parked targets immediately.
#[derive(Clone)]
pub struct SharedSessionPollHandle {
    control: Rc<RefCell<SharedSessionPollControl>>,
    wake: Rc<RefCell<futures::channel::mpsc::Sender<()>>>,
}

impl SharedSessionPollHandle {
    pub fn set_targets(&self, targets: Vec<String>) {
        let changed = self.control.borrow_mut().set_targets(targets);
        if changed {
            self.wake();
        }
    }

    pub fn request_refresh(&self) {
        self.control.borrow_mut().request_refresh();
        self.wake();
    }

    fn wake(&self) {
        let _ = self.wake.borrow_mut().try_send(());
    }
}

/// Poll each target sequentially while the owning view lives. Whole cycles are
/// serialized, and `on_snapshot` runs once after a cycle changes display state.
pub fn spawn_shared_session_poll<T, F>(
    session_handle: SessionHandle,
    workspace_state: Entity<WorkspaceState>,
    initial_targets: Vec<String>,
    on_snapshot: F,
    cx: &mut Context<T>,
) -> (Task<()>, SharedSessionPollHandle)
where
    T: 'static,
    F: Fn(&mut T, &mut Context<T>) + 'static,
{
    let control = Rc::new(RefCell::new(SharedSessionPollControl::new(initial_targets)));
    let task_control = Rc::clone(&control);
    let (wake, mut wake_rx) = futures::channel::mpsc::channel::<()>(1);
    let task = cx.spawn(async move |this, cx| {
        let mut poll_state = SharedSessionPollState::new(&task_control.borrow());
        loop {
            poll_state.sync(&task_control.borrow());
            let targets = poll_state.pollable_targets();
            if targets.is_empty() {
                if wake_rx.next().await.is_none() {
                    break;
                }
                continue;
            }

            let mut downgraded = !session_handle.shared_agent_sessions_supported();
            let mut outcomes = Vec::with_capacity(targets.len());
            if !downgraded {
                for slug in targets {
                    let outcome = session_handle.agent_share_list(slug.clone()).await;
                    if !session_handle.shared_agent_sessions_supported() {
                        downgraded = true;
                        break;
                    }
                    outcomes.push((slug, outcome));
                }
            }

            // A target update may arrive while an RPC is in flight. Apply only
            // outcomes that still belong to this view's latest target set.
            poll_state.sync(&task_control.borrow());
            outcomes.retain(|(slug, _)| poll_state.contains_target(slug));
            if downgraded {
                poll_state.park_all();
            }

            let applied = this.update(cx, |this, cx| {
                let changed = workspace_state.update(cx, |state, cx| {
                    if downgraded {
                        state.clear_shared_session_snapshots(cx)
                    } else {
                        outcomes.iter().fold(false, |changed, (slug, outcome)| {
                            state.apply_shared_sessions(slug, outcome.as_ref(), cx) || changed
                        })
                    }
                });
                if changed {
                    on_snapshot(this, cx);
                }
            });
            if applied.is_err() {
                break;
            }

            if poll_state.pollable_targets().is_empty() {
                if wake_rx.next().await.is_none() {
                    break;
                }
                continue;
            }
            let sleep = cx
                .background_executor()
                .timer(SHARED_SESSION_POLL_INTERVAL)
                .fuse();
            let wake = wake_rx.next().fuse();
            pin_mut!(sleep, wake);
            match future::select(sleep, wake).await {
                future::Either::Left(_) => {}
                future::Either::Right((Some(()), _)) => continue,
                future::Either::Right((None, _)) => break,
            }
        }
    });
    (
        task,
        SharedSessionPollHandle {
            control,
            wake: Rc::new(RefCell::new(wake)),
        },
    )
}

pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

// ---------------------------------------------------------------------------
// Agent card
// ---------------------------------------------------------------------------

pub struct AgentCardProps<'a> {
    pub agent: &'a AgentSummary,
}

pub fn render_agent_card(cx: &App, props: AgentCardProps<'_>) -> Stateful<Div> {
    let agent = props.agent;
    let slug = agent.slug.clone();
    let display_name = agent.display_name.clone();
    let version = cli_version_display(agent);
    let session_count = agent.sessions.resumable.max(agent.sessions.total);
    let sessions_label = format!("{session_count} sessions");
    let field_value = |label: &str| {
        agent
            .account
            .fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.clone())
    };
    let plan = field_value("Plan");
    let model_provider = match (
        field_value("Default model"),
        field_value("Default provider"),
    ) {
        (Some(model), Some(provider)) => Some(format!("{model} · {provider}")),
        (model, provider) => model.or(provider),
    };
    let usage = agent.usage.clone();

    div()
        .id(SharedString::from(format!("agent-card-{}", slug)))
        .w_full()
        .min_w_0()
        .px(px(theme::SPACING_MD))
        .py(px(theme::SPACING_SM))
        .rounded(px(6.0))
        .border_1()
        .border_color(rgb(theme::border_subtle(cx)))
        .bg(rgb(theme::bg_card_dim(cx)))
        .child(
            div()
                .w_full()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap(px(theme::SPACING_SM))
                        .child(
                            svg()
                                .path(crate::agent::icon(&slug))
                                .size(px(theme::ICON_MD))
                                .flex_shrink_0()
                                .text_color(rgb(theme::text_muted(cx))),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .flex()
                                .flex_row()
                                .items_center()
                                .gap(px(theme::SPACING_SM))
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .overflow_hidden()
                                        .whitespace_nowrap()
                                        .text_size(px(theme::FONT_AGENT_CARD_TITLE))
                                        .font_family(fonts::HEADING_FONT_FAMILY)
                                        .text_color(rgb(theme::text_primary(cx)))
                                        .child(display_name),
                                )
                                .when_some(plan, |row, plan_label| {
                                    row.child(
                                        div()
                                            .flex_shrink_0()
                                            .px(px(theme::BADGE_PX))
                                            .py(px(theme::BADGE_PY))
                                            .rounded(px(theme::BADGE_RADIUS))
                                            .bg(rgb(theme::bg_card(cx)))
                                            .border_1()
                                            .border_color(rgb(theme::border_subtle(cx)))
                                            .text_size(px(theme::FONT_DETAIL))
                                            .text_color(rgb(theme::text_muted(cx)))
                                            .whitespace_nowrap()
                                            .child(plan_label.to_ascii_lowercase()),
                                    )
                                }),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap(px(theme::SPACING_SM))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_size(px(theme::FONT_DETAIL))
                                .text_color(rgb(theme::text_muted(cx)))
                                .child(version),
                        )
                        .child(
                            div()
                                .flex_shrink_0()
                                .whitespace_nowrap()
                                .text_size(px(theme::FONT_DETAIL))
                                .text_color(rgb(theme::text_muted(cx)))
                                .child(sessions_label),
                        ),
                )
                .when_some(model_provider, |el, text| {
                    el.child(
                        div()
                            .w_full()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_size(px(theme::FONT_DETAIL))
                            .text_color(rgb(theme::text_muted(cx)))
                            .child(text),
                    )
                })
                .when_some(usage, |el, snap| el.children(render_usage_row(&snap, cx)))
                .when(!agent.highlight.is_empty(), |el| {
                    el.child(
                        div()
                            .w_full()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_size(px(theme::FONT_DETAIL))
                            .text_color(rgb(theme::text_muted(cx)))
                            .child(agent.highlight.clone()),
                    )
                }),
        )
}

/// Rate-limit gauges (5h / 7d) with reset times; `None` when no live limits.
pub fn render_usage_row(snap: &AgentUsageSnapshot, cx: &App) -> Option<Div> {
    let five_reset = snap
        .rate_limit_five_hour_resets_at
        .and_then(format_reset_duration_hm);
    let seven_reset = snap
        .rate_limit_seven_day_resets_at
        .and_then(format_reset_duration_dh);
    render_usage_gauges(snap, five_reset.as_deref(), seven_reset.as_deref(), cx)
}

/// Render `label: value` fields (detail screen, e.g. `usage.extra`). The card
/// uses `AgentSummary.highlight` instead. `None` when empty.
pub fn render_extra_row(fields: &[AgentInfoField], cx: &App) -> Option<Div> {
    if fields.is_empty() {
        return None;
    }
    Some(
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .children(fields.iter().map(|field| {
                div()
                    .text_size(px(theme::FONT_DETAIL))
                    .text_color(rgb(theme::text_muted(cx)))
                    .child(format!("{}: {}", field.label, field.value))
            })),
    )
}

// Fixed column widths so 5h / 7d value columns align within each gauge.
const GAUGE_LABEL_W: f32 = 18.0;
const GAUGE_LABEL_BAR_GAP: f32 = 2.0;
const GAUGE_BAR_W: f32 = 40.0;
const GAUGE_BAR_VALUES_GAP: f32 = 6.0;
const GAUGE_PCT_W: f32 = 30.0;
const GAUGE_RESET_W: f32 = 40.0;

fn render_usage_gauges(
    snap: &AgentUsageSnapshot,
    five_reset: Option<&str>,
    seven_reset: Option<&str>,
    cx: &App,
) -> Option<Div> {
    let has_five = snap.rate_limit_five_hour_used_percent.is_some();
    let has_seven = snap.rate_limit_seven_day_used_percent.is_some();
    if !has_five && !has_seven {
        return None;
    }

    let mut gauges: Vec<AnyElement> = Vec::new();
    if let Some(pct) = snap.rate_limit_five_hour_used_percent {
        gauges.push(usage_gauge("5h", pct, five_reset, cx).into_any_element());
    }
    if let Some(pct) = snap.rate_limit_seven_day_used_percent {
        gauges.push(usage_gauge("7d", pct, seven_reset, cx).into_any_element());
    }

    Some(
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_row()
            .items_center()
            .justify_between()
            .children(gauges),
    )
}

/// Label + bar + fixed `%` and reset columns: `5h [████] 45%  2h30m`
fn usage_gauge(
    label: &'static str,
    pct: f32,
    resets_in: Option<&str>,
    cx: &App,
) -> impl IntoElement {
    let pct_clamped = pct.clamp(0.0, 100.0);
    let bar_color = usage_bar_color(pct_clamped, cx);
    let pct_text = format!("{pct:.0}%");

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(GAUGE_BAR_VALUES_GAP))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(GAUGE_LABEL_BAR_GAP))
                .child(
                    div()
                        .w(px(GAUGE_LABEL_W))
                        .flex_shrink_0()
                        .whitespace_nowrap()
                        .text_size(px(theme::FONT_DETAIL))
                        .text_color(rgb(theme::text_muted(cx)))
                        .child(label),
                )
                .child(
                    div()
                        .w(px(GAUGE_BAR_W))
                        .h(px(3.0))
                        .flex_shrink_0()
                        .rounded_full()
                        .bg(rgb(theme::border_subtle(cx)))
                        .child(
                            div()
                                .h_full()
                                .rounded_full()
                                .w(px(GAUGE_BAR_W * pct_clamped / 100.0))
                                .bg(rgb(bar_color)),
                        ),
                ),
        )
        .child(
            div()
                .w(px(GAUGE_PCT_W))
                .flex_shrink_0()
                .flex()
                .justify_end()
                .child(
                    div()
                        .whitespace_nowrap()
                        .text_size(px(theme::FONT_DETAIL))
                        .text_color(rgb(bar_color))
                        .child(pct_text),
                ),
        )
        .child(
            div()
                .w(px(GAUGE_RESET_W))
                .flex_shrink_0()
                .flex()
                .justify_end()
                .child(
                    div()
                        .whitespace_nowrap()
                        .text_size(px(theme::FONT_DETAIL))
                        .text_color(rgb(theme::text_muted(cx)))
                        .child(SharedString::from(resets_in.unwrap_or("").to_string())),
                ),
        )
}

fn usage_bar_color(pct: f32, cx: &App) -> u32 {
    if pct >= 80.0 {
        theme::accent_red(cx)
    } else if pct >= 50.0 {
        theme::accent_yellow(cx)
    } else {
        theme::accent_green(cx)
    }
}

fn seconds_until_reset(resets_at: i64) -> Option<i64> {
    let secs = resets_at - chrono::Utc::now().timestamp();
    (secs > 0).then_some(secs)
}

/// 5h window reset: `2h30m`, `45m`.
fn format_reset_duration_hm(resets_at: i64) -> Option<String> {
    let secs = seconds_until_reset(resets_at)?;
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    if hours > 0 {
        Some(format!("{hours}h{mins}m"))
    } else {
        Some(format!("{}m", mins.max(1)))
    }
}

/// 7d window reset: `3d5h`, `12h`.
fn format_reset_duration_dh(resets_at: i64) -> Option<String> {
    let secs = seconds_until_reset(resets_at)?;
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    if hours >= 24 {
        let days = hours / 24;
        let rem = hours % 24;
        if rem > 0 {
            Some(format!("{days}d{rem}h"))
        } else {
            Some(format!("{days}d"))
        }
    } else if hours > 0 {
        Some(format!("{hours}h"))
    } else {
        Some(format!("{}m", mins.max(1)))
    }
}

// ---------------------------------------------------------------------------
// Session card
// ---------------------------------------------------------------------------

/// Terminate is offered via long-press only for rows carrying a shared tmux
/// snapshot — never for plain past rows or foreign tmux sessions.
pub fn offers_terminate(shared: Option<&AgentShareSession>) -> bool {
    shared.is_some()
}

pub struct SessionCardProps<'a> {
    pub session: &'a AgentSessionSummary,
    pub shared: Option<&'a AgentShareSession>,
    pub resume_on_tap: bool,
}

pub fn render_session_card(props: SessionCardProps<'_>, cx: &App) -> Stateful<Div> {
    let session = props.session;
    let can_resume = session.resume.available;
    let slug = session.slug.clone();
    let session_id = session.session_id.clone();
    let item_id = SharedString::from(format!(
        "session-card-{}-{}",
        slug,
        short_id(&session.session_id)
    ));

    div()
        .w_full()
        .min_w_0()
        .px(px(theme::SPACING_MD))
        .py(px(theme::SPACING_SM))
        .rounded(px(6.0))
        .border_1()
        .border_color(rgb(theme::border_subtle(cx)))
        .bg(rgb(theme::bg_card_dim(cx)))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .when(props.resume_on_tap && can_resume, |el| {
            el.cursor_pointer().on_press({
                let session_id = session_id.clone();
                let slug = slug.clone();
                move |_event, window, cx| {
                    platform_bridge::trigger_haptic(HapticFeedback::ImpactLight);
                    window.dispatch_action(
                        workspace_action::ResumeAgentSession {
                            slug: slug.clone(),
                            session_id: session_id.clone(),
                        }
                        .boxed_clone(),
                        cx,
                    );
                }
            })
        })
        .when(offers_terminate(props.shared), |el| {
            el.on_long_press({
                let session_id = session_id.clone();
                let slug = slug.clone();
                move |_event, window, cx| {
                    platform_bridge::trigger_haptic(HapticFeedback::ImpactMedium);
                    window.dispatch_action(
                        workspace_action::TerminateSharedAgentSession {
                            slug: slug.clone(),
                            session_id: session_id.clone(),
                        }
                        .boxed_clone(),
                        cx,
                    );
                }
            })
        })
        .id(item_id)
        .child(
            svg()
                .path(crate::agent::icon(&slug))
                .size(px(theme::ICON_MD))
                .flex_shrink_0()
                .text_color(rgb(theme::text_muted(cx))),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .child(session_title_row(session, props.shared, cx))
                .child(session_meta_row(session, cx)),
        )
}
pub fn session_title(session: &AgentSessionSummary) -> String {
    session
        .title
        .clone()
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn session_title_row(
    session: &AgentSessionSummary,
    shared: Option<&AgentShareSession>,
    cx: &App,
) -> Div {
    let mut row = div()
        .w_full()
        .min_w_0()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .child(
            div()
                .flex_1()
                .min_w_0()
                // Trim long titles to the row width at render time (host only
                // applies a generous anti-abuse cap).
                .truncate()
                .text_size(px(theme::FONT_BODY))
                .text_color(rgb(theme::text_primary(cx)))
                .child(session_title(session)),
        )
        .when_some(shared, |row, shared| {
            row.child(shared_status_badge(shared, cx))
        });

    if let Some(at) = session.last_activity_at.or(session.created_at) {
        row = row.child(
            div()
                .flex_shrink_0()
                .text_size(px(theme::FONT_DETAIL))
                .text_color(rgb(theme::text_muted(cx)))
                .child(format_session_time(at)),
        );
    }

    row
}

/// Small semantic status chip: green while the shared pane runs, muted once
/// it has ended.
fn shared_status_badge(shared: &AgentShareSession, cx: &App) -> Div {
    let status = shared_session_status(shared);
    let text_color = if status.is_live() {
        theme::accent_green(cx)
    } else {
        theme::text_muted(cx)
    };
    div()
        .flex_shrink_0()
        .px(px(theme::BADGE_PX))
        .py(px(theme::BADGE_PY))
        .rounded(px(theme::BADGE_RADIUS))
        .bg(rgb(theme::bg_card(cx)))
        .border_1()
        .border_color(rgb(theme::border_subtle(cx)))
        .text_size(px(theme::FONT_DETAIL))
        .text_color(rgb(text_color))
        .whitespace_nowrap()
        .child(status.label())
}

fn session_meta_row(session: &AgentSessionSummary, cx: &App) -> impl IntoElement {
    let branch = session
        .git
        .as_ref()
        .and_then(|git| git.branch.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let right = session_meta_tail(session);

    div()
        .id(SharedString::from(format!(
            "session-card-meta-{}",
            short_id(&session.session_id)
        )))
        .w_full()
        .min_w_0()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .text_size(px(theme::FONT_DETAIL))
        .text_color(rgb(theme::text_muted(cx)))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(4.0))
                .overflow_hidden()
                .child(
                    svg()
                        .path("icons/git-branch.svg")
                        .size(px(theme::ICON_XS))
                        .flex_shrink_0()
                        .text_color(rgb(theme::text_muted(cx))),
                )
                .child(
                    div()
                        .min_w_0()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .child(branch),
                ),
        )
        .when(!right.is_empty(), |el| {
            el.child(
                div()
                    .flex_shrink_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .child(right),
            )
        })
}

fn session_meta_tail(session: &AgentSessionSummary) -> String {
    session
        .transcript_size_bytes
        .map(format_size)
        .unwrap_or_default()
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_session_time(at: DateTime<Utc>) -> String {
    at.format("%H:%M").to_string()
}

// ---------------------------------------------------------------------------
// Session list
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct AgentSessionSection {
    pub label: String,
    pub sessions: Vec<AgentSessionItem>,
}

pub fn group_sessions_by_day(sessions: Vec<AgentSessionItem>) -> Vec<AgentSessionSection> {
    let mut sorted = sessions;
    sorted.sort_by(|left, right| {
        right
            .session
            .last_activity_at
            .cmp(&left.session.last_activity_at)
            .then_with(|| right.session.created_at.cmp(&left.session.created_at))
    });

    let mut sections = Vec::new();
    for item in sorted {
        let label = day_label(item.session.last_activity_at.or(item.session.created_at));
        if sections
            .last()
            .is_some_and(|section: &AgentSessionSection| section.label == label)
        {
            sections
                .last_mut()
                .expect("section exists")
                .sessions
                .push(item);
        } else {
            sections.push(AgentSessionSection {
                label,
                sessions: vec![item],
            });
        }
    }
    sections
}

pub struct AgentSessionListProps<'a> {
    pub sections: &'a [AgentSessionSection],
    pub loading: bool,
    pub error: Option<String>,
    pub empty_message: &'static str,
    pub resume_on_tap: bool,
}

/// Eager list for short, embedded session lists (one agent, host-capped).
/// Long, standalone lists use [`render_virtualized_agent_session_list`].
pub fn render_agent_session_list(props: AgentSessionListProps<'_>, cx: &App) -> impl IntoElement {
    let mut list = div()
        .id("agent-session-list")
        .w_full()
        .min_w_0()
        .pb(px(theme::SPACING_MD))
        .flex()
        .flex_col()
        .gap(px(theme::SPACING_SM));

    if props.loading {
        return list.child(list_empty_text("Loading…", cx));
    }
    if let Some(error) = props.error {
        return list.child(list_empty_text(error, cx));
    }
    if props.sections.is_empty() {
        return list.child(list_empty_text(props.empty_message, cx));
    }

    for section in props.sections {
        list = list.child(section_header(&section.label, cx));
        for item in &section.sessions {
            list = list.child(render_session_card(
                SessionCardProps {
                    session: &item.session,
                    shared: item.shared.as_ref(),
                    resume_on_tap: props.resume_on_tap,
                },
                cx,
            ));
        }
    }
    list
}

/// One virtualized row: a section header, custom tmux session, or history card.
pub enum AgentSessionRow {
    Header(SharedString),
    Tmux(TmuxSessionSummary),
    Session(AgentSessionItem),
}

pub fn flatten_session_sections(sections: Vec<AgentSessionSection>) -> Vec<AgentSessionRow> {
    let mut rows = Vec::new();
    for section in sections {
        rows.push(AgentSessionRow::Header(SharedString::from(section.label)));
        rows.extend(section.sessions.into_iter().map(AgentSessionRow::Session));
    }
    rows
}

#[derive(Debug, PartialEq, Eq)]
struct TmuxSessionRowModel {
    secondary_label: String,
    icon_path: String,
    attach_agent_slug: Option<String>,
}

fn tmux_session_row_model(session: &TmuxSessionSummary) -> TmuxSessionRowModel {
    let mut seen = HashSet::new();
    let agent_slugs: Vec<&str> = session
        .agent_slugs
        .iter()
        .map(String::as_str)
        .filter(|slug| seen.insert(*slug))
        .collect();
    let secondary_label = agent_slugs
        .iter()
        .map(|slug| crate::agent::name(slug))
        .collect::<Vec<_>>()
        .join(" · ");
    let (icon_path, attach_agent_slug) = match agent_slugs.as_slice() {
        [slug] => (crate::agent::icon(slug), Some((*slug).to_string())),
        _ => ("icons/terminal.svg".to_string(), None),
    };
    TmuxSessionRowModel {
        secondary_label,
        icon_path,
        attach_agent_slug,
    }
}

fn tmux_session_actions(
    session: &TmuxSessionSummary,
    model: &TmuxSessionRowModel,
) -> (
    workspace_action::AttachTmuxSession,
    workspace_action::ManageTmuxSession,
) {
    (
        workspace_action::AttachTmuxSession {
            name: session.name.clone(),
            agent_slug: model.attach_agent_slug.clone(),
        },
        workspace_action::ManageTmuxSession {
            name: session.name.clone(),
        },
    )
}

fn render_tmux_session_card(session: &TmuxSessionSummary, cx: &App) -> Stateful<Div> {
    let model = tmux_session_row_model(session);
    let (attach_action, manage_action) = tmux_session_actions(session, &model);

    div()
        .id(SharedString::from(format!(
            "tmux-session-card-{}",
            session.name
        )))
        .w_full()
        .min_w_0()
        .px(px(theme::SPACING_MD))
        .py(px(theme::SPACING_SM))
        .rounded(px(6.0))
        .border_1()
        .border_color(rgb(theme::border_subtle(cx)))
        .bg(rgb(theme::bg_card_dim(cx)))
        .active(|style| style.bg(theme::row_pressed_bg(cx)))
        .cursor_pointer()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .on_press(move |_event, window, cx| {
            platform_bridge::trigger_haptic(HapticFeedback::ImpactLight);
            window.dispatch_action(attach_action.boxed_clone(), cx);
        })
        .on_long_press(move |_event, window, cx| {
            platform_bridge::trigger_haptic(HapticFeedback::ImpactMedium);
            window.dispatch_action(manage_action.boxed_clone(), cx);
        })
        .child(
            svg()
                .path(model.icon_path)
                .size(px(theme::ICON_MD))
                .flex_shrink_0()
                .text_color(rgb(theme::text_muted(cx))),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .child(
                    div()
                        .w_full()
                        .min_w_0()
                        .truncate()
                        .text_size(px(theme::FONT_BODY))
                        .text_color(rgb(theme::text_primary(cx)))
                        .child(session.name.clone()),
                )
                .child(
                    div()
                        .w_full()
                        .min_w_0()
                        .truncate()
                        .text_size(px(theme::FONT_DETAIL))
                        .text_color(rgb(theme::text_muted(cx)))
                        .child(model.secondary_label),
                ),
        )
}

pub fn new_session_list_state(row_count: usize) -> ListState {
    ListState::new(
        session_list_item_count(row_count),
        ListAlignment::Top,
        px(SESSION_LIST_OVERDRAW_PX),
    )
}

pub fn reset_session_list_state(state: &ListState, row_count: usize) {
    state.reset(session_list_item_count(row_count));
}

fn session_list_item_count(row_count: usize) -> usize {
    row_count + 1
}

/// Virtualized session list: only visible rows are built per frame. Fills its
/// parent, which must give it a definite height and own no scroll of its own.
pub fn render_virtualized_agent_session_list(
    rows: Rc<Vec<AgentSessionRow>>,
    state: ListState,
    resume_on_tap: bool,
) -> impl IntoElement {
    let row_count = rows.len();
    list(state, move |ix, _window, cx| {
        let Some(row) = rows.get(ix) else {
            return if ix == row_count {
                div().h(px(SESSION_LIST_BOTTOM_INSET)).into_any_element()
            } else {
                Empty.into_any_element()
            };
        };
        let content = match row {
            AgentSessionRow::Header(label) => section_header(label, cx).into_any_element(),
            AgentSessionRow::Tmux(session) => {
                render_tmux_session_card(session, cx).into_any_element()
            }
            AgentSessionRow::Session(item) => render_session_card(
                SessionCardProps {
                    session: &item.session,
                    shared: item.shared.as_ref(),
                    resume_on_tap,
                },
                cx,
            )
            .into_any_element(),
        };
        div()
            .w_full()
            .min_w_0()
            .px(px(theme::SUBSCREEN_PADDING_X))
            .pb(px(theme::SPACING_SM))
            .child(content)
            .into_any_element()
    })
    .with_sizing_behavior(ListSizingBehavior::Auto)
    .size_full()
}

fn section_header(label: &str, cx: &App) -> Div {
    div()
        .w_full()
        .min_w_0()
        .pt(px(theme::SPACING_SM))
        .pb(px(4.0))
        .text_size(px(theme::FONT_DETAIL))
        .text_color(rgb(theme::text_muted(cx)))
        .child(label.to_string())
}

fn list_empty_text(text: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .w_full()
        .min_w_0()
        .py(px(theme::SPACING_LG))
        .text_size(px(theme::FONT_BODY))
        .text_color(rgb(theme::text_muted(cx)))
        .whitespace_normal()
        .child(text.into())
}

fn day_label(at: Option<DateTime<Utc>>) -> String {
    let Some(at) = at else {
        return "Unknown date".to_string();
    };
    let today = Utc::now().date_naive();
    let date = at.date_naive();
    if date == today {
        "Today".to_string()
    } else if date == today.pred_opt().unwrap_or(today) {
        "Yesterday".to_string()
    } else {
        at.format("%A, %b %d").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentSessionItem, AgentSessionSummary, AgentShareSession, SharedSessionPollControl,
        SharedSessionPollState, SharedSessionStatus, TmuxSessionSummary, group_sessions_by_day,
        merge_shared_sessions, offers_terminate, shared_session_status, tmux_session_actions,
        tmux_session_row_model,
    };
    use crate::workspace_state::AgentSharedSessions;
    use chrono::Utc;
    use zedra_rpc::proto::AgentResumeSummary;

    fn summary(slug: &str, id: &str, hours_ago: i64) -> AgentSessionSummary {
        let at = Utc::now() - chrono::Duration::hours(hours_ago);
        AgentSessionSummary {
            slug: slug.into(),
            session_id: id.into(),
            title: None,
            cwd: None,
            created_at: Some(at),
            last_activity_at: Some(at),
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

    fn share(id: &str, dead: bool) -> AgentShareSession {
        AgentShareSession {
            session_id: id.into(),
            title: Some("live".into()),
            cwd: None,
            current_command: None,
            dead,
            exit_code: dead.then_some(7),
        }
    }

    fn snapshot(
        slug: &str,
        available: bool,
        sessions: Vec<AgentShareSession>,
    ) -> AgentSharedSessions {
        let mut snapshot = AgentSharedSessions::default();
        snapshot.slug = slug.into();
        snapshot.available = available;
        snapshot.sessions = sessions;
        snapshot
    }

    #[test]
    fn merge_groups_by_persisted_times_and_matches_full_agent_identity() {
        let older = summary("pi", "old", 48);
        let newer = summary("pi", "new", 1);
        let omp_same_id = summary("omp", "old", 2);
        let foreign = summary("hermes", "old", 3);
        let snapshots = vec![
            snapshot("pi", true, vec![share("old", false)]),
            snapshot("omp", true, vec![share("old", true)]),
        ];

        let sections = group_sessions_by_day(merge_shared_sessions(
            vec![older, newer, omp_same_id, foreign],
            &snapshots,
        ));
        let items: Vec<&AgentSessionItem> = sections
            .iter()
            .flat_map(|section| section.sessions.iter())
            .collect();

        // Persisted times control ordering; same session ids in different
        // agent namespaces receive only their own live snapshot.
        let identities: Vec<(&str, &str)> = items
            .iter()
            .map(|item| (item.session.slug.as_str(), item.session.session_id.as_str()))
            .collect();
        assert_eq!(
            identities,
            [
                ("pi", "new"),
                ("omp", "old"),
                ("hermes", "old"),
                ("pi", "old")
            ]
        );
        assert!(items[0].shared.is_none());
        assert!(items[1].shared.as_ref().unwrap().dead);
        assert!(items[2].shared.is_none());
        assert!(!items[3].shared.as_ref().unwrap().dead);
    }

    #[test]
    fn merge_keeps_dead_panes_attached_with_exit_code() {
        let snapshots = vec![snapshot("pi", true, vec![share("dead", true)])];
        let items = merge_shared_sessions(vec![summary("pi", "dead", 3)], &snapshots);
        let shared = items[0].shared.as_ref().expect("dead pane still shared");
        assert!(shared.dead);
        assert_eq!(shared.exit_code, Some(7));
    }

    #[test]
    fn merge_never_fabricates_history_for_unlisted_shares() {
        let row = summary("pi", "known", 3);
        let snapshots = vec![snapshot(
            "pi",
            true,
            vec![share("known", false), share("ghost", false)],
        )];
        let items = merge_shared_sessions(vec![row.clone()], &snapshots);

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].session, row);
    }

    #[test]
    fn merge_uses_first_duplicate_and_ignores_unavailable_snapshots() {
        let mut duplicate = share("dup", false);
        duplicate.title = Some("second".into());
        let snapshots = vec![
            snapshot(
                "pi",
                true,
                vec![share("dup", false), duplicate, share("other", false)],
            ),
            snapshot("omp", false, vec![share("dup", false)]),
        ];

        let items = merge_shared_sessions(
            vec![summary("pi", "dup", 3), summary("omp", "dup", 2)],
            &snapshots,
        );

        assert_eq!(
            items[0].shared.as_ref().unwrap().title.as_deref(),
            Some("live")
        );
        assert!(items[1].shared.is_none());
    }

    #[test]
    fn downgraded_poll_targets_resume_on_refresh_or_target_change() {
        let mut control =
            SharedSessionPollControl::new(vec!["pi".into(), "omp".into(), "pi".into()]);
        let mut state = SharedSessionPollState::new(&control);
        assert_eq!(state.pollable_targets(), ["pi", "omp"]);

        state.park_all();
        assert!(state.pollable_targets().is_empty());
        assert!(!control.set_targets(vec!["pi".into(), "omp".into()]));
        state.sync(&control);
        assert!(state.pollable_targets().is_empty());

        control.request_refresh();
        state.sync(&control);
        assert_eq!(state.pollable_targets(), ["pi", "omp"]);

        state.park_all();
        assert!(state.pollable_targets().is_empty());
        assert!(control.set_targets(vec!["omp".into(), "claude".into()]));
        state.sync(&control);
        assert_eq!(state.pollable_targets(), ["omp", "claude"]);
    }

    #[test]
    fn tmux_row_uses_single_agent_label_icon_and_attach_identity() {
        let session = TmuxSessionSummary {
            name: "cars_us".into(),
            agent_slugs: vec!["pi".into()],
        };
        let model = tmux_session_row_model(&session);
        let (attach, manage) = tmux_session_actions(&session, &model);

        assert_eq!(model.secondary_label, "Pi");
        assert_eq!(model.icon_path, "icons/pi.svg");
        assert_eq!(model.attach_agent_slug.as_deref(), Some("pi"));
        assert_eq!(attach.name, "cars_us");
        assert_eq!(attach.agent_slug.as_deref(), Some("pi"));
        assert_eq!(manage.name, "cars_us");
    }

    #[test]
    fn tmux_row_uses_terminal_icon_and_all_distinct_agent_names_for_multiple_agents() {
        let session = TmuxSessionSummary {
            name: "review swarm".into(),
            agent_slugs: vec!["pi".into(), "claude".into(), "pi".into()],
        };
        let model = tmux_session_row_model(&session);
        let (attach, manage) = tmux_session_actions(&session, &model);

        assert_eq!(model.secondary_label, "Pi · Claude Code");
        assert_eq!(model.icon_path, "icons/terminal.svg");
        assert_eq!(model.attach_agent_slug, None);
        assert_eq!(attach.name, "review swarm");
        assert_eq!(attach.agent_slug, None);
        assert_eq!(manage.name, "review swarm");
    }

    #[test]
    fn terminate_is_offered_only_for_rows_with_a_shared_snapshot() {
        assert!(offers_terminate(Some(&share("s", false))));
        // Dead panes keep their snapshot, so the long-press still offers
        // explicit cleanup.
        assert!(offers_terminate(Some(&share("s", true))));
        // Plain past rows and foreign tmux sessions never offer it.
        assert!(!offers_terminate(None));
    }

    #[test]
    fn shared_status_is_live_for_running_panes() {
        let status = shared_session_status(&share("s", false));
        assert_eq!(status, SharedSessionStatus::Live);
        assert!(status.is_live());
        assert_eq!(status.label(), "Live");
    }

    #[test]
    fn shared_status_reports_known_exit_codes_for_dead_panes() {
        let status = shared_session_status(&share("s", true));
        assert_eq!(status, SharedSessionStatus::Ended(Some(7)));
        assert!(!status.is_live());
        assert_eq!(status.label(), "Ended (code 7)");
    }

    #[test]
    fn shared_status_stays_muted_when_exit_code_is_unknown() {
        let mut dead = share("s", true);
        dead.exit_code = None;

        let status = shared_session_status(&dead);
        assert_eq!(status, SharedSessionStatus::Ended(None));
        assert_eq!(status.label(), "Ended");
    }
}
