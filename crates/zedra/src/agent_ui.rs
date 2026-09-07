//! Shared agent cards, session list, and display helpers (not navigation-stack views).
use chrono::{DateTime, Utc};
use futures::{FutureExt, StreamExt, future, pin_mut};
use gpui::prelude::FluentBuilder;
use gpui::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use zedra_rpc::proto::{
    AgentInfoField, AgentSessionSummary, AgentSetupState, AgentShareSession, AgentSummary,
    AgentUsageSnapshot,
};
use zedra_session::SessionHandle;

use crate::fonts;
use crate::platform_bridge::{self, HapticFeedback};
use crate::workspace_state::WorkspaceState;
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
// Shared tmux sessions (Pi)
// ---------------------------------------------------------------------------

/// Only agents with the host-side shared-session capability are polled; Pi
/// is the only one today.
pub const SHARED_SESSION_AGENT_SLUG: &str = "pi";

/// Interval between tmux snapshots while a sessions view is open.
const SHARED_SESSION_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// One persisted session row plus its live tmux share, when listed.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentSessionItem {
    pub session: AgentSessionSummary,
    pub shared: Option<AgentShareSession>,
}

/// Pair persisted history with the live tmux snapshot by `(slug, session_id)`.
/// Pure: rows keep their order and timestamps; shares without a persisted row
/// are dropped (never fabricated), and duplicate entries collapse to the first.
pub fn merge_shared_sessions(
    sessions: Vec<AgentSessionSummary>,
    slug: &str,
    shares: &[AgentShareSession],
) -> Vec<AgentSessionItem> {
    sessions
        .into_iter()
        .map(|session| {
            let shared = if session.slug == slug {
                shares
                    .iter()
                    .find(|share| share.session_id == session.session_id)
                    .cloned()
            } else {
                None
            };
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

/// Wake handle nudging the poll to refresh right away; full/closed channels
/// are no-ops.
#[derive(Clone)]
pub struct SharedSessionPollHandle {
    wake: Rc<RefCell<futures::channel::mpsc::Sender<()>>>,
}

impl SharedSessionPollHandle {
    pub fn request_refresh(&self) {
        let _ = self.wake.borrow_mut().try_send(());
    }
}

/// Poll `AgentShareList` for [`SHARED_SESSION_AGENT_SLUG`] while the owning
/// view lives. Requests never overlap: the next fires only after the previous
/// response is applied and the interval elapses — or a wake arrives early.
/// Cancels when the view drops the `Task`; `on_snapshot` re-derives display
/// rows after a changed snapshot.
pub fn spawn_shared_session_poll<T, F>(
    session_handle: SessionHandle,
    workspace_state: Entity<WorkspaceState>,
    on_snapshot: F,
    cx: &mut Context<T>,
) -> (Task<()>, SharedSessionPollHandle)
where
    T: 'static,
    F: Fn(&mut T, &mut Context<T>) + 'static,
{
    let (wake, mut wake_rx) = futures::channel::mpsc::channel::<()>(1);
    let task = cx.spawn(async move |this, cx| {
        loop {
            let listing = session_handle
                .agent_share_list(SHARED_SESSION_AGENT_SLUG.to_string())
                .await;
            let applied = this.update(cx, |this, cx| {
                let changed = workspace_state.update(cx, |state, cx| {
                    state.apply_shared_sessions(SHARED_SESSION_AGENT_SLUG, listing.as_ref(), cx)
                });
                if changed {
                    on_snapshot(this, cx);
                }
            });
            if applied.is_err() {
                break;
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

/// One virtualized row: either a day header or a session card.
pub enum AgentSessionRow {
    Header(SharedString),
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
        AgentSessionItem, AgentSessionSummary, AgentShareSession, SharedSessionStatus,
        group_sessions_by_day, merge_shared_sessions, shared_session_status,
    };
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

    #[test]
    fn merge_groups_by_persisted_times_and_attaches_only_own_live_shares() {
        let older = summary("pi", "old", 48);
        let newer = summary("pi", "new", 1);
        let foreign = summary("hermes", "other", 2);
        let shares = vec![share("old", false), share("other", false)];

        let sections = group_sessions_by_day(merge_shared_sessions(
            vec![older, newer, foreign],
            "pi",
            &shares,
        ));
        let items: Vec<&AgentSessionItem> = sections
            .iter()
            .flat_map(|section| section.sessions.iter())
            .collect();

        // Newest first by persisted times; the live "old" row stays last, and
        // the foreign-slug row never picks up a share from the Pi snapshot.
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item.session.session_id.as_str())
            .collect();
        assert_eq!(ids, ["new", "other", "old"]);
        assert_eq!(
            items[2].shared.as_ref().map(|s| s.session_id.as_str()),
            Some("old")
        );
        assert!(items[0].shared.is_none() && items[1].shared.is_none());
    }

    #[test]
    fn merge_keeps_dead_panes_attached_with_exit_code() {
        let items =
            merge_shared_sessions(vec![summary("pi", "dead", 3)], "pi", &[share("dead", true)]);
        let shared = items[0].shared.as_ref().expect("dead pane still shared");
        assert!(shared.dead);
        assert_eq!(shared.exit_code, Some(7));
    }

    #[test]
    fn merge_never_fabricates_history_for_unlisted_shares() {
        let row = summary("pi", "known", 3);
        let items = merge_shared_sessions(
            vec![row.clone()],
            "pi",
            &[share("known", false), share("ghost", false)],
        );

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].session, row);
    }

    #[test]
    fn merge_collapses_duplicate_snapshot_entries_to_first() {
        let mut duplicate = share("dup", false);
        duplicate.title = Some("second".into());

        let items = merge_shared_sessions(
            vec![summary("pi", "dup", 3)],
            "pi",
            &[share("dup", false), duplicate],
        );

        assert_eq!(
            items[0].shared.as_ref().unwrap().title.as_deref(),
            Some("live")
        );
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
