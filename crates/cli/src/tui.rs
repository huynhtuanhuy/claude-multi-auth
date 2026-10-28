//! `cma list --live`: a live table that redraws every 250 ms and refreshes
//! usage in the background every `live_interval_secs` after the previous
//! refresh finished. ↑↓ select, Enter switch (default target), `d` Desktop,
//! `b` both, `r` refresh now, `q` / Esc / Ctrl-C quit.
//!
//! Sessions and the cma lock are `!Send`, so every background job (usage
//! refresh, switch) builds its own [`Deps`] and runs its whole session on
//! its own thread; the UI thread never blocks on a lock or the network.
//! Each result carries the generation it started in; results older than
//! the latest switch are dropped (credential safety itself comes from the
//! core's per-account locks). Quitting waits for a running job to finish,
//! so a token refresh is never cut off halfway.

use std::io::IsTerminal;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cma_core::registry::{Registry, Target};
use cma_core::switch::{Confirm, SwitchOpts, switch_cli};
use cma_core::usage::{AccountUsage, disclaimer_due};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};
use serde_json::json;

use crate::commands::{interactive, label_of, start};
use crate::deps::Deps;
use crate::output::{CliError, Out, Outcome};

const FRAME: Duration = Duration::from_millis(250);

enum Msg {
    Usage {
        generation: u64,
        result: Box<Result<(Registry, Vec<AccountUsage>), CliError>>,
    },
    Status(String),
    Switched {
        key: String,
        result: Result<String, CliError>,
    },
}

enum Ctl {
    RefreshNow,
    Stop,
}

/// What a declined switch needs to go ahead.
#[derive(Clone, Copy, Default)]
struct Consent {
    force: bool,
    replace_live: bool,
}

struct App {
    reg: Registry,
    usage: Vec<AccountUsage>,
    table: TableState,
    status: String,
    refreshing: bool,
    last_refresh: Option<Instant>,
    generation: u64,
    switching: Option<JoinHandle<()>>,
    /// A switch refused for lack of consent: (key, consent so far, missing flag).
    pending: Option<(String, Consent, &'static str)>,
    /// Consent the running switch was started with.
    inflight: Consent,
    interval: u64,
}

pub fn run(deps: &Deps, out: &mut Out) -> Result<Outcome, CliError> {
    // The table is drawn on stdout: a redirected stdout gets no screen.
    if !interactive(out) || !std::io::stdout().is_terminal() {
        return Err(
            CliError::new("invalid", "`cma list --live` needs a terminal")
                .with_hint("use `cma usage`, or `cma list --live --json` for one live fetch"),
        );
    }
    let reg = {
        let profile = deps.profile();
        let ctx = deps.ctx(&profile);
        let mut s = start(&ctx, out)?;
        if disclaimer_due(&s.registry) {
            eprintln!("note: {}", cma_core::usage::DISCLAIMER);
            s.registry.settings.usage_disclaimer_shown = true;
            s.save()?;
        }
        s.registry.clone()
    };
    let interval = reg.settings.live_interval_secs.max(1);
    let (tx, rx) = mpsc::channel::<Msg>();
    let (ctl_tx, ctl_rx) = mpsc::channel::<Ctl>();
    let mut app = App {
        table: TableState::default().with_selected(if reg.accounts.is_empty() {
            None
        } else {
            Some(0)
        }),
        reg,
        usage: Vec::new(),
        status: "fetching usage…".into(),
        refreshing: true,
        last_refresh: None,
        generation: 0,
        switching: None,
        pending: None,
        inflight: Consent::default(),
        interval,
    };
    let worker = {
        let tx = tx.clone();
        let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let g = generation.clone();
        let h = std::thread::spawn(move || refresher(tx, ctl_rx, interval, g));
        (h, generation)
    };

    let mut terminal = ratatui::init();
    // ratatui's panic hook restores the terminal on any thread's panic.
    // Only a panic on this (UI) thread ends the screen; a background job's
    // panic is caught by the job and shown as an error instead.
    let ui_thread = std::thread::current().id();
    let screen_hook: std::sync::Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync> =
        std::sync::Arc::from(std::panic::take_hook());
    {
        let h = screen_hook.clone();
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current().id() == ui_thread {
                h(info);
            }
        }));
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ui_loop(&mut terminal, &mut app, &rx, &tx, &ctl_tx, &worker.1)
    }));
    ratatui::restore();
    // Put ratatui's hook back (the one installed by `ratatui::init`, which
    // also restores the terminal; harmless after the screen, and cma exits
    // right after the live view).
    let _ = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| screen_hook(info)));
    let result = result.unwrap_or_else(|_| {
        Err(CliError::new(
            "internal",
            "the live view hit an internal error and closed",
        ))
    });

    let _ = ctl_tx.send(Ctl::Stop);
    if app.refreshing || app.switching.is_some() {
        eprintln!("waiting for the running refresh or switch to finish…");
    }
    if let Some(h) = app.switching.take() {
        let _ = h.join();
    }
    let _ = worker.0.join();
    result?;
    Ok(Outcome::new(json!(null), ""))
}

fn ui_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    rx: &Receiver<Msg>,
    tx: &Sender<Msg>,
    ctl: &Sender<Ctl>,
    generation: &std::sync::atomic::AtomicU64,
) -> Result<(), CliError> {
    let io = |e: std::io::Error| CliError::new("io", format!("terminal: {}", e.kind()));
    loop {
        while let Ok(m) = rx.try_recv() {
            handle_msg(app, m, ctl);
        }
        terminal.draw(|f| draw(f, app)).map_err(io)?;
        if !event::poll(FRAME).map_err(io)? {
            continue;
        }
        let Event::Key(k) = event::read().map_err(io)? else {
            continue;
        };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        if is_ctrl_c(&k) {
            return Ok(());
        }
        if let Some((key, consent, flag)) = app.pending.take() {
            if matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
                let mut c = consent;
                if flag == "--replace-live" {
                    c.replace_live = true;
                } else {
                    c.force = true;
                }
                start_switch(app, tx, generation, key, c);
            } else {
                app.status = "switch cancelled".into();
            }
            continue;
        }
        if is_quit(&k) {
            return Ok(());
        }
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => app.table.select_previous(),
            KeyCode::Down | KeyCode::Char('j') => app.table.select_next(),
            KeyCode::Char('r') => {
                app.status = "refreshing…".into();
                let _ = ctl.send(Ctl::RefreshNow);
            }
            KeyCode::Char('d') => {
                app.status = "switch Claude Desktop with `cma switch --desktop <account>` (it quits and restarts Desktop)".into();
            }
            KeyCode::Enter | KeyCode::Char('b') => {
                let Some(key) = selected_key(app) else {
                    continue;
                };
                if k.code == KeyCode::Enter && app.reg.settings.default_target == Target::Desktop {
                    app.status = "default_target is desktop: switch it with `cma switch --desktop <account>` (it quits and restarts Desktop); press b to switch Claude Code only".into();
                    continue;
                }
                if start_switch(app, tx, generation, key, Consent::default())
                    && k.code == KeyCode::Char('b')
                {
                    app.status
                        .push_str(" (Claude Code only; Claude Desktop: `cma switch --desktop`)");
                }
            }
            _ => {}
        }
    }
}

/// Ctrl-C: raw mode delivers it as a key, not a signal. It quits even
/// while a "press y" prompt is shown.
fn is_ctrl_c(k: &KeyEvent) -> bool {
    k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL)
}

/// `q`, Esc or Ctrl-C.
fn is_quit(k: &KeyEvent) -> bool {
    matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) || is_ctrl_c(k)
}

/// Run a background job; a panic becomes an `internal` error, so the UI
/// never waits for a message that will not come.
fn guarded<T>(job: impl FnOnce() -> Result<T, CliError>) -> Result<T, CliError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).unwrap_or_else(|_| {
        Err(CliError::new(
            "internal",
            "the background job hit an internal error; run `cma status`",
        ))
    })
}

fn selected_key(app: &App) -> Option<String> {
    let i = app.table.selected()?;
    app.reg
        .accounts
        .get(i.min(app.reg.accounts.len().saturating_sub(1)))
        .map(|a| a.key.clone())
}

fn handle_msg(app: &mut App, m: Msg, ctl: &Sender<Ctl>) {
    match m {
        Msg::Usage { generation, result } => {
            app.refreshing = false;
            if generation < app.generation {
                // Started before the latest switch: its view is stale.
                let _ = ctl.send(Ctl::RefreshNow);
                return;
            }
            app.last_refresh = Some(Instant::now());
            match *result {
                Ok((reg, usage)) => {
                    app.reg = reg;
                    app.usage = usage;
                    if app.status.starts_with("fetching") || app.status.starts_with("refreshing") {
                        app.status.clear();
                    }
                }
                Err(e) if app.pending.is_none() => {
                    app.status = format!("usage refresh failed [{}]: {}", e.code, e.message);
                }
                Err(_) => {}
            }
        }
        Msg::Status(s) => {
            if s.starts_with("refreshing") {
                app.refreshing = true;
            }
            // Never hide a pending "press y" prompt: the next key answers it.
            if app.pending.is_none() {
                app.status = s;
            }
        }
        Msg::Switched { key, result } => {
            if let Some(h) = app.switching.take() {
                let _ = h.join();
            }
            match result {
                Ok(s) => {
                    app.status = s;
                    let _ = ctl.send(Ctl::RefreshNow);
                }
                Err(e) if e.code == "confirmation_required" => {
                    let flag = if e.message.contains("--replace-live") {
                        "--replace-live"
                    } else {
                        "--force"
                    };
                    let consent = app.inflight;
                    app.status = format!(
                        "{} — press y to switch anyway, any other key to cancel",
                        trim_flag(&e.message)
                    );
                    app.pending = Some((key, consent, flag));
                }
                Err(e) => {
                    app.status = format!("switch failed [{}]: {}", e.code, e.message);
                    if let Some(h) = e.hint {
                        app.status.push_str(&format!(" ({h})"));
                    }
                }
            }
        }
    }
}

fn trim_flag(m: &str) -> &str {
    m.rsplit_once("; pass --").map_or(m, |(a, _)| a)
}

fn start_switch(
    app: &mut App,
    tx: &Sender<Msg>,
    generation: &std::sync::atomic::AtomicU64,
    key: String,
    consent: Consent,
) -> bool {
    if app.switching.is_some() {
        app.status = "a switch is already running".into();
        return false;
    }
    app.generation += 1;
    generation.store(app.generation, std::sync::atomic::Ordering::SeqCst);
    app.status = format!(
        "switching Claude Code to {}…",
        app.reg
            .account(&key)
            .map(label_of)
            .unwrap_or_else(|| key.clone())
    );
    // Kept so a second refusal (the other consent) builds on this one.
    app.inflight = consent;
    app.pending = None;
    let tx = tx.clone();
    app.switching = Some(std::thread::spawn(move || {
        let result = guarded(|| switch_job(&key, consent, &tx));
        let _ = tx.send(Msg::Switched { key, result });
    }));
    true
}

fn switch_job(key: &str, consent: Consent, tx: &Sender<Msg>) -> Result<String, CliError> {
    let deps = Deps::from_env()?;
    let status = tx.clone();
    let registry_file = deps.paths.registry_file();
    cma_core::lock::set_account_wait_notifier(Some(Box::new(move |k: &str| {
        let who = Registry::load(&registry_file)
            .ok()
            .and_then(|r| r.account(k).map(label_of))
            .unwrap_or_else(|| k.to_string());
        let _ = status.send(Msg::Status(format!(
            "waiting for a token refresh of {who} to finish (up to 40 s)…"
        )));
    })));
    let profile = deps.profile();
    let ctx = deps.ctx(&profile);
    let mut out = Out::new(true);
    let mut s = start(&ctx, &mut out)?;
    let r = switch_cli(
        &mut s,
        key,
        &SwitchOpts {
            confirm: Confirm::NonInteractive {
                force: consent.force,
            },
            replace_live: Confirm::NonInteractive {
                force: consent.replace_live,
            },
            procs: deps.procs.as_ref(),
        },
    )?;
    let who = s
        .registry
        .account(key)
        .map(label_of)
        .unwrap_or_else(|| key.to_string());
    Ok(if r.already_active {
        format!("{who} already is the active Claude Code account")
    } else {
        format!("switched Claude Code to {who}")
    })
}

/// Background usage refresh: run, wait `interval` after it finished (or a
/// refresh request), repeat until stopped.
fn refresher(
    tx: Sender<Msg>,
    ctl: Receiver<Ctl>,
    interval: u64,
    generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    loop {
        let g = generation.load(std::sync::atomic::Ordering::SeqCst);
        let _ = tx.send(Msg::Status("refreshing usage…".into()));
        let result = guarded(usage_job);
        if tx
            .send(Msg::Usage {
                generation: g,
                result: Box::new(result),
            })
            .is_err()
        {
            return;
        }
        match ctl.recv_timeout(Duration::from_secs(interval)) {
            Ok(Ctl::Stop) | Err(RecvTimeoutError::Disconnected) => return,
            Ok(Ctl::RefreshNow) | Err(RecvTimeoutError::Timeout) => {
                // Collapse queued refresh requests; honour a queued stop.
                while let Ok(c) = ctl.try_recv() {
                    if matches!(c, Ctl::Stop) {
                        return;
                    }
                }
            }
        }
    }
}

fn usage_job() -> Result<(Registry, Vec<AccountUsage>), CliError> {
    let deps = Deps::from_env()?;
    let mut out = Out::new(true);
    let (run, reg) = crate::commands::usage::fetch(&deps, &mut out, None)?;
    Ok((reg, run.accounts))
}

fn draw(f: &mut ratatui::Frame<'_>, app: &mut App) {
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .areas(f.area());
    let age = app
        .last_refresh
        .map(|t| format!("updated {}s ago", t.elapsed().as_secs()))
        .unwrap_or_else(|| "not updated yet".into());
    let spin = if app.refreshing { " · refreshing" } else { "" };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                "cma — live usage, every {}s · {age}{spin}",
                app.interval
            )),
            Line::from("↑↓ select · Enter switch · d Desktop · b both · r refresh · q quit"),
        ]),
        head,
    );
    let now = cma_core::cli_target::system_now_ms() / 1000;
    let rows: Vec<Row> = app
        .reg
        .accounts
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let active = if app.reg.active.cli.as_deref() == Some(a.key.as_str()) {
                "CLI●"
            } else {
                ""
            };
            let mut who = label_of(a);
            if a.needs_login {
                who.push_str(" [needs login]");
            }
            let mut usage = crate::commands::list::usage_cell(a, now);
            if let Some(n) = app
                .usage
                .iter()
                .find(|u| u.key == a.key)
                .and_then(|u| u.note)
            {
                usage.push_str(&format!(" [{}]", n.message()));
            }
            Row::new(vec![
                Cell::from((i + 1).to_string()),
                Cell::from(active),
                Cell::from(who),
                Cell::from(a.org_name.clone()),
                Cell::from(a.plan.clone()),
                Cell::from(usage),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Percentage(30),
            Constraint::Percentage(15),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(vec!["#", "", "ACCOUNT", "ORG", "PLAN", "USAGE"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, body, &mut app.table);
    f.render_widget(Paragraph::new(app.status.clone()), foot);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App {
            reg: Registry::default(),
            usage: Vec::new(),
            table: TableState::default(),
            status: "refreshing usage…".into(),
            refreshing: true,
            last_refresh: None,
            generation: 1,
            switching: None,
            pending: None,
            inflight: Consent::default(),
            interval: 60,
        }
    }

    #[test]
    fn ctrl_c_q_and_esc_quit() {
        let key = |c, m| KeyEvent::new(c, m);
        assert!(is_quit(&key(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert!(is_ctrl_c(&key(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert!(is_quit(&key(KeyCode::Char('q'), KeyModifiers::NONE)));
        assert!(is_quit(&key(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(!is_quit(&key(KeyCode::Char('c'), KeyModifiers::NONE)));
        assert!(!is_quit(&key(KeyCode::Enter, KeyModifiers::NONE)));
    }

    #[test]
    fn a_panicking_switch_job_reports_an_error_and_frees_the_switch_slot() {
        let mut a = app();
        let (ctl, _rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        a.switching = Some(std::thread::spawn(move || {
            let result = guarded(|| -> Result<String, CliError> { panic!("boom") });
            let _ = tx.send(Msg::Switched {
                key: "B::oB".into(),
                result,
            });
        }));
        let m = rx.recv().unwrap();
        handle_msg(&mut a, m, &ctl);
        assert!(a.switching.is_none(), "a new switch can start");
        assert!(a.status.contains("internal"), "{}", a.status);
    }

    #[test]
    fn results_from_before_the_latest_switch_are_dropped() {
        let mut a = app();
        let (ctl, ctl_rx) = mpsc::channel();
        let mut reg = Registry::default();
        reg.active.cli = Some("stale".into());
        handle_msg(
            &mut a,
            Msg::Usage {
                generation: 0,
                result: Box::new(Ok((reg.clone(), Vec::new()))),
            },
            &ctl,
        );
        assert!(a.reg.active.cli.is_none(), "stale view not shown");
        assert!(matches!(ctl_rx.try_recv(), Ok(Ctl::RefreshNow)));
        handle_msg(
            &mut a,
            Msg::Usage {
                generation: 1,
                result: Box::new(Ok((reg, Vec::new()))),
            },
            &ctl,
        );
        assert_eq!(a.reg.active.cli.as_deref(), Some("stale"));
        assert!(a.status.is_empty());
    }

    #[test]
    fn a_refused_switch_asks_for_the_missing_consent_and_keeps_the_given_one() {
        let mut a = app();
        let (ctl, _rx) = mpsc::channel();
        a.inflight = Consent {
            force: true,
            replace_live: false,
        };
        handle_msg(
            &mut a,
            Msg::Switched {
                key: "B::oB".into(),
                result: Err(CliError::new(
                    "confirmation_required",
                    "the live CLI login is C; pass --replace-live",
                )),
            },
            &ctl,
        );
        let (key, consent, flag) = a.pending.clone().unwrap();
        assert_eq!(key, "B::oB");
        assert!(consent.force && !consent.replace_live);
        assert_eq!(flag, "--replace-live");
        assert!(a.status.contains("press y"), "{}", a.status);
        assert!(!a.status.contains("pass --"), "{}", a.status);
        // A background refresh does not hide the pending prompt.
        let prompt = a.status.clone();
        handle_msg(&mut a, Msg::Status("refreshing usage…".into()), &ctl);
        handle_msg(
            &mut a,
            Msg::Usage {
                generation: 1,
                result: Box::new(Err(CliError::new("locked", "busy"))),
            },
            &ctl,
        );
        assert_eq!(a.status, prompt);
        assert!(a.pending.is_some());
    }
}
