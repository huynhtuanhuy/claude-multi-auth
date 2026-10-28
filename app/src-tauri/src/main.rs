//! Claude Multi Auth: menubar app. Tray-only (no Dock icon); the settings
//! window is created on demand and hidden, not destroyed, when closed.
//!
//! Every cma operation runs in-process through `cma::embed` on a blocking
//! thread (see `commands`); a watcher thread refreshes the menu when
//! `registry.json` changes (another `cma` command) and runs the live usage
//! refresh when it is turned on.

mod commands;
#[cfg(test)]
mod embed_tests;
mod login;
mod tray;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use cma::Cmd;
use cma_core::paths::Paths;
use cma_core::registry::Registry;
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

use crate::commands::AppState;

const SETTINGS_LABEL: &str = "settings";
/// How often `registry.json` is checked for outside changes.
const WATCH_EVERY: Duration = Duration::from_secs(2);
/// Lowest live usage interval (as `cma config set` enforces).
const MIN_LIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Show the settings window (created on first use), optionally on a view.
pub fn open_settings(app: &AppHandle, section: Option<&str>) {
    if let Some(s) = section {
        *app.state::<AppState>()
            .section
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(s.to_string());
    }
    if let Some(w) = app.get_webview_window(SETTINGS_LABEL) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
        return;
    }
    let built =
        WebviewWindowBuilder::new(app, SETTINGS_LABEL, WebviewUrl::App("index.html".into()))
            .title("Claude Multi Auth")
            .inner_size(720.0, 620.0)
            .min_inner_size(520.0, 400.0)
            .build();
    match built {
        Ok(w) => {
            let w2 = w.clone();
            w.on_window_event(move |e| {
                if let WindowEvent::CloseRequested { api, .. } = e {
                    api.prevent_close();
                    let _ = w2.hide();
                }
            });
            let _ = w.set_focus();
        }
        Err(e) => eprintln!("claude-multi-auth: could not open the settings window: {e}"),
    }
}

/// A system notification (best effort).
pub fn notify(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
}

/// Whether the app launches at login; `None` when it cannot be read.
pub fn launch_at_login(app: &AppHandle) -> Option<bool> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().ok()
}

/// Watch `registry.json` for changes made outside the app and run the live
/// usage refresh while it is on. A plain thread: cma's I/O is blocking.
fn start_watcher(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last_usage: Option<Instant> = None;
        loop {
            std::thread::sleep(WATCH_EVERY);
            if commands::quitting(&app.state::<AppState>()) {
                return;
            }
            let Ok(paths) = Paths::from_system() else {
                continue;
            };
            let file = paths.registry_file();
            let mtime = commands::registry_mtime(&file);
            let state = app.state::<AppState>();
            let changed = {
                let mut seen = state.seen_mtime.lock().unwrap_or_else(|e| e.into_inner());
                let changed = *seen != mtime;
                *seen = mtime;
                changed
            };
            if changed {
                state.bump();
                tray::refresh(&app);
            }
            let Ok(reg) = Registry::load(&file) else {
                continue;
            };
            if !reg.settings.live_usage || reg.accounts.is_empty() {
                last_usage = None;
                continue;
            }
            let every = Duration::from_secs(reg.settings.live_interval_secs).max(MIN_LIVE_INTERVAL);
            if last_usage.is_some_and(|t| t.elapsed() < every) {
                continue;
            }
            // Skipped (tried again next tick) while another app command runs.
            if let Some(doc) = commands::try_run_cmd(&app, Cmd::Usage { query: None }) {
                last_usage = Some(Instant::now());
                if let Some(w) = doc["warnings"]
                    .as_array()
                    .and_then(|w| w.iter().find(|x| x["code"] == "usage_disclaimer"))
                {
                    notify(
                        &app,
                        "Live usage",
                        w["message"].as_str().unwrap_or_default(),
                    );
                }
            }
        }
    });
}

/// A panic prints only where it happened, never its message (as the CLI
/// does in JSON mode): no payload can carry data to stderr or a log.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".into());
        eprintln!("claude-multi-auth: internal error (panic at {at})");
    }));
}

fn main() {
    install_panic_hook();
    let app = tauri::Builder::default()
        // Registered first: a second launch only opens the settings window.
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            open_settings(app, None)
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let handle = app.handle().clone();
            if let Ok(p) = Paths::from_system() {
                login::clear_stale(&p, login::STALE_AFTER);
                *handle
                    .state::<AppState>()
                    .seen_mtime
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) =
                    commands::registry_mtime(&p.registry_file());
            }
            handle
                .state::<AppState>()
                .login_in_progress
                .store(false, Ordering::SeqCst);
            tray::create(&handle)?;
            start_watcher(handle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_state,
            commands::poll,
            commands::switch,
            commands::remove,
            commands::set_alias,
            commands::set_setting,
            commands::refresh_usage,
            commands::list_backups,
            commands::restore,
            commands::resolve_journal,
            commands::install_cli,
            commands::start_login,
            commands::desktop_link,
            commands::set_launch_at_login,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the app");
    app.run(|_app, event| {
        // Closing the settings window must not quit a menubar app; Quit
        // (an explicit exit code) does.
        if let RunEvent::ExitRequested {
            api, code: None, ..
        } = event
        {
            api.prevent_exit();
        }
    });
}
