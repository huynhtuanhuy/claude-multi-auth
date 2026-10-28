//! Tauri build script. The app's commands are listed in the ACL manifest,
//! so the webview can call only the ones `capabilities/default.json`
//! grants (each gets an `allow-<command>` permission).

const COMMANDS: &[&str] = &[
    "get_state",
    "poll",
    "switch",
    "remove",
    "set_alias",
    "set_setting",
    "refresh_usage",
    "list_backups",
    "restore",
    "resolve_journal",
    "install_cli",
    "start_login",
    "desktop_link",
    "set_launch_at_login",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build script failed");
}
