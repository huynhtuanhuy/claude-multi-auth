//! Fixture Desktop dir (built from the layout census: two accounts, two
//! orgs each, sidecars, a secret journal file, decoy keys) under a temp
//! HOME, a scripted Desktop and `MemoryStore`. Nothing here touches the
//! real Desktop dir or starts/quits the real Desktop.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde_json::{Value, json};

use super::*;
use crate::backup::{Allowlist, Restorer};
use crate::cli_target::testkit::World;
use crate::desktop_app::tests::FakeApp;
use crate::procs::tests::p;
use crate::registry::{Registry, SessionFollow};
use crate::secret::MemoryStore;
use crate::switch::failpoint::{self, Act};
use crate::sync::begin;

const A: &str = "3a000000-0000-4000-8000-00000000000a";
const B: &str = "7b000000-0000-4000-8000-00000000000b";
const C: &str = "0b0c0d0e-0000-4000-8000-00000000000c";
const O1: &str = "60000000-0000-4000-8000-0000000000c1";
const O2: &str = "84000000-0000-4000-8000-0000000000c2";

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        failpoint::clear();
    }
}

fn dd(w: &World) -> PathBuf {
    w.paths.desktop_dir.clone()
}

fn write(p: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn read(p: &Path) -> String {
    String::from_utf8(std::fs::read(p).unwrap()).unwrap()
}

fn config(w: &World) -> Value {
    serde_json::from_slice(&std::fs::read(dd(w).join("config.json")).unwrap()).unwrap()
}

/// What Desktop leaves behind when `who` (tag `t`) is signed in: identity
/// keys and paths, plus settings that are not identity.
fn sign_in(w: &World, who: &str, t: &str) {
    let d = dd(w);
    let mut cfg = if d.join("config.json").exists() {
        config(w)
    } else {
        json!({"hostGitConfinedInstall": {"lastOffReadAt": "x"}, "locale": "en-US", "userThemeMode": "dark"})
    };
    let o = cfg.as_object_mut().unwrap();
    o.insert("lastKnownAccountUuid".into(), json!(who));
    o.insert("oauth:tokenCache".into(), json!(format!("TOKENCACHE-{t}")));
    o.insert("oauth:tokenCacheV2".into(), json!(format!("TOKENV2-{t}")));
    o.insert(
        "bootSideSessions".into(),
        json!({"accountUuid": who, "supported": true}),
    );
    o.insert(
        "bootSidebarPlaceholder".into(),
        json!(format!("PLACEHOLDER-{t}")),
    );
    o.insert(
        format!("dxt:allowlistCache:{O1}"),
        json!(format!("DXT-{t}")),
    );
    o.insert(format!("dxt:allowlistLastUpdated:{O1}"), json!(17));
    if t == "A" {
        // Only A has the second org's keys.
        o.insert(format!("dxt:allowlistCache:{O2}"), json!("DXT2-A"));
    }
    write(
        &d.join("config.json"),
        &serde_json::to_vec_pretty(&cfg).unwrap(),
    );
    write(&d.join("Cookies"), format!("COOKIES-{t}").as_bytes());
    write(&d.join("Cookies-journal"), b"");
    write(
        &d.join("Local Storage/leveldb/000003.log"),
        format!("LS-{t}").as_bytes(),
    );
    write(
        &d.join("Partitions/launch-preview-static/Session Storage/CURRENT"),
        format!("SS-{t}").as_bytes(),
    );
    if t == "A" {
        write(
            &d.join("IndexedDB/https_claude.ai_0.indexeddb.blob/1/00/a"),
            b"BLOB-A",
        );
        write(&d.join("config.json.journal"), b"CFGJOURNAL-SECRET-A");
    }
}

/// A signed in, sessions for both accounts in both orgs, settings that are
/// not identity, A and B stored as CLI accounts.
fn fixture() -> World {
    let w = World::new();
    let d = dd(&w);
    sign_in(&w, A, "A");
    write(
        &d.join("claude_desktop_config.json"),
        b"{\"mcpServers\":{}}",
    );
    write(&d.join("window-state.json"), b"{}");
    for (rel, body) in [
        (format!("claude-code-sessions/{A}/{O1}/local_1.json"), "s1"),
        (format!("claude-code-sessions/{A}/{O2}/local_2.json"), "s2"),
        (
            format!("claude-code-sessions/{A}/{O2}/scheduled-tasks.json"),
            "q",
        ),
        (format!("claude-code-sessions/{B}/{O1}/local_b.json"), "sb"),
        (
            format!("claude-code-sessions/{B}/{O1}/local_2.json"),
            "collides",
        ),
        (
            format!("local-agent-mode-sessions/{A}/{O2}/local_3/t.json"),
            "s3",
        ),
        (
            format!("local-agent-mode-sessions/{A}/{O2}/rpm/m.json"),
            "rpm",
        ),
        (
            format!("local-agent-mode-sessions/skills-plugin/{O2}/{A}/manifest.json"),
            "plugin",
        ),
        (
            format!("spaces-present/{}/{}/link-key", &A[..8], &O2[..8]),
            "lk",
        ),
    ] {
        write(&d.join(rel), body.as_bytes());
    }
    let mut r = Registry::default();
    for (acct, org, email) in [(A, O2, "a@x"), (B, O1, "b@x")] {
        r.accounts.push(Account {
            key: Account::key_for(acct, org),
            account_uuid: acct.into(),
            org_uuid: org.into(),
            email: email.into(),
            has_cli: true,
            ..Account::default()
        });
    }
    r.save(&w.paths.registry_file()).unwrap();
    w
}

fn opts<'a>(app: &'a dyn DesktopApp, force: bool) -> DesktopOpts<'a> {
    DesktopOpts {
        app,
        replace_live: Confirm::NonInteractive { force },
    }
}

fn yes() -> Confirm<'static> {
    Confirm::NonInteractive { force: true }
}

/// import-current A → link step 1 → B signs in → link B. Ends with B live.
fn linked_both(w: &World) {
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let r = link_live(&mut s, &yes(), None).unwrap();
    assert_eq!((r.account_uuid.as_str(), r.org_uuid.as_str()), (A, O2));
    assert!(!r.created_desktop_only);
    let st = stash_live(&mut s, &opts(&app, false)).unwrap();
    assert_eq!(st.from.as_deref(), Some(A));
    assert_eq!(st.to, None);
    assert_eq!(s.registry.active.desktop, None);
    drop(s);
    // Desktop starts signed out: no identity left.
    let cfg = config(w);
    assert!(cfg.get("lastKnownAccountUuid").is_none());
    assert!(cfg.get("oauth:tokenCacheV2").is_none());
    assert_eq!(cfg["locale"], "en-US");
    assert!(!dd(w).join("Cookies").exists());
    assert!(!dd(w).join("config.json.journal").exists());
    // The user signs in as B.
    sign_in(w, B, "B");
    let mut s = begin(&ctx).unwrap();
    let r = link_live(&mut s, &yes(), None).unwrap();
    assert_eq!((r.account_uuid.as_str(), r.org_uuid.as_str()), (B, O1));
    assert_eq!(s.registry.active.desktop.as_deref(), Some(B));
}

fn switch(w: &World, to: &str) -> Result<DesktopReport> {
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx)?;
    switch_desktop(&mut s, to, &opts(&app, false))
}

/// Every file under `root`, as text (lossy).
fn all_text(root: &Path) -> String {
    let mut out = String::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let m = std::fs::symlink_metadata(&p).unwrap();
        if m.is_dir() {
            for e in std::fs::read_dir(&p).unwrap() {
                stack.push(e.unwrap().path());
            }
        } else if m.is_file() {
            out.push_str(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()));
        }
    }
    out
}

fn reg(w: &World) -> Registry {
    Registry::load(&w.paths.registry_file()).unwrap()
}

#[test]
fn shipped_identity_data_parses_and_matches_keys() {
    let id = identity();
    assert_eq!(id.account_key, "lastKnownAccountUuid");
    for k in [
        "lastKnownAccountUuid",
        "oauth:tokenCache",
        "oauth:tokenCacheV2",
        "bootSideSessions",
        "bootSidebarPlaceholder",
        &format!("dxt:allowlistCache:{O1}"),
        &format!("dxt:allowlistLastUpdated:{O2}"),
    ] {
        assert!(id.matches_key(k), "{k}");
    }
    for k in [
        "hostGitConfinedInstall",
        "lastQuitCleanup",
        "updaterRunningInstance",
        &format!("dxt:allowlistEnabled:{O1}"),
        "dxt:allowlistCache:not-a-uuid",
        "locale",
    ] {
        assert!(!id.matches_key(k), "{k}");
    }
    assert_eq!(id.paths.len(), 19);
    assert!(id.units().contains(&"Cookies-journal".to_string()));
    assert!(id.units().contains(&"DIPS-wal".to_string()));
    assert_eq!(id.secret_files, vec!["config.json.journal"]);
    for f in &id.exclude {
        assert!(!id.units().contains(f), "{f}");
    }
    assert!(Identity::parse(&IDENTITY_JSON.replace("\"Cookies\"", "\"../Cookies\"")).is_err());
}

#[test]
fn link_and_switch_round_trip_merges_config_and_keeps_secrets_off_disk() {
    let w = fixture();
    let before = config(&w);
    linked_both(&w);
    let r = switch(&w, A).unwrap();
    assert_eq!((r.from.as_deref(), r.to.as_deref()), (Some(B), Some(A)));
    assert!(!r.already_active && r.backup_id.is_some());
    let d = dd(&w);
    let cfg = config(&w);
    // A's keys are back, B's are gone, and every other key is preserved.
    assert_eq!(cfg["lastKnownAccountUuid"], A);
    assert_eq!(cfg["oauth:tokenCacheV2"], "TOKENV2-A");
    assert_eq!(cfg[format!("dxt:allowlistCache:{O2}")], "DXT2-A");
    for k in ["hostGitConfinedInstall", "locale", "userThemeMode"] {
        assert_eq!(cfg[k], before[k], "{k}");
    }
    assert_eq!(read(&d.join("Cookies")), "COOKIES-A");
    assert_eq!(read(&d.join("Local Storage/leveldb/000003.log")), "LS-A");
    assert_eq!(
        read(&d.join("IndexedDB/https_claude.ai_0.indexeddb.blob/1/00/a")),
        "BLOB-A"
    );
    assert_eq!(read(&d.join("config.json.journal")), "CFGJOURNAL-SECRET-A");
    assert_eq!(
        read(&d.join("claude_desktop_config.json")),
        "{\"mcpServers\":{}}"
    );
    // B's login is stored: paths on disk (0700 dirs), values in the Keychain.
    let sb = store_dir(&w.paths, B).unwrap();
    assert_eq!(read(&sb.join("files/Cookies")), "COOKIES-B");
    assert_eq!(
        fsutil::existing_mode(&sb.join(SNAPSHOT_FILE)).unwrap(),
        Some(0o600)
    );
    for dir in [store_root(&w.paths), sb.clone(), sb.join("files")] {
        assert_eq!(
            std::fs::metadata(&dir).unwrap().mode() & 0o777,
            0o700,
            "{}",
            dir.display()
        );
    }
    let v2 = w
        .store
        .get(DESKTOP_SERVICE, &format!("{B}/oauth:tokenCacheV2"))
        .unwrap();
    assert_eq!(v2.unwrap().expose(), b"\"TOKENV2-B\"");
    // A is live, so its snapshot holds no paths.
    assert!(
        !store_dir(&w.paths, A)
            .unwrap()
            .join("files/Cookies")
            .exists()
    );
    // No config value or secret file content is ever written under CMA_HOME.
    let disk = all_text(&w.paths.cma_home);
    for secret in ["TOKENV2", "TOKENCACHE", "PLACEHOLDER", "DXT", "CFGJOURNAL"] {
        assert!(!disk.contains(secret), "{secret} written to disk");
    }
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
    assert_eq!(reg(&w).active.desktop.as_deref(), Some(A));

    // And back: B's latest state, A captured again.
    let r = switch(&w, B).unwrap();
    assert_eq!(r.to.as_deref(), Some(B));
    assert_eq!(config(&w)["oauth:tokenCacheV2"], "TOKENV2-B");
    assert!(config(&w).get(format!("dxt:allowlistCache:{O2}")).is_none());
    assert_eq!(read(&d.join("Cookies")), "COOKIES-B");
    assert!(!d.join("config.json.journal").exists());
    assert!(
        !d.join("IndexedDB/https_claude.ai_0.indexeddb.blob")
            .exists()
    );
    // Sessions were not touched (session follow is off).
    assert!(
        d.join(format!("claude-code-sessions/{A}/{O2}/local_2.json"))
            .exists()
    );
    // Already active: nothing written.
    let r = switch(&w, B).unwrap();
    assert!(r.already_active && r.backup_id.is_none());
}

#[test]
fn a_rotated_token_is_recaptured_before_every_switch() {
    let w = fixture();
    linked_both(&w);
    switch(&w, A).unwrap();
    // Desktop refreshed A's token while it ran.
    let mut cfg = config(&w);
    cfg["oauth:tokenCacheV2"] = json!("TOKENV2-A-ROTATED");
    write(
        &dd(&w).join("config.json"),
        &serde_json::to_vec(&cfg).unwrap(),
    );
    switch(&w, B).unwrap();
    switch(&w, A).unwrap();
    assert_eq!(config(&w)["oauth:tokenCacheV2"], "TOKENV2-A-ROTATED");
}

#[test]
fn session_follow_moves_every_org_and_keeps_collisions() {
    let w = fixture();
    linked_both(&w);
    switch(&w, A).unwrap();
    let mut r = reg(&w);
    r.settings.session_follow = SessionFollow::On;
    r.save(&w.paths.registry_file()).unwrap();
    let d = dd(&w);
    let rep = switch(&w, B).unwrap();
    assert!(rep.session_follow);
    // Both of A's orgs went to B's org O1.
    let b1 = d.join(format!("claude-code-sessions/{B}/{O1}"));
    assert_eq!(read(&b1.join("local_1.json")), "s1");
    assert_eq!(read(&b1.join("local_2.json")), "collides");
    let renamed: Vec<_> = std::fs::read_dir(&b1)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("local_2.json.cma-"))
        .collect();
    assert_eq!(renamed.len(), 1);
    assert_eq!(read(&b1.join(&renamed[0])), "s2");
    assert_eq!(rep.sessions_renamed.len(), 1);
    assert_eq!(
        read(&d.join(format!("local-agent-mode-sessions/{B}/{O1}/local_3/t.json"))),
        "s3"
    );
    // Kept names and non-movable patterns stay.
    assert!(
        d.join(format!(
            "claude-code-sessions/{A}/{O2}/scheduled-tasks.json"
        ))
        .exists()
    );
    assert!(
        d.join(format!("local-agent-mode-sessions/{A}/{O2}/rpm/m.json"))
            .exists()
    );
    assert!(
        d.join(format!(
            "local-agent-mode-sessions/skills-plugin/{O2}/{A}/manifest.json"
        ))
        .exists()
    );
    assert!(rep.sessions_left.len() >= 3, "{:?}", rep.sessions_left);
    let codes: Vec<_> = rep.warnings.iter().map(|w| w.code).collect();
    assert!(codes.contains(&"sessions_moved") && codes.contains(&"sessions_renamed"));
    assert_eq!(rep.sessions_moved, 3);
}

#[test]
fn user_restore_moves_back_only_unchanged_sessions() {
    let w = fixture();
    linked_both(&w);
    switch(&w, A).unwrap();
    let mut r = reg(&w);
    r.settings.session_follow = SessionFollow::On;
    r.save(&w.paths.registry_file()).unwrap();
    let rep = switch(&w, B).unwrap();
    let id = rep.backup_id.unwrap();
    let d = dd(&w);
    // B keeps working in one moved session.
    let moved = d.join(format!("claude-code-sessions/{B}/{O1}/local_1.json"));
    std::thread::sleep(std::time::Duration::from_millis(20));
    write(&moved, b"s1 + more");
    let ctx = w.ctx();
    let s = begin(&ctx).unwrap();
    let allow = Allowlist::for_paths(&w.paths);
    let rs = Restorer::load(&w.paths, &w.store, &w.locker, &allow, &id).unwrap();
    match rs.restore_user(s.lock(), false) {
        Err(Error::RestoreConflict(c)) => {
            assert_eq!(c.len(), 1, "{c:?}");
            assert!(c[0].contains("local_1.json"), "{c:?}");
        }
        other => panic!("expected a conflict, got {other:?}"),
    }
    // Forced: everything else goes back, the changed session stays.
    let rr = rs.restore_user(s.lock(), true).unwrap();
    assert!(
        rr.skipped.iter().any(|u| u.contains("local_1.json")),
        "{rr:?}"
    );
    assert!(!rr.state_uncertain(), "{rr:?}");
    assert_eq!(read(&moved), "s1 + more");
    assert!(
        d.join(format!("claude-code-sessions/{A}/{O2}/local_2.json"))
            .exists()
    );
    assert_eq!(config(&w)["lastKnownAccountUuid"], A);
    assert_eq!(read(&d.join("Cookies")), "COOKIES-A");
}

#[test]
fn desktop_appearing_mid_switch_keeps_the_journal_until_desktop_quits() {
    let _r = Reset;
    let mut w = fixture();
    linked_both(&w);
    let before_cfg = config(&w);
    let d = dd(&w);
    let mut r = reg(&w);
    r.settings.session_follow = SessionFollow::On;
    r.save(&w.paths.registry_file()).unwrap();
    let before_reg = reg(&w);
    let app = Rc::new(FakeApp {
        script: std::cell::RefCell::new(vec![FakeApp::running_app()]),
        ..Default::default()
    });
    app.stopped.set(true);
    let a2 = app.clone();
    // An auto-update relaunches Desktop right after the capture.
    failpoint::set(move |step, _| {
        if step == "capture" {
            a2.stopped.set(false);
        }
        Act::Continue
    });
    {
        let ctx = w.ctx();
        let mut s = begin(&ctx).unwrap();
        let e = switch_desktop(&mut s, A, &opts(app.as_ref(), false)).unwrap_err();
        assert_eq!(e.code(), "desktop_running", "{e}");
        assert!(e.to_string().contains("journal is kept"), "{e}");
        assert_eq!(s.registry, before_reg);
    }
    failpoint::clear();
    // Nothing was rolled back under the running Desktop: the capture's
    // moves are still in place, and the journal waits.
    assert!(crate::journal::read(&w.paths).unwrap().is_some());
    assert!(!d.join("Cookies").exists());
    assert_eq!(
        read(&store_dir(&w.paths, B).unwrap().join("files/Cookies")),
        "COOKIES-B"
    );
    // While Desktop runs, the next command refuses and writes nothing.
    w.procs.0 = vec![p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude")];
    {
        let ctx = w.ctx();
        assert_eq!(
            begin(&ctx).map(|_| ()).unwrap_err().code(),
            "desktop_running"
        );
    }
    assert!(!d.join("Cookies").exists());
    // Quit: the next command rolls everything back.
    w.procs.0.clear();
    let ctx = w.ctx();
    begin(&ctx).unwrap();
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
    assert_eq!(config(&w), before_cfg);
    assert_eq!(read(&d.join("Cookies")), "COOKIES-B");
    assert!(!d.join("config.json.journal").exists());
    assert!(
        store_dir(&w.paths, A)
            .unwrap()
            .join("files/Cookies")
            .exists()
    );
    assert!(
        !store_dir(&w.paths, B)
            .unwrap()
            .join("files/Cookies")
            .exists()
    );
    assert_eq!(reg(&w).desktop, before_reg.desktop);
    assert_eq!(
        w.store
            .get(DESKTOP_SERVICE, &format!("{A}/oauth:tokenCacheV2"))
            .unwrap()
            .unwrap()
            .expose(),
        b"\"TOKENV2-A\""
    );
}

#[test]
fn a_failure_after_session_moves_rolls_them_back() {
    let _r = Reset;
    let w = fixture();
    linked_both(&w);
    switch(&w, A).unwrap();
    let mut r = reg(&w);
    r.settings.session_follow = SessionFollow::On;
    r.save(&w.paths.registry_file()).unwrap();
    failpoint::set(|step, _| {
        if step == "post_check" {
            Act::Fail
        } else {
            Act::Continue
        }
    });
    let e = switch(&w, B).unwrap_err();
    assert_eq!(e.code(), "invalid");
    let d = dd(&w);
    assert_eq!(
        read(&d.join(format!("claude-code-sessions/{A}/{O1}/local_1.json"))),
        "s1"
    );
    assert_eq!(
        read(&d.join(format!("claude-code-sessions/{A}/{O2}/local_2.json"))),
        "s2"
    );
    assert_eq!(
        read(&d.join(format!("claude-code-sessions/{B}/{O1}/local_2.json"))),
        "collides"
    );
    assert_eq!(config(&w)["lastKnownAccountUuid"], A);
    assert_eq!(reg(&w).active.desktop.as_deref(), Some(A));
    // Folders the moves created are gone again.
    assert!(!d.join(format!("local-agent-mode-sessions/{B}")).exists());
}

#[test]
fn a_crash_is_recovered_only_while_desktop_is_quit() {
    let _r = Reset;
    let mut w = fixture();
    linked_both(&w);
    failpoint::set(|step, _| {
        if step == "apply" {
            Act::Crash
        } else {
            Act::Continue
        }
    });
    assert_eq!(switch(&w, A).unwrap_err().code(), "interrupted");
    failpoint::clear();
    assert!(crate::journal::read(&w.paths).unwrap().is_some());
    // The user starts Desktop before the next command.
    w.procs.0 = vec![
        p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude"),
        p(
            11,
            9,
            "/Applications/Claude.app/Contents/Helpers/chrome-native-host",
        ),
    ];
    {
        let ctx = w.ctx();
        let e = begin(&ctx).map(|_| ()).unwrap_err();
        assert_eq!(e.code(), "desktop_running");
        assert!(
            crate::journal::read(&w.paths).unwrap().is_some(),
            "journal kept"
        );
    }
    // Only the browser's native host left: it does not count.
    w.procs.0.remove(0);
    let ctx = w.ctx();
    let s = begin(&ctx).unwrap();
    assert!(s.warnings.iter().any(|x| x.code == "recovered"));
    drop(s);
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
    assert_eq!(config(&w)["lastKnownAccountUuid"], B);
    assert_eq!(read(&dd(&w).join("Cookies")), "COOKIES-B");
    assert!(
        store_dir(&w.paths, A)
            .unwrap()
            .join("files/Cookies")
            .exists()
    );
    // A's secret journal file, written by the interrupted apply, is gone.
    assert!(!dd(&w).join("config.json.journal").exists());
}

#[test]
fn a_login_cma_does_not_store_needs_consent_and_survives_in_the_backup() {
    let w = fixture();
    linked_both(&w);
    // Someone signs Desktop into C outside cma.
    sign_in(&w, C, "C");
    let e = switch(&w, A).unwrap_err();
    assert_eq!(e.code(), "confirmation_required");
    assert!(e.to_string().contains("--replace-live"), "{e}");
    assert_eq!(config(&w)["lastKnownAccountUuid"], C);
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let r = switch_desktop(&mut s, A, &opts(&app, true)).unwrap();
    assert!(r.warnings.iter().any(|x| x.code == "live_login_replaced"));
    assert!(
        r.warnings
            .iter()
            .any(|x| x.code == "desktop_account_changed")
    );
    let id = r.backup_id.unwrap();
    assert_eq!(
        read(&w.paths.backups_dir().join(&id).join("stash/Cookies")),
        "COOKIES-C"
    );
    assert_eq!(config(&w)["lastKnownAccountUuid"], A);
}

#[test]
fn switching_to_an_unlinked_account_or_without_desktop_config_fails_first() {
    let w = fixture();
    let e = switch(&w, B).unwrap_err();
    assert_eq!(e.code(), "desktop_not_linked");
    linked_both(&w);
    std::fs::remove_file(dd(&w).join("config.json")).unwrap();
    let e = switch(&w, A).unwrap_err();
    assert_eq!(e.code(), "not_found");
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
}

#[test]
fn a_running_desktop_is_refused_before_anything_is_written() {
    let w = fixture();
    linked_both(&w);
    let app = FakeApp::quits(); // running until asked to quit
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let e = switch_desktop(&mut s, A, &opts(&app, false)).unwrap_err();
    assert_eq!(e.code(), "desktop_running");
    assert!(app.calls.borrow().is_empty(), "the op itself never quits");
    assert_eq!(config(&w)["lastKnownAccountUuid"], B);
}

#[test]
fn a_desktop_only_account_needs_consent_and_unlink_removes_it() {
    let w = fixture();
    sign_in(&w, C, "C");
    write(
        &dd(&w).join(format!("claude-code-sessions/{C}/{O1}/local_c.json")),
        b"c",
    );
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let e = link_live(&mut s, &Confirm::NonInteractive { force: false }, None).unwrap_err();
    assert_eq!(e.code(), "confirmation_required");
    let r = link_live(&mut s, &yes(), Some("work")).unwrap();
    assert!(r.created_desktop_only);
    assert_eq!(r.org_uuid, O1, "org taken from the session layout");
    let a = s.registry.account(&r.key).unwrap();
    assert!(!a.has_cli);
    assert_eq!(a.alias.as_deref(), Some("work"));
    // Stash C so it has a stored login, then unlink it.
    let app = FakeApp::idle();
    stash_live(&mut s, &opts(&app, false)).unwrap();
    assert!(
        w.store
            .get(DESKTOP_SERVICE, &format!("{C}/oauth:tokenCacheV2"))
            .unwrap()
            .is_some()
    );
    let u = unlink(&mut s, C).unwrap();
    assert_eq!(u.removed_accounts, vec![r.key.clone()]);
    assert!(s.registry.account(&r.key).is_none());
    assert!(s.registry.desktop.is_empty());
    assert!(
        w.store
            .get(DESKTOP_SERVICE, &format!("{C}/oauth:tokenCacheV2"))
            .unwrap()
            .is_none()
    );
    assert!(!store_dir(&w.paths, C).unwrap().exists());
    let id = u.backup_id.unwrap();
    assert!(
        w.paths
            .backups_dir()
            .join(&id)
            .join("unlinked")
            .join(C)
            .join("files/Cookies")
            .exists()
    );
    assert_eq!(unlink(&mut s, C).unwrap_err().code(), "desktop_not_linked");
}

#[test]
fn backups_of_desktop_ops_pass_the_default_allowlist_and_are_flagged() {
    let w = fixture();
    linked_both(&w);
    let r = switch(&w, A).unwrap();
    let id = r.backup_id.unwrap();
    let store = MemoryStore::new();
    let allow = Allowlist::for_paths(&w.paths);
    let rs = Restorer::load(&w.paths, &store, &w.locker, &allow, &id).unwrap();
    assert!(touches_desktop(&w.paths, rs.manifest()));
}

#[test]
fn launch_and_verify_reports_problems_as_warnings() {
    let w = fixture();
    let app = FakeApp::idle();
    // Starts, and config.json names A.
    let ws = launch_and_verify(&app, &w.paths, Some(A), std::time::Duration::from_secs(1));
    assert!(ws.is_empty(), "{ws:?}");
    assert_eq!(*app.calls.borrow(), ["launch"]);
    let ws = launch_and_verify(&app, &w.paths, Some(B), std::time::Duration::from_secs(1));
    assert_eq!(ws[0].code, "desktop_verify_failed");
}

#[test]
fn an_unlinked_stored_account_is_linked_instead_of_moved_aside() {
    let w = fixture();
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    // A is signed in and stored, but was never linked.
    let r = stash_live(&mut s, &opts(&app, false)).unwrap();
    assert!(r.warnings.iter().any(|x| x.code == "desktop_auto_linked"));
    assert!(!r.warnings.iter().any(|x| x.code == "live_login_replaced"));
    assert_eq!(
        read(&store_dir(&w.paths, A).unwrap().join("files/Cookies")),
        "COOKIES-A"
    );
    let l = s
        .registry
        .desktop
        .iter()
        .find(|l| l.account_uuid == A)
        .unwrap();
    assert_eq!(l.last_org_uuid, O2);
}

#[test]
fn recovering_a_restore_of_a_desktop_backup_waits_for_desktop_to_quit() {
    let mut w = fixture();
    linked_both(&w);
    let id = switch(&w, A).unwrap().backup_id.unwrap();
    // A restore of that backup was interrupted.
    let j = json!({"op": "restore", "target": "backup", "from": id, "to": null, "backup_id": id, "steps_done": []});
    std::fs::write(w.paths.journal_file(), serde_json::to_vec(&j).unwrap()).unwrap();
    w.procs.0 = vec![p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude")];
    let ctx = w.ctx();
    let e = begin(&ctx).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), "desktop_running");
    assert!(crate::journal::read(&w.paths).unwrap().is_some());
}

#[test]
fn a_desktop_only_account_can_be_removed() {
    let w = fixture();
    sign_in(&w, C, "C");
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let r = link_live(&mut s, &yes(), None).unwrap();
    assert!(r.created_desktop_only);
    crate::account::remove(&mut s, &r.key, false).unwrap();
    assert!(s.registry.account(&r.key).is_none());
}

struct FlipProcs {
    calls: std::cell::Cell<usize>,
    quiet_for: usize,
}

impl crate::procs::ProcessLister for FlipProcs {
    fn list(&self) -> Result<Vec<crate::procs::ProcInfo>> {
        let n = self.calls.get();
        self.calls.set(n + 1);
        Ok(if n < self.quiet_for {
            Vec::new()
        } else {
            vec![p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude")]
        })
    }
}

#[test]
fn a_live_login_without_a_readable_account_needs_consent() {
    let w = fixture();
    let mut cfg = config(&w);
    cfg.as_object_mut().unwrap().remove("lastKnownAccountUuid");
    write(
        &dd(&w).join("config.json"),
        &serde_json::to_vec(&cfg).unwrap(),
    );
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let e = stash_live(&mut s, &opts(&app, false)).unwrap_err();
    assert_eq!(e.code(), "confirmation_required");
    assert!(dd(&w).join("Cookies").exists(), "nothing moved");
    let r = stash_live(&mut s, &opts(&app, true)).unwrap();
    assert!(r.warnings.iter().any(|x| x.code == "live_login_replaced"));
    // Nothing of a login left: no question.
    stash_live(&mut s, &opts(&app, false)).unwrap();
}

#[test]
fn a_failed_op_does_not_keep_the_auto_link() {
    let _r = Reset;
    let w = fixture();
    failpoint::set(|step, _| {
        if step == "capture" {
            Act::Fail
        } else {
            Act::Continue
        }
    });
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    stash_live(&mut s, &opts(&app, false)).unwrap_err();
    assert!(s.registry.desktop.is_empty());
    assert!(reg(&w).desktop.is_empty());
    assert_eq!(read(&dd(&w).join("Cookies")), "COOKIES-A");
}

#[test]
fn recovery_stops_with_the_journal_kept_when_desktop_starts_midway() {
    let _r = Reset;
    let w = fixture();
    linked_both(&w);
    failpoint::set(|step, _| {
        if step == "config" {
            Act::Crash
        } else {
            Act::Continue
        }
    });
    assert_eq!(switch(&w, A).unwrap_err().code(), "interrupted");
    failpoint::clear();
    // Desktop shows up after the first check.
    let fp = FlipProcs {
        calls: std::cell::Cell::new(0),
        quiet_for: 1,
    };
    let base = w.ctx();
    let ctx = crate::cli_target::Ctx { procs: &fp, ..base };
    let e = begin(&ctx).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), "desktop_running", "{e}");
    assert!(e.to_string().contains("journal is kept"), "{e}");
    assert!(crate::journal::read(&w.paths).unwrap().is_some());
    // Quit again: the next command finishes the rollback.
    let ctx = w.ctx();
    begin(&ctx).unwrap();
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
    assert_eq!(config(&w)["lastKnownAccountUuid"], B);
    assert_eq!(read(&dd(&w).join("Cookies")), "COOKIES-B");
}

#[test]
fn a_restore_stops_with_its_journal_kept_when_desktop_starts_midway() {
    let w = fixture();
    linked_both(&w);
    let id = switch(&w, A).unwrap().backup_id.unwrap();
    let ctx = w.ctx();
    let s = begin(&ctx).unwrap();
    let calls = std::cell::Cell::new(0);
    let g = || -> Result<()> {
        calls.set(calls.get() + 1);
        if calls.get() > 1 {
            Err(Error::DesktopRunning("pid 10".into()))
        } else {
            Ok(())
        }
    };
    let allow = Allowlist::for_paths(&w.paths);
    let rs = Restorer::load(&w.paths, &w.store, &w.locker, &allow, &id)
        .unwrap()
        .with_guard(&g);
    let e = rs.restore_user(s.lock(), false).unwrap_err();
    assert_eq!(e.code(), "desktop_running");
    assert!(
        crate::journal::read(&w.paths).unwrap().is_some(),
        "restore journal kept"
    );
    drop(s);
    // Desktop quit: the next command rolls the partial restore back.
    begin(&ctx).unwrap();
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
    assert_eq!(config(&w)["lastKnownAccountUuid"], A);
    assert_eq!(read(&dd(&w).join("Cookies")), "COOKIES-A");
}

#[test]
fn an_interrupted_capture_that_desktop_ran_over_keeps_the_moved_login() {
    let _r = Reset;
    let w = fixture();
    linked_both(&w);
    failpoint::set(|step, _| {
        if step == "capture" {
            Act::Crash
        } else {
            Act::Continue
        }
    });
    assert_eq!(switch(&w, A).unwrap_err().code(), "interrupted");
    failpoint::clear();
    // Desktop ran on the half-moved dir and created new storage.
    write(&dd(&w).join("Cookies"), b"COOKIES-NEW");
    let ctx = w.ctx();
    let e = begin(&ctx).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), "state_uncertain");
    let msg = e.to_string();
    assert!(
        msg.contains("files/") && msg.contains("resolve-journal"),
        "{msg}"
    );
    let stored = store_dir(&w.paths, B).unwrap().join("files/Cookies");
    assert_eq!(read(&stored), "COOKIES-B");
    let lock = crate::lock::CmaLock::acquire(&w.paths.lock_file()).unwrap();
    crate::journal::resolve(&w.paths, &lock).unwrap().unwrap();
    drop(lock);
    assert_eq!(
        read(&stored),
        "COOKIES-B",
        "accepting the state keeps the moved login"
    );
    begin(&ctx).unwrap();
}

/// Switch B→A, then Desktop (on A) rotates its token and rewrites keys.
fn switched_then_rotated(w: &World) -> String {
    linked_both(w);
    let id = switch(w, A).unwrap().backup_id.unwrap();
    let mut cfg = config(w);
    cfg["oauth:tokenCacheV2"] = json!("TOKENV2-A-ROTATED");
    cfg["bootSideSessions"] = json!({"accountUuid": A, "supported": false});
    write(
        &dd(w).join("config.json"),
        &serde_json::to_vec(&cfg).unwrap(),
    );
    id
}

#[test]
fn a_forced_restore_after_desktop_rotated_a_token_keeps_the_stored_login_current() {
    let w = fixture();
    let id = switched_then_rotated(&w);
    let ctx = w.ctx();
    let s = begin(&ctx).unwrap();
    let allow = Allowlist::for_paths(&w.paths);
    let rs = Restorer::load(&w.paths, &w.store, &w.locker, &allow, &id).unwrap();
    assert!(matches!(
        rs.restore_user(s.lock(), false),
        Err(Error::RestoreConflict(_))
    ));
    assert_eq!(
        previous_account(&w.paths, rs.manifest()).as_deref(),
        Some(B)
    );
    let rid = recapture_for_restore(&w.paths, &w.store, &w.locker, s.lock(), rs.manifest())
        .unwrap()
        .unwrap();
    assert!(rid.ends_with("desktop-recapture"));
    rs.restore_user(s.lock(), true).unwrap();
    drop(s);
    assert_eq!(config(&w)["lastKnownAccountUuid"], B);
    // A's stored login holds the rotated token, so switching back works.
    switch(&w, A).unwrap();
    assert_eq!(config(&w)["oauth:tokenCacheV2"], "TOKENV2-A-ROTATED");
    assert_eq!(config(&w)["bootSideSessions"]["supported"], false);
    assert_eq!(read(&dd(&w).join("Cookies")), "COOKIES-A");
}

#[test]
fn a_forced_restore_is_refused_when_desktop_added_identity() {
    let w = fixture();
    let id = switched_then_rotated(&w);
    let mut cfg = config(&w);
    cfg["oauth:somethingNew"] = json!("NEW");
    write(
        &dd(&w).join("config.json"),
        &serde_json::to_vec(&cfg).unwrap(),
    );
    let ctx = w.ctx();
    let s = begin(&ctx).unwrap();
    let allow = Allowlist::for_paths(&w.paths);
    let rs = Restorer::load(&w.paths, &w.store, &w.locker, &allow, &id).unwrap();
    let e =
        recapture_for_restore(&w.paths, &w.store, &w.locker, s.lock(), rs.manifest()).unwrap_err();
    assert_eq!(e.code(), "desktop_restore_refused");
    assert!(e.to_string().contains("cma switch --desktop"), "{e}");
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
}

#[test]
fn a_forced_restore_of_a_parked_login_moves_the_live_one_out_first() {
    let w = fixture();
    // C (no stored account) is live; link's first step parks it in the backup.
    sign_in(&w, C, "C");
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let id = stash_live(&mut s, &opts(&app, true))
        .unwrap()
        .backup_id
        .unwrap();
    drop(s);
    // The user signs in as B, which gets linked.
    sign_in(&w, B, "B");
    let mut s = begin(&ctx).unwrap();
    link_live(&mut s, &yes(), None).unwrap();
    let allow = Allowlist::for_paths(&w.paths);
    let rs = Restorer::load(&w.paths, &w.store, &w.locker, &allow, &id).unwrap();
    assert!(matches!(
        rs.restore_user(s.lock(), false),
        Err(Error::RestoreConflict(_))
    ));
    assert!(
        recapture_for_restore(&w.paths, &w.store, &w.locker, s.lock(), rs.manifest())
            .unwrap()
            .is_none()
    );
    let parked = park_live_for_restore(
        &w.paths,
        &w.store,
        &w.locker,
        s.lock(),
        &app,
        &yes(),
        rs.manifest(),
    )
    .unwrap()
    .unwrap();
    assert!(parked.backup_id.ends_with("desktop-park"));
    assert_eq!(parked.account.as_deref(), Some(B));
    // Now nothing conflicts: C's files and keys come back together.
    rs.restore_user(s.lock(), false).unwrap();
    drop(s);
    assert_eq!(config(&w)["lastKnownAccountUuid"], C);
    assert_eq!(config(&w)["oauth:tokenCacheV2"], "TOKENV2-C");
    assert_eq!(read(&dd(&w).join("Cookies")), "COOKIES-C");
    // B's login is stored under B, complete.
    assert_eq!(
        read(&store_dir(&w.paths, B).unwrap().join("files/Cookies")),
        "COOKIES-B"
    );
    assert_eq!(
        w.store
            .get(DESKTOP_SERVICE, &format!("{B}/oauth:tokenCacheV2"))
            .unwrap()
            .unwrap()
            .expose(),
        b"\"TOKENV2-B\""
    );
    let mut s = begin(&ctx).unwrap();
    switch_desktop(&mut s, B, &opts(&app, true)).unwrap();
    assert_eq!(config(&w)["oauth:tokenCacheV2"], "TOKENV2-B");
}

#[test]
fn parking_an_unstored_login_needs_consent_and_a_stored_one_is_linked() {
    let w = fixture();
    sign_in(&w, C, "C");
    let app = FakeApp::idle();
    let ctx = w.ctx();
    let mut s = begin(&ctx).unwrap();
    let id = stash_live(&mut s, &opts(&app, true))
        .unwrap()
        .backup_id
        .unwrap();
    // C again (unstored): consent needed, nothing moved without it.
    sign_in(&w, C, "C");
    let allow = Allowlist::for_paths(&w.paths);
    let rs = Restorer::load(&w.paths, &w.store, &w.locker, &allow, &id).unwrap();
    let no = Confirm::NonInteractive { force: false };
    let e = park_live_for_restore(
        &w.paths,
        &w.store,
        &w.locker,
        s.lock(),
        &app,
        &no,
        rs.manifest(),
    )
    .unwrap_err();
    assert_eq!(e.code(), "confirmation_required");
    assert!(e.to_string().contains("--replace-live"), "{e}");
    assert_eq!(read(&dd(&w).join("Cookies")), "COOKIES-C");
    assert!(crate::journal::read(&w.paths).unwrap().is_none());
    // A (stored, never linked) signed in: linked and stored under A.
    sign_in(&w, A, "A");
    drop(s);
    let s = begin(&ctx).unwrap();
    assert!(!s.registry.desktop.iter().any(|l| l.account_uuid == A));
    let p = park_live_for_restore(
        &w.paths,
        &w.store,
        &w.locker,
        s.lock(),
        &app,
        &no,
        rs.manifest(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(p.auto_linked.as_deref(), Some(A));
    assert_eq!(
        read(&store_dir(&w.paths, A).unwrap().join("files/Cookies")),
        "COOKIES-A"
    );
    assert!(reg(&w).desktop.iter().any(|l| l.account_uuid == A));
}

fn write_both(w: &World, r: &crate::journal::BothRecord) {
    let lock = crate::lock::CmaLock::acquire(&w.paths.lock_file()).unwrap();
    crate::journal::both_write(&w.paths, &lock, r).unwrap();
}

#[test]
fn a_both_record_of_a_running_owner_is_left_alone() {
    let w = fixture();
    // Owned by this (running) process, with a Claude Code backup that
    // recovery would try to restore.
    let mut r = crate::journal::BothRecord::new(Some("x".into()), "y".into());
    r.cli_backup_id = Some("20260101T000000Z-switch".into());
    assert!(r.owner_alive());
    write_both(&w, &r);
    let ctx = w.ctx();
    begin(&ctx).unwrap();
    assert!(
        crate::journal::both_read(&w.paths).unwrap().is_some(),
        "untouched"
    );
    // Its owner gone: recovery acts (here the backup is missing, so it
    // cannot put Claude Code back and says so).
    r.owner_pid = 0;
    write_both(&w, &r);
    let e = begin(&ctx).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), "state_uncertain");
    // A Desktop half that began and was never rolled back finished: the
    // record is just cleared, Claude Code is not touched.
    r.desktop_backup_id = Some("20260101T000001Z-desktop-switch".into());
    write_both(&w, &r);
    begin(&ctx).unwrap();
    assert!(crate::journal::both_read(&w.paths).unwrap().is_none());
}
