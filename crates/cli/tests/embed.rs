//! The in-process entry point the menubar app uses (`cma::embed`), on the
//! test backend with a fixed environment (temp HOME and CMA_HOME, file
//! fake Keychain): consent questions go to the app's asker only after the
//! command released its locks, and the command runs again with the answer.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use cma::embed::{Finished, run_with_env};
use cma::{AliasCmd, Cmd, LoginArgs, SwitchArgs};
use cma_core::paths::MapEnv;
use serde_json::{Value, json};

const FAR_FUTURE_MS: i64 = 4_000_000_000_000;
const USER: &str = "tester";

struct World {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    cma_home: PathBuf,
    fake: PathBuf,
}

fn oauth(tag: &str) -> Value {
    json!({
        "accessToken": format!("dummy-access-{tag}"),
        "refreshToken": format!("dummy-refresh-{tag}"),
        "expiresAt": FAR_FUTURE_MS,
        "refreshTokenExpiresAt": FAR_FUTURE_MS,
        "scopes": ["user:inference", "user:profile"],
        "subscriptionType": "max",
    })
}

impl World {
    /// A and B stored, B live and active.
    fn two_accounts() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cma_home = tmp.path().join("cma-home");
        let fake = tmp.path().join("fake");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(home.join(".claude.json"), b"{}").unwrap();
        let w = World {
            _tmp: tmp,
            home,
            cma_home,
            fake,
        };
        w.write("secrets.json", &json!([]));
        w.write(
            "profiles.json",
            &json!({
                "dummy-access-A": {"account": {"uuid": "A", "email": "a@x.test"}, "organization": {"uuid": "oA", "name": "Org A"}},
                "dummy-access-B": {"account": {"uuid": "B", "email": "b@x.test"}, "organization": {"uuid": "oB", "name": "Org B"}},
                "dummy-access-B2": {"account": {"uuid": "B", "email": "b@x.test"}, "organization": {"uuid": "oB", "name": "Org B"}},
                "dummy-access-A2": {"account": {"uuid": "A", "email": "a@x.test"}, "organization": {"uuid": "oA", "name": "Org A"}},
                "dummy-access-C": {"account": {"uuid": "C", "email": "c@x.test"}, "organization": {"uuid": "oC", "name": "Org C"}},
            }),
        );
        for tag in ["A", "B"] {
            w.set_live(tag);
            let f = w.run(Cmd::ImportCurrent { alias: None }, never());
            assert_eq!(f.exit_code, 0, "{}", f.document);
        }
        w
    }

    fn env(&self) -> MapEnv {
        MapEnv::new([
            ("HOME", self.home.to_str().unwrap()),
            ("USER", USER),
            ("CMA_HOME", self.cma_home.to_str().unwrap()),
            ("CMA_ALLOW_HOME_OVERRIDE", "1"),
            ("CMA_SECRET_BACKEND", "fake"),
            ("CMA_FAKE_DIR", self.fake.to_str().unwrap()),
        ])
    }

    fn write(&self, name: &str, v: &Value) {
        std::fs::write(self.fake.join(name), serde_json::to_vec(v).unwrap()).unwrap();
    }

    fn set_live(&self, tag: &str) {
        let p = self.fake.join("secrets.json");
        let mut v: Vec<Value> = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v.retain(|x| x["service"] != "Claude Code-credentials");
        let item = json!({"claudeAiOauth": oauth(tag)}).to_string();
        v.push(json!({"service": "Claude Code-credentials", "account": USER, "value": item}));
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    fn live_tag(&self) -> String {
        let v: Vec<Value> =
            serde_json::from_slice(&std::fs::read(self.fake.join("secrets.json")).unwrap())
                .unwrap();
        let item = v
            .iter()
            .find(|x| x["service"] == "Claude Code-credentials")
            .unwrap();
        let cred: Value = serde_json::from_str(item["value"].as_str().unwrap()).unwrap();
        cred["claudeAiOauth"]["accessToken"]
            .as_str()
            .unwrap()
            .trim_start_matches("dummy-access-")
            .to_string()
    }

    /// cma's stored credential for `key` (as if cma refreshed it).
    fn set_stored(&self, key: &str, tag: &str) {
        let p = self.fake.join("secrets.json");
        let mut v: Vec<Value> = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v.retain(|x| !(x["service"] == "claude-multi-auth" && x["account"] == key));
        let item = json!({"claudeAiOauth": oauth(tag)}).to_string();
        v.push(json!({"service": "claude-multi-auth", "account": key, "value": item}));
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    /// Switch to A (no consent needed) and return the switch's backup id.
    fn switch_to_a(&self) -> String {
        let f = self.run(switch("a@x.test"), never());
        assert_eq!(f.exit_code, 0, "{}", f.document);
        f.document["data"]["backup_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn running_claude(&self) {
        std::fs::write(self.fake.join("ps.txt"), "10 1 -zsh\n11 10 claude\n").unwrap();
    }

    fn run(&self, cmd: Cmd, ask: impl Fn(&str) -> bool + 'static) -> Finished {
        self.run_env(self.env(), cmd, ask)
    }

    fn run_env(&self, env: MapEnv, cmd: Cmd, ask: impl Fn(&str) -> bool + 'static) -> Finished {
        let f = run_with_env(env, cmd, ask);
        let s = f.document.to_string();
        assert!(!s.contains("dummy-"), "secret in the document: {s}");
        assert_eq!(f.document["schema_version"], 1);
        f
    }

    fn registry(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.cma_home.join("registry.json")).unwrap())
            .unwrap()
    }
}

fn never() -> impl Fn(&str) -> bool + 'static {
    |q: &str| panic!("unexpected question: {q}")
}

/// An asker that records each question and gives `answer`.
fn recording(answer: bool) -> (Rc<RefCell<Vec<String>>>, impl Fn(&str) -> bool + 'static) {
    let asked = Rc::new(RefCell::new(Vec::new()));
    let a = asked.clone();
    (asked, move |q: &str| {
        a.borrow_mut().push(q.to_string());
        answer
    })
}

fn switch(query: &str) -> Cmd {
    Cmd::Switch(SwitchArgs {
        query: Some(query.into()),
        cli: true,
        desktop: false,
        both: false,
        strict: false,
        force: false,
        replace_live: false,
        yes: false,
    })
}

fn lock_is_free(cma_home: &Path) -> bool {
    let f = std::fs::File::open(cma_home.join(".lock")).unwrap();
    let free = f.try_lock().is_ok();
    let _ = f.unlock();
    free
}

#[test]
fn running_sessions_are_asked_about_and_an_agreed_switch_runs_again() {
    let w = World::two_accounts();
    w.running_claude();
    let home = w.cma_home.clone();
    let asked = Rc::new(RefCell::new(Vec::<String>::new()));
    let a = asked.clone();
    let f = w.run(switch("a@x.test"), move |q: &str| {
        // Asked with no lock held: another process could take it now.
        assert!(lock_is_free(&home), "asked while the cma lock is held");
        a.borrow_mut().push(q.to_string());
        true
    });
    assert_eq!(f.exit_code, 0, "{}", f.document);
    assert_eq!(asked.borrow().len(), 1);
    assert!(asked.borrow()[0].ends_with("Switch anyway?"), "{:?}", asked);
    assert_eq!(w.live_tag(), "A");
    assert_eq!(f.document["data"]["to"], "A::oA");
}

#[test]
fn a_declined_question_switches_nothing() {
    let w = World::two_accounts();
    w.running_claude();
    let (asked, ask) = recording(false);
    let f = w.run(switch("a@x.test"), ask);
    assert_eq!(f.exit_code, 1);
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert_eq!(asked.borrow().len(), 1);
    assert_eq!(w.live_tag(), "B", "nothing switched");
}

#[test]
fn a_switch_that_needs_no_consent_never_asks() {
    let w = World::two_accounts();
    let f = w.run(switch("a@x.test"), never());
    assert_eq!(f.exit_code, 0, "{}", f.document);
    assert_eq!(w.live_tag(), "A");
}

#[test]
fn the_asker_is_gone_after_the_call() {
    let w = World::two_accounts();
    let (asked, ask) = recording(true);
    let f = w.run(switch("a@x.test"), ask);
    assert_eq!(f.exit_code, 0, "{}", f.document);
    // Same thread, a later command with a refusing asker: the earlier
    // (agreeing) asker must not answer for it.
    w.running_claude();
    let f = w.run(switch("b@x.test"), |_: &str| false);
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert!(asked.borrow().is_empty());
    assert_eq!(w.live_tag(), "A");
}

#[test]
fn an_alias_with_shell_characters_is_stored_literally() {
    let w = World::two_accounts();
    let alias = "\"; rm -rf ~ $(touch pwned) `x`";
    let f = w.run(
        Cmd::Alias(AliasCmd::Set {
            query: "A::oA".into(),
            alias: alias.into(),
        }),
        never(),
    );
    assert_eq!(f.exit_code, 0, "{}", f.document);
    let reg = w.registry();
    let a = reg["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == "A::oA")
        .unwrap();
    assert_eq!(a["alias"], alias);
    // An alias starting with a dash is a value, not a flag.
    let f = w.run(
        Cmd::Alias(AliasCmd::Set {
            query: "B::oB".into(),
            alias: "--force".into(),
        }),
        never(),
    );
    assert_eq!(f.exit_code, 0, "{}", f.document);
}

#[test]
fn login_does_not_run_embedded() {
    let w = World::two_accounts();
    let f = w.run(Cmd::Login(LoginArgs::default()), never());
    assert_eq!(f.document["error"]["code"], "invalid");
    let f = w.run(Cmd::List { live: false }, never());
    assert_eq!(f.exit_code, 0, "{}", f.document);
    assert_eq!(f.document["data"]["accounts"].as_array().unwrap().len(), 2);
}

#[test]
fn removing_the_active_account_asks_first() {
    let w = World::two_accounts();
    let (asked, ask) = recording(false);
    let f = w.run(
        Cmd::Remove {
            queries: vec!["b@x.test".into()],
            all: false,
            force: false,
        },
        ask,
    );
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert!(asked.borrow()[0].ends_with("Remove it anyway?"));
    assert_eq!(w.registry()["accounts"].as_array().unwrap().len(), 2);
}

/// An asker that records each question and answers by its last line.
fn answering(
    answer: impl Fn(&str) -> bool + 'static,
) -> (Rc<RefCell<Vec<String>>>, impl Fn(&str) -> bool + 'static) {
    let asked = Rc::new(RefCell::new(Vec::new()));
    let a = asked.clone();
    (asked, move |q: &str| {
        a.borrow_mut().push(q.to_string());
        answer(q.lines().last().unwrap_or_default())
    })
}

fn restore(id: &str, force: bool) -> Cmd {
    Cmd::Restore {
        id: id.into(),
        force,
        yes: false,
        replace_live: false,
    }
}

#[test]
fn replacing_an_unstored_live_login_is_its_own_question_before_running_sessions() {
    // Both agreed: two separate questions, then the switch.
    let w = World::two_accounts();
    w.set_live("C");
    w.running_claude();
    let (asked, ask) = answering(|_| true);
    let f = w.run(switch("a@x.test"), ask);
    assert_eq!(f.exit_code, 0, "{}", f.document);
    let last: Vec<String> = asked
        .borrow()
        .iter()
        .map(|q| q.lines().last().unwrap().to_string())
        .collect();
    assert_eq!(
        last,
        ["Replace it?", "Switch anyway?"],
        "{:?}",
        asked.borrow()
    );
    assert_eq!(w.live_tag(), "A");

    // Replacing agreed, running sessions declined: nothing switched.
    let w = World::two_accounts();
    w.set_live("C");
    w.running_claude();
    let (asked, ask) = answering(|last| last == "Replace it?");
    let f = w.run(switch("a@x.test"), ask);
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert_eq!(asked.borrow().len(), 2);
    assert_eq!(w.live_tag(), "C");

    // Replacing declined: the sessions question is never reached.
    let w = World::two_accounts();
    w.set_live("C");
    w.running_claude();
    let (asked, ask) = answering(|_| false);
    let f = w.run(switch("a@x.test"), ask);
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert_eq!(asked.borrow().len(), 1);
    assert!(asked.borrow()[0].ends_with("Replace it?"));
    assert_eq!(w.live_tag(), "C");
}

#[test]
fn a_forced_restore_over_a_changed_item_asks_and_a_decline_restores_nothing() {
    let w = World::two_accounts();
    let id = w.switch_to_a();
    // Claude Code refreshed A's token since the switch.
    w.set_live("A2");
    let f = w.run(restore(&id, false), never());
    assert_eq!(f.document["error"]["code"], "restore_conflict");
    let (asked, ask) = recording(false);
    let f = w.run(restore(&id, true), ask);
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert_eq!(asked.borrow().len(), 1);
    assert!(
        asked.borrow()[0].ends_with("Restore anyway?"),
        "{:?}",
        asked.borrow()
    );
    assert_eq!(w.live_tag(), "A2", "nothing restored");
    let (asked, ask) = recording(true);
    let f = w.run(restore(&id, true), ask);
    assert_eq!(f.exit_code, 0, "{}", f.document);
    assert_eq!(asked.borrow().len(), 1);
    assert_eq!(w.live_tag(), "B");
}

#[test]
fn a_forced_restore_of_an_older_login_asks_and_a_decline_restores_nothing() {
    let w = World::two_accounts();
    let id = w.switch_to_a();
    // cma refreshed B after the switch: its stored grant is newer than the
    // one the switch backed up.
    w.set_stored("B::oB", "B2");
    let f = w.run(restore(&id, false), never());
    assert_eq!(f.document["error"]["code"], "restore_older_login");
    let (asked, ask) = recording(false);
    let f = w.run(restore(&id, true), ask);
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert_eq!(asked.borrow().len(), 1);
    assert!(
        asked.borrow()[0].ends_with("Restore the older login anyway?"),
        "{:?}",
        asked.borrow()
    );
    assert_eq!(w.live_tag(), "A", "nothing restored");
}

#[test]
fn resolving_a_kept_journal_asks_first() {
    let w = World::two_accounts();
    let id = w.switch_to_a();
    std::fs::write(
        w.cma_home.join("op.journal"),
        serde_json::to_vec(&json!({
            "op": "switch", "target": "cli", "from": "B::oB", "to": "A::oA",
            "backup_id": id, "steps_done": ["keychain", "claude_json"],
        }))
        .unwrap(),
    )
    .unwrap();
    // The live login changed after the crash: the rollback cannot finish.
    w.set_live("C");
    let (asked, ask) = recording(false);
    let f = w.run(Cmd::ResolveJournal { yes: false }, ask);
    assert_eq!(f.document["error"]["code"], "confirmation_required");
    assert_eq!(asked.borrow().len(), 1);
    assert!(
        asked.borrow()[0].ends_with("Resolve it?"),
        "{:?}",
        asked.borrow()
    );
    assert!(w.cma_home.join("op.journal").exists(), "nothing resolved");
    let (_, ask) = recording(true);
    let f = w.run(Cmd::ResolveJournal { yes: false }, ask);
    assert_eq!(f.exit_code, 0, "{}", f.document);
    assert_eq!(f.document["data"]["resolved"], true);
    assert!(!w.cma_home.join("op.journal").exists());
}

#[test]
fn a_panic_while_a_journal_exists_is_state_uncertain_with_exit_2() {
    let w = World::two_accounts();
    std::fs::write(w.cma_home.join("op.journal"), b"{}").unwrap();
    let mut env = w.env();
    env.0.insert("CMA_TEST_PANIC".into(), "1".into());
    let f = w.run_env(env, Cmd::Status, never());
    assert_eq!(f.exit_code, 2, "{}", f.document);
    assert_eq!(f.document["error"]["code"], "state_uncertain");
    assert_eq!(f.document["state_uncertain"], true);
    // Without a journal the same panic is `internal`, exit 1.
    std::fs::remove_file(w.cma_home.join("op.journal")).unwrap();
    let mut env = w.env();
    env.0.insert("CMA_TEST_PANIC".into(), "1".into());
    let f = w.run_env(env, Cmd::Status, never());
    assert_eq!(f.exit_code, 1);
    assert_eq!(f.document["error"]["code"], "internal");
}
