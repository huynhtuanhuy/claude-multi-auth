//! The app's Desktop actions run through its consent handling
//! ([`commands::run_asking`]) against cma's fake backend: temp HOME and
//! CMA_HOME, a file-backed Keychain, a fake Claude Desktop (its process
//! list, quit/launch log and a fixture Desktop dir). Only dummy data.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;

use cma::{Cmd, DesktopCmd};
use cma_core::paths::MapEnv;
use serde_json::{Value, json};

use crate::commands::{desktop_link_cmd, run_asking, switch_cmd};

const USER: &str = "tester";
const FAR_FUTURE_MS: i64 = 4_000_000_000_000;
const DA: &str = "3a000000-0000-4000-8000-00000000000a";
const DOA: &str = "84000000-0000-4000-8000-0000000000c2";
const DB: &str = "7b000000-0000-4000-8000-00000000000b";
const DOB: &str = "60000000-0000-4000-8000-0000000000c1";
const DESKTOP_PS: &str = "500 1 /Applications/Claude.app/Contents/MacOS/Claude\n";

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

/// Questions asked, and the answers still to give (a missing one is no).
type Answers = (Rc<RefCell<Vec<String>>>, Rc<RefCell<VecDeque<bool>>>);

impl World {
    /// A and B stored (B live in Claude Code); a running Claude Desktop
    /// signed in as A, linked.
    fn new() -> Self {
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
                "dummy-access-A": {"account": {"uuid": DA, "email": "a@x.test"}, "organization": {"uuid": DOA, "name": "Org A"}},
                "dummy-access-B": {"account": {"uuid": DB, "email": "b@x.test"}, "organization": {"uuid": DOB, "name": "Org B"}},
            }),
        );
        for tag in ["A", "B"] {
            w.set_live(tag);
            let d = w.run(Cmd::ImportCurrent { alias: None }, &[]);
            assert_eq!(d["ok"], true, "{d}");
        }
        let d = w.desktop_dir();
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("config.json"),
            serde_json::to_vec(&json!({
                "lastKnownAccountUuid": DA,
                "oauth:tokenCacheV2": "TOKENV2-A",
                "locale": "en-US",
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(d.join("Cookies"), b"COOKIES-A").unwrap();
        std::fs::write(d.join("claude_desktop_config.json"), b"{}").unwrap();
        std::fs::write(w.fake.join("ps.txt"), DESKTOP_PS).unwrap();
        let d = w.run(
            Cmd::Desktop(DesktopCmd::ImportCurrent {
                alias: None,
                yes: false,
            }),
            &[],
        );
        assert_eq!(d["ok"], true, "{d}");
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

    /// Make `tag` the live Claude Code login (cma's stored items stay).
    fn set_live(&self, tag: &str) {
        let p = self.fake.join("secrets.json");
        let mut v: Vec<Value> = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v.retain(|x| x["service"] != "Claude Code-credentials");
        let item = json!({"claudeAiOauth": oauth(tag)}).to_string();
        v.push(json!({"service": "Claude Code-credentials", "account": USER, "value": item}));
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    /// The live Claude Code login's tag.
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

    fn desktop_dir(&self) -> PathBuf {
        self.home.join("Library/Application Support/Claude")
    }

    fn desktop_account(&self) -> Value {
        let c: Value =
            serde_json::from_slice(&std::fs::read(self.desktop_dir().join("config.json")).unwrap())
                .unwrap();
        c["lastKnownAccountUuid"].clone()
    }

    fn desktop_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.fake.join("desktop.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// What the fake Desktop shows after its next launch: B signed in.
    fn desktop_signs_in_as_b(&self) {
        self.write(
            "desktop-signin.json",
            &json!({
                "config": {"lastKnownAccountUuid": DB, "oauth:tokenCacheV2": "TOKENV2-B"},
                "files": {"Cookies": "COOKIES-B"},
            }),
        );
    }

    fn registry(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.cma_home.join("registry.json")).unwrap())
            .unwrap()
    }

    /// Run `cmd` as the app does, answering its questions with `answers`.
    fn run(&self, cmd: Cmd, answers: &[bool]) -> Value {
        self.run_recording(cmd, answers).0
    }

    fn run_recording(&self, cmd: Cmd, answers: &[bool]) -> (Value, Vec<String>) {
        let (asked, left): Answers = (
            Rc::new(RefCell::new(Vec::new())),
            Rc::new(RefCell::new(answers.iter().copied().collect())),
        );
        let (a, l) = (asked.clone(), left.clone());
        let env = self.env();
        let doc = run_asking(
            cmd,
            move |q| {
                a.borrow_mut().push(q.to_string());
                l.borrow_mut().pop_front().unwrap_or(false)
            },
            move |cmd, ask| cma::embed::run_with_env(env, cmd, ask),
        );
        let s = doc.to_string();
        assert!(
            !s.contains("dummy-") && !s.contains("TOKENV2"),
            "secret in the document: {s}"
        );
        let asked = asked.borrow().clone();
        (doc, asked)
    }
}

fn key(uuid: &str, org: &str) -> String {
    format!("{uuid}::{org}")
}

#[test]
fn a_declined_desktop_quit_during_link_changes_nothing() {
    let w = World::new();
    w.desktop_signs_in_as_b();
    let before = w.registry();
    let (d, asked) = w.run_recording(desktop_link_cmd(&key(DB, DOB)), &[false]);
    assert_eq!(d["error"]["code"], "cancelled", "{d}");
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert!(asked[0].contains("Quit Claude Desktop now?"), "{asked:?}");
    assert!(w.desktop_log().is_empty(), "Desktop was not quit");
    assert_eq!(w.desktop_account(), DA);
    assert_eq!(w.registry()["desktop"], before["desktop"]);
    assert_eq!(w.registry()["active"], before["active"]);
}

#[test]
fn link_asks_each_step_and_a_stop_after_storing_keeps_its_hint() {
    let w = World::new();
    // Quit: yes; signed in: no. The previous login was already stored, so
    // this is not "nothing changed": cma's message and hint stay.
    let (d, asked) = w.run_recording(desktop_link_cmd(&key(DB, DOB)), &[true, false]);
    assert_eq!(d["error"]["code"], "confirmation_required", "{d}");
    assert!(
        d["error"]["message"]
            .as_str()
            .unwrap()
            .contains("stopped after storing"),
        "{d}"
    );
    assert!(
        d["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("switch --desktop"),
        "{d}"
    );
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert!(asked[1].contains("Signed in?"), "{asked:?}");
    assert_eq!(w.desktop_log(), ["quit", "launch"]);
}

#[test]
fn link_signs_desktop_in_and_keeps_the_new_login_when_not_switching_back() {
    let w = World::new();
    w.desktop_signs_in_as_b();
    // Quit: yes; signed in: yes; switch back to A: no.
    let (d, asked) = w.run_recording(desktop_link_cmd(&key(DB, DOB)), &[true, true, false]);
    assert_eq!(d["ok"], true, "{d}");
    assert_eq!(asked.len(), 3, "{asked:?}");
    assert!(asked[2].contains("Switch Claude Desktop back"), "{asked:?}");
    assert_eq!(d["data"]["key"], key(DB, DOB));
    assert_eq!(d["data"]["active"], DB);
    assert!(d["data"]["restored_previous"].is_null());
    assert_eq!(w.desktop_log(), ["quit", "launch", "quit", "launch"]);
    assert_eq!(w.desktop_account(), DB);
    let reg = w.registry();
    assert_eq!(reg["active"]["desktop"], DB);
    assert_eq!(reg["desktop"].as_array().unwrap().len(), 2);
}

#[test]
fn switch_passes_the_desktop_and_both_targets_through() {
    for (target, cli, desktop, both) in [
        ("cli", true, false, false),
        ("desktop", false, true, false),
        ("both", false, false, true),
    ] {
        let Cmd::Switch(a) = switch_cmd("K", target).unwrap() else {
            panic!("not a switch");
        };
        assert_eq!((a.cli, a.desktop, a.both), (cli, desktop, both), "{target}");
        assert_eq!(a.query.as_deref(), Some("K"));
        assert!(!a.yes && !a.force && !a.replace_live && !a.strict);
    }
    assert!(switch_cmd("K", "Desktop").is_err());
    assert!(switch_cmd("K", "").is_err());

    let w = World::new();
    let (kb, ka) = (key(DB, DOB), key(DA, DOA));
    // B is not linked: refused before Desktop is quit.
    let d = w.run(switch_cmd(&kb, "desktop").unwrap(), &[]);
    assert_eq!(d["error"]["code"], "desktop_not_linked", "{d}");
    assert!(w.desktop_log().is_empty());

    w.desktop_signs_in_as_b();
    let d = w.run(desktop_link_cmd(&kb), &[true, true, false]);
    assert_eq!(d["ok"], true, "{d}");

    // Desktop runs (signed in as B): the quit is asked, then it switches.
    let (d, asked) = w.run_recording(switch_cmd(&ka, "desktop").unwrap(), &[true]);
    assert_eq!(d["ok"], true, "{d}");
    assert_eq!(d["data"]["target"], "desktop");
    assert_eq!(d["data"]["to"], ka);
    assert_eq!(d["data"]["desktop"]["switched"], true);
    assert!(asked[0].contains("Quit Claude Desktop now?"), "{asked:?}");
    assert_eq!(w.desktop_account(), DA);

    // Both: Claude Code (live B) and Desktop (A) to B: only Desktop moves.
    assert_eq!(w.live_tag(), "B");
    let d = w.run(switch_cmd(&kb, "both").unwrap(), &[true]);
    assert_eq!(d["ok"], true, "{d}");
    assert_eq!(d["data"]["target"], "both");
    assert_eq!(d["data"]["desktop"]["switched"], true);
    assert_eq!(w.desktop_account(), DB);
    assert_eq!(w.registry()["active"]["desktop"], DB);
    assert_eq!(w.live_tag(), "B");

    // Both to A: Claude Code and Desktop both move.
    let d = w.run(switch_cmd(&ka, "both").unwrap(), &[true]);
    assert_eq!(d["ok"], true, "{d}");
    assert_eq!(d["data"]["target"], "both");
    assert_eq!(d["data"]["to"], ka);
    assert_eq!(d["data"]["desktop"]["switched"], true);
    assert_eq!(w.live_tag(), "A");
    assert_eq!(w.desktop_account(), DA);
    let reg = w.registry();
    assert_eq!(reg["active"]["cli"], ka);
    assert_eq!(reg["active"]["desktop"], DA);
}
