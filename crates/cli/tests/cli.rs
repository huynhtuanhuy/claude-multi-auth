//! End-to-end tests of the `cma` binary on the test backend
//! (`CMA_SECRET_BACKEND=fake`): a temp HOME and CMA_HOME, a file-backed fake
//! Keychain, fake profile/usage/token endpoints, a fake process list and a
//! fake `claude auth login`. Dummy credentials only; the environment is
//! cleared so nothing from the developer's shell reaches the binary.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::{Value, json};

const FAR_FUTURE_MS: i64 = 4_000_000_000_000;
const LIVE_SERVICE: &str = "Claude Code-credentials";
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

struct Run {
    code: i32,
    doc: Value,
    stderr: String,
}

impl World {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cma_home = tmp.path().join("cma-home");
        let fake = tmp.path().join("fake");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(home.join(".claude.json"), b"{\"numStartups\": 3}").unwrap();
        let w = World {
            _tmp: tmp,
            home,
            cma_home,
            fake,
        };
        w.write_fake("secrets.json", &json!([]));
        w
    }

    fn write_fake(&self, name: &str, v: &Value) {
        std::fs::write(self.fake.join(name), serde_json::to_vec_pretty(v).unwrap()).unwrap();
    }

    fn read_fake(&self, name: &str) -> Value {
        serde_json::from_slice(&std::fs::read(self.fake.join(name)).unwrap()).unwrap()
    }

    /// Register a profile for `tag` (access token `dummy-access-<tag>`).
    fn profile(&self, tag: &str, acct: &str, org: &str, email: &str) {
        let mut p = std::fs::read(self.fake.join("profiles.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or(json!({}));
        p[format!("dummy-access-{tag}")] = json!({
            "account": {"uuid": acct, "email": email, "display_name": "T"},
            "organization": {"uuid": org, "name": format!("Org {org}")},
        });
        self.write_fake("profiles.json", &p);
    }

    fn secrets(&self) -> Vec<Value> {
        self.read_fake("secrets.json").as_array().unwrap().clone()
    }

    fn secret(&self, service: &str, account: &str) -> Option<String> {
        self.secrets()
            .into_iter()
            .find(|x| x["service"] == service && x["account"] == account)
            .map(|x| x["value"].as_str().unwrap().to_string())
    }

    fn set_secret(&self, service: &str, account: &str, value: &str) {
        let mut v = self.secrets();
        v.retain(|x| !(x["service"] == service && x["account"] == account));
        v.push(json!({"service": service, "account": account, "value": value}));
        self.write_fake("secrets.json", &Value::Array(v));
    }

    fn set_live(&self, cred: &Value) {
        let item = json!({"claudeAiOauth": cred, "mcpOAuth": {"srv": {"x": 1}}});
        self.set_secret(LIVE_SERVICE, USER, &item.to_string());
    }

    fn live_oauth(&self) -> Value {
        let s = self.secret(LIVE_SERVICE, USER).unwrap();
        serde_json::from_str::<Value>(&s).unwrap()["claudeAiOauth"].clone()
    }

    fn cmd(&self) -> Command {
        Command::from_std(self.std_cmd())
    }

    fn std_cmd(&self) -> std::process::Command {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_cma"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("USER", USER)
            .env("CMA_HOME", &self.cma_home)
            .env("CMA_ALLOW_HOME_OVERRIDE", "1")
            .env("CMA_SECRET_BACKEND", "fake")
            .env("CMA_FAKE_DIR", &self.fake);
        c
    }

    fn run(&self, args: &[&str]) -> Run {
        let out = self.cmd().args(args).arg("--json").output().unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let doc: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout:?}"));
        assert_envelope(&doc);
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(!stderr.contains("dummy-"), "secret on stderr: {stderr}");
        Run {
            code: out.status.code().unwrap(),
            doc,
            stderr,
        }
    }

    /// Human mode (no `--json`): stdout and stderr, both checked for secrets.
    fn human(&self, args: &[&str]) -> (i32, String, String) {
        let out = self.cmd().args(args).output().unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            !stdout.contains("dummy-"),
            "{args:?}: secret on stdout: {stdout}"
        );
        assert!(
            !stderr.contains("dummy-"),
            "{args:?}: secret on stderr: {stderr}"
        );
        (out.status.code().unwrap(), stdout, stderr)
    }

    /// Human mode with a stand-in terminal answering its prompts in order
    /// (`answers`: comma-separated `y`/`n`).
    fn human_answering(&self, args: &[&str], answers: &str) -> (i32, String, String) {
        let out = self
            .cmd()
            .args(args)
            .env("CMA_TEST_TERMINAL_ANSWERS", answers)
            .output()
            .unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(!stdout.contains("dummy-"), "secret on stdout: {stdout}");
        assert!(!stderr.contains("dummy-"), "secret on stderr: {stderr}");
        (out.status.code().unwrap(), stdout, stderr)
    }

    fn set_stored(&self, key: &str, cred: &Value) {
        self.set_secret(
            "claude-multi-auth",
            key,
            &json!({"claudeAiOauth": cred}).to_string(),
        );
    }

    fn stored(&self, key: &str) -> Value {
        let s = self.secret("claude-multi-auth", key).unwrap();
        serde_json::from_str::<Value>(&s).unwrap()["claudeAiOauth"].clone()
    }

    fn ok(&self, args: &[&str]) -> Value {
        let r = self.run(args);
        assert_eq!(r.code, 0, "{args:?}: {}\n{}", r.doc, r.stderr);
        assert_eq!(r.doc["ok"], true);
        r.doc["data"].clone()
    }

    fn err(&self, args: &[&str], code: &str) -> Run {
        let r = self.run(args);
        assert_eq!(r.doc["ok"], false, "{args:?}: {}", r.doc);
        assert_eq!(r.doc["error"]["code"], code, "{args:?}: {}", r.doc);
        r
    }

    fn registry(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.cma_home.join("registry.json")).unwrap())
            .unwrap()
    }

    fn save_registry(&self, v: &Value) {
        std::fs::write(
            self.cma_home.join("registry.json"),
            serde_json::to_vec_pretty(v).unwrap(),
        )
        .unwrap();
    }

    /// A and B stored, A live and active.
    fn two_accounts() -> Self {
        let w = World::new();
        w.profile("A", "A", "oA", "a@x.test");
        w.profile("B", "B", "oB", "b@x.test");
        w.set_live(&oauth("A"));
        w.ok(&["import-current"]);
        w.write_fake("login.json", &oauth("B"));
        w.ok(&["login"]);
        w
    }
}

fn assert_envelope(doc: &Value) {
    let keys: Vec<&str> = doc
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for k in [
        "schema_version",
        "ok",
        "data",
        "warnings",
        "error",
        "state_uncertain",
    ] {
        assert!(keys.contains(&k), "missing {k}: {doc}");
    }
    assert_eq!(doc["schema_version"], 1);
    assert!(doc["ok"].is_boolean());
    assert!(doc["state_uncertain"].is_boolean());
    for w in doc["warnings"].as_array().unwrap() {
        assert!(w["code"].is_string() && w["message"].is_string(), "{w}");
    }
    if doc["ok"] == true {
        assert!(doc["error"].is_null());
    } else {
        assert!(doc["data"].is_null());
        assert!(doc["error"]["code"].is_string());
        assert!(doc["error"]["message"].is_string());
        assert!(doc["error"].get("hint").is_some());
    }
    // No dummy secret ever reaches the output.
    let s = doc.to_string();
    assert!(!s.contains("dummy-"), "secret in output: {s}");
}

fn has_keys(v: &Value, keys: &[&str]) {
    for k in keys {
        assert!(v.get(*k).is_some(), "missing {k} in {v}");
    }
}

fn warning_codes(doc: &Value) -> Vec<String> {
    doc["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn import_current_login_and_list_shapes() {
    let w = World::two_accounts();
    // The login did not touch the live login.
    assert_eq!(w.live_oauth(), oauth("A"));
    let d = w.ok(&["list"]);
    has_keys(&d, &["active", "accounts"]);
    assert_eq!(d["active"]["cli"], "A::oA");
    let accts = d["accounts"].as_array().unwrap();
    assert_eq!(accts.len(), 2);
    for a in accts {
        has_keys(
            a,
            &[
                "index",
                "key",
                "alias",
                "email",
                "org_name",
                "plan",
                "kind",
                "cli_active",
                "desktop_active",
                "needs_login",
                "added_at",
                "last_active_at",
                "usage",
            ],
        );
        has_keys(&a["usage"], &["fetched_at", "windows", "error"]);
    }
    assert_eq!(accts[0]["key"], "A::oA");
    assert_eq!(accts[0]["cli_active"], true);
    assert_eq!(accts[1]["email"], "b@x.test");
    assert_eq!(accts[1]["kind"], "oauth");
    // Human output goes to stdout; it is a table, not JSON.
    let out = w.cmd().arg("list").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("CLI●") && text.contains("b@x.test"), "{text}");
}

#[test]
fn login_shape_and_status_shape() {
    let w = World::new();
    w.profile("B", "B", "oB", "b@x.test");
    w.write_fake("login.json", &oauth("B"));
    let d = w.ok(&["login", "--alias", "work"]);
    has_keys(&d, &["key", "email", "org_name", "kind", "replaced"]);
    assert_eq!(d["key"], "B::oB");
    assert_eq!(d["replaced"], false);
    let s = w.ok(&["status"]);
    has_keys(
        &s,
        &[
            "cli",
            "desktop",
            "running_cli_sessions",
            "pending_journal",
            "sync_error",
            "cma_home",
            "accounts",
        ],
    );
    assert_eq!(s["cli"]["live"]["state"], "absent");
    assert_eq!(s["desktop"]["available"], true);
    assert_eq!(s["running_cli_sessions"], 0);
    assert!(s["pending_journal"].is_null());
}

#[test]
fn switch_happy_path_and_already_active() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "b@x.test"]);
    has_keys(
        &d,
        &[
            "target",
            "from",
            "to",
            "already_active",
            "running_sessions",
            "backup_id",
            "elapsed_ms",
            "storage_lock_held_ms",
            "desktop",
        ],
    );
    assert_eq!(d["from"], "A::oA");
    assert_eq!(d["to"], "B::oB");
    assert_eq!(d["target"], "cli");
    assert!(d["elapsed_ms"].is_u64());
    assert!(d["storage_lock_held_ms"].is_u64());
    assert_eq!(w.live_oauth(), oauth("B"));
    // mcpOAuth kept.
    let item: Value = serde_json::from_str(&w.secret(LIVE_SERVICE, USER).unwrap()).unwrap();
    assert_eq!(item["mcpOAuth"], json!({"srv": {"x": 1}}));
    let cj: Value =
        serde_json::from_slice(&std::fs::read(w.home.join(".claude.json")).unwrap()).unwrap();
    assert_eq!(cj["oauthAccount"]["accountUuid"], "B");
    assert_eq!(cj["numStartups"], 3);
    let d = w.ok(&["switch", "2"]);
    assert_eq!(d["already_active"], true);
}

/// The part of the running-sessions warning that explains what happens.
const SESSIONS_EXPLANATION: &str = "their /status keeps showing the old account name";

fn two_running_sessions(w: &World) {
    std::fs::write(
        w.fake.join("ps.txt"),
        "10 1 -zsh\n11 10 claude\n12 10 claude\n",
    )
    .unwrap();
}

#[test]
fn an_agreed_running_sessions_prompt_explains_once_in_human_mode() {
    let w = World::two_accounts();
    two_running_sessions(&w);
    let (code, stdout, stderr) = w.human_answering(&["switch", "B"], "y");
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let all = format!("{stdout}{stderr}");
    assert_eq!(all.matches(SESSIONS_EXPLANATION).count(), 1, "{all}");
    assert_eq!(
        stderr
            .matches("2 running Claude Code session(s): running sessions switch")
            .count(),
        1,
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("Switch anyway? [y/N]").count(),
        1,
        "{stderr}"
    );
    // The explanation comes before the prompt.
    assert!(stderr.find(SESSIONS_EXPLANATION) < stderr.find("Switch anyway?"));
    assert!(!stderr.contains("warning:"), "{stderr}");
    assert!(!all.contains("note:"), "{all}");
    assert_eq!(
        stdout.matches("switched Claude Code:").count(),
        1,
        "{stdout}"
    );
    assert_eq!(w.live_oauth(), oauth("B"));
}

#[test]
fn a_declined_running_sessions_prompt_explains_once_in_human_mode() {
    let w = World::two_accounts();
    two_running_sessions(&w);
    let (code, stdout, stderr) = w.human_answering(&["switch", "B"], "n");
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let all = format!("{stdout}{stderr}");
    assert_eq!(all.matches(SESSIONS_EXPLANATION).count(), 1, "{all}");
    assert!(
        stderr.contains("error [confirmation_required]: switch cancelled"),
        "{stderr}"
    );
    assert_eq!(w.live_oauth(), oauth("A"), "nothing switched");
}

#[test]
fn a_forced_switch_with_running_sessions_warns_once_in_human_mode() {
    let w = World::two_accounts();
    two_running_sessions(&w);
    let (code, stdout, stderr) = w.human(&["switch", "B", "--force"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let all = format!("{stdout}{stderr}");
    assert_eq!(all.matches(SESSIONS_EXPLANATION).count(), 1, "{all}");
    assert!(
        stderr.contains("warning: 2 running Claude Code session(s):"),
        "{stderr}"
    );
    assert!(!all.contains("Switch anyway?"), "{all}");
    assert!(!all.contains("note:"), "{all}");
    assert_eq!(
        stdout.matches("switched Claude Code:").count(),
        1,
        "{stdout}"
    );
    assert_eq!(w.live_oauth(), oauth("B"));
    // Also when a terminal is there: --force never prompts.
    w.ok(&["switch", "A", "--force"]);
    let (code, stdout, stderr) = w.human_answering(&["switch", "B", "--force"], "");
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let all = format!("{stdout}{stderr}");
    assert_eq!(all.matches(SESSIONS_EXPLANATION).count(), 1, "{all}");
    assert!(!all.contains("Switch anyway?"), "{all}");
}

#[test]
fn other_prompts_explain_once_in_human_mode() {
    let w = World::two_accounts();
    // Export: one consent, its warning printed once above the prompt.
    let dir = w.home.join("export");
    let (code, stdout, stderr) = w.human_answering(&["export", dir.to_str().unwrap(), "A"], "y");
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        stderr.matches("anyone who reads them").count(),
        1,
        "{stderr}"
    );
    assert_eq!(stderr.matches("Write them? [y/N]").count(), 1, "{stderr}");
    // Remove the active account: declined, then agreed.
    let active = "is the active CLI account";
    let (code, stdout, stderr) = w.human_answering(&["remove", "A"], "n");
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert_eq!(stderr.matches(active).count(), 1, "{stderr}");
    let (code, stdout, stderr) = w.human_answering(&["remove", "A"], "y");
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(format!("{stdout}{stderr}").matches(active).count(), 1);
    assert_eq!(
        stderr.matches("Remove it anyway? [y/N]").count(),
        1,
        "{stderr}"
    );
}

#[test]
fn running_sessions_need_force_in_json_mode() {
    let w = World::two_accounts();
    std::fs::write(w.fake.join("ps.txt"), "10 1 -zsh\n11 10 claude\n").unwrap();
    let r = w.err(&["switch", "B"], "confirmation_required");
    assert_eq!(r.code, 1);
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pass --force")
    );
    assert_eq!(w.live_oauth(), oauth("A"), "nothing switched");
    let r = w.run(&["switch", "B", "--force"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert!(warning_codes(&r.doc).contains(&"running_sessions".to_string()));
    assert_eq!(r.doc["data"]["running_sessions"], 1);
    assert_eq!(w.live_oauth(), oauth("B"));
}

#[test]
fn replacing_an_unstored_live_login_needs_its_own_flag() {
    let w = World::two_accounts();
    // C is a login cma does not store.
    w.profile("C", "C", "oC", "c@x.test");
    w.set_live(&oauth("C"));
    std::fs::write(w.fake.join("ps.txt"), "11 1 claude\n").unwrap();
    let r = w.err(&["switch", "B", "--force"], "confirmation_required");
    let m = r.doc["error"]["message"].as_str().unwrap();
    assert!(m.contains("pass --replace-live"), "{m}");
    assert!(m.contains("cma import-current"), "{m}");
    assert_eq!(w.live_oauth(), oauth("C"));
    let r = w.err(&["switch", "B", "--replace-live"], "confirmation_required");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pass --force")
    );
    let r = w.run(&["switch", "B", "--force", "--replace-live"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert!(warning_codes(&r.doc).contains(&"live_login_replaced".to_string()));
    assert_eq!(w.live_oauth(), oauth("B"));
}

const DA: &str = "3a000000-0000-4000-8000-00000000000a";
const DOA: &str = "84000000-0000-4000-8000-0000000000c2";
const DB: &str = "7b000000-0000-4000-8000-00000000000b";
const DOB: &str = "60000000-0000-4000-8000-0000000000c1";
const DESKTOP_PS: &str = "500 1 /Applications/Claude.app/Contents/MacOS/Claude\n";

impl World {
    fn desktop_dir(&self) -> PathBuf {
        self.home.join("Library/Application Support/Claude")
    }

    fn desktop_config(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.desktop_dir().join("config.json")).unwrap())
            .unwrap()
    }

    fn desktop_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.fake.join("desktop.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn desktop_running(&self, yes: bool) {
        std::fs::write(self.fake.join("ps.txt"), if yes { DESKTOP_PS } else { "" }).unwrap();
    }

    /// A (uuid accounts) live in Claude Code and signed in to a fixture
    /// Claude Desktop that runs; B stored.
    fn desktop_accounts() -> Self {
        let w = World::new();
        w.profile("A", DA, DOA, "a@x.test");
        w.profile("B", DB, DOB, "b@x.test");
        w.set_live(&oauth("A"));
        w.ok(&["import-current"]);
        w.write_fake("login.json", &oauth("B"));
        w.ok(&["login"]);
        let d = w.desktop_dir();
        std::fs::create_dir_all(d.join(format!("claude-code-sessions/{DA}/{DOA}"))).unwrap();
        std::fs::write(
            d.join(format!("claude-code-sessions/{DA}/{DOA}/local_1.json")),
            b"s1",
        )
        .unwrap();
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
        w.desktop_running(true);
        w
    }

    /// What the fake Desktop shows after its next launch: B signed in.
    fn desktop_signin_b(&self) {
        self.write_fake(
            "desktop-signin.json",
            &json!({
                "config": {"lastKnownAccountUuid": DB, "oauth:tokenCacheV2": "TOKENV2-B"},
                "files": {"Cookies": "COOKIES-B", "Local Storage/leveldb/1.log": "LS-B"},
            }),
        );
    }
}

#[test]
fn desktop_link_switch_both_restore_and_unlink() {
    let w = World::desktop_accounts();
    let d = w.desktop_dir();
    // Not linked yet: refused up front, nothing quit or switched.
    let r = w.err(&["switch", "b@x.test", "--desktop"], "desktop_not_linked");
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("desktop link")
    );
    w.err(
        &["switch", "b@x.test", "--both", "--strict"],
        "desktop_not_linked",
    );
    assert_eq!(w.live_oauth(), oauth("A"), "--strict refuses up front");
    assert!(w.desktop_log().is_empty());

    // import-current links the running Desktop's login without quitting it.
    let i = w.ok(&["desktop", "import-current"]);
    assert_eq!(i["account_uuid"], DA);
    assert_eq!(i["key"], format!("{DA}::{DOA}"));
    assert!(w.desktop_log().is_empty());
    let l = w.ok(&["list"]);
    assert_eq!(l["active"]["desktop"], DA);
    assert_eq!(l["accounts"][0]["desktop_linked"], true);

    // link signs in while the user watches: never in JSON mode.
    let r = w.err(&["desktop", "link", "b@x.test"], "confirmation_required");
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("import-current")
    );
    // On a terminal: quit? yes; signed in? yes; switch back to A? no.
    w.desktop_signin_b();
    let (code, out, err) = w.human_answering(&["desktop", "link", "b@x.test"], "y,y,n");
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(err.contains("Quit Claude Desktop now?"), "{err}");
    assert!(err.contains("Signed in?"), "{err}");
    assert_eq!(w.desktop_log(), ["quit", "launch", "quit", "launch"]);
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);
    assert_eq!(std::fs::read(d.join("Cookies")).unwrap(), b"COOKIES-B");
    let reg = w.registry();
    assert_eq!(reg["active"]["desktop"], DB);
    assert_eq!(reg["desktop"].as_array().unwrap().len(), 2);

    // Desktop runs: JSON mode needs --yes to quit it.
    let r = w.err(
        &["switch", "a@x.test", "--desktop"],
        "confirmation_required",
    );
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--yes")
    );
    let s = w.ok(&["switch", "a@x.test", "--desktop", "--yes"]);
    assert_eq!(s["target"], "desktop");
    assert_eq!(s["to"], format!("{DA}::{DOA}"));
    assert_eq!(s["desktop"]["switched"], true);
    assert_eq!(s["desktop"]["from"], DB);
    let cfg = w.desktop_config();
    assert_eq!(cfg["lastKnownAccountUuid"], DA);
    assert_eq!(cfg["oauth:tokenCacheV2"], "TOKENV2-A");
    assert_eq!(cfg["locale"], "en-US");
    assert_eq!(std::fs::read(d.join("Cookies")).unwrap(), b"COOKIES-A");
    assert!(!d.join("Local Storage").exists());
    assert_eq!(
        std::fs::read(d.join("claude_desktop_config.json")).unwrap(),
        b"{}"
    );
    assert_eq!(w.desktop_log()[4..], ["quit", "launch"]);
    // Token values never reach a file under CMA_HOME.
    let mut stack = vec![w.cma_home.clone()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            stack.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
        } else if let Ok(b) = std::fs::read(&p) {
            assert!(
                !String::from_utf8_lossy(&b).contains("TOKENV2"),
                "{}",
                p.display()
            );
        }
    }
    let st = w.ok(&["status"]);
    assert_eq!(st["desktop"]["available"], true);
    assert_eq!(st["desktop"]["active"], DA);
    assert_eq!(st["desktop"]["live_account"], DA);
    assert_eq!(st["desktop"]["running"], true);

    // --both: Claude Code and Desktop.
    let s = w.ok(&["switch", "b@x.test", "--both", "--yes"]);
    assert_eq!(s["target"], "both");
    assert_eq!(s["desktop"]["switched"], true);
    assert_eq!(w.live_oauth(), oauth("B"));
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);

    // default_target = desktop: a plain switch is a Desktop switch.
    let r = w.run(&["config", "set", "default_target", "desktop"]);
    assert_eq!(r.code, 0);
    assert!(warning_codes(&r.doc).is_empty(), "{}", r.doc);
    let s = w.ok(&["switch", "a@x.test", "--yes"]);
    assert_eq!(s["target"], "desktop");
    // The newest Desktop switch is the one a restore can undo cleanly.
    let switch_backup = s["backup_id"].as_str().unwrap().to_string();
    assert_eq!(w.live_oauth(), oauth("B"), "Claude Code untouched");
    assert_eq!(
        w.ok(&["switch", "a@x.test", "--cli"])["to"],
        format!("{DA}::{DOA}")
    );

    // Restore of a Desktop switch: only while Desktop is quit.
    let r = w.err(&["restore", &switch_backup], "desktop_running");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pid 9001")
    );
    w.desktop_running(false);
    let r = w.run(&["restore", &switch_backup]);
    assert_eq!(r.doc["ok"], true, "{}", r.doc);
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);
    assert_eq!(
        w.registry()["active"]["desktop"],
        DB,
        "re-synced after restore"
    );

    // unlink: the stored login goes into a backup; the live one stays.
    let u = w.ok(&["desktop", "unlink", "b@x.test"]);
    assert_eq!(u["account_uuid"], DB);
    assert!(u["backup_id"].is_string());
    // --both to an unlinked account: Claude Code switched, Desktop not (exit 3).
    let r = w.run(&["switch", "b@x.test", "--both", "--yes"]);
    assert_eq!(r.code, 3, "{}", r.doc);
    assert_eq!(r.doc["data"]["desktop"]["switched"], false);
    assert_eq!(r.doc["data"]["desktop"]["reason"], "desktop_not_linked");
    assert!(warning_codes(&r.doc).contains(&"desktop_not_linked".to_string()));
    assert_eq!(w.live_oauth(), oauth("B"));
}

#[test]
fn a_declined_desktop_quit_changes_nothing() {
    let w = World::desktop_accounts();
    w.ok(&["desktop", "import-current"]);
    w.desktop_signin_b();
    let (code, _out, err) = w.human_answering(&["desktop", "link", "b@x.test"], "n");
    assert_eq!(code, 1);
    assert_eq!(
        err.matches("Claude Desktop is running; cma quits it")
            .count(),
        1,
        "{err}"
    );
    assert!(w.desktop_log().is_empty());
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DA);
}

#[test]
fn failed_rollback_exits_2_and_repair_commands_still_work() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "B"]);
    let backup = d["backup_id"].as_str().unwrap().to_string();
    // Simulate a crash after the switch wrote B: the journal is still there,
    // and another writer has since replaced the live item with C.
    std::fs::write(
        w.cma_home.join("op.journal"),
        serde_json::to_vec(&json!({
            "op": "switch", "target": "cli", "from": "A::oA", "to": "B::oB",
            "backup_id": backup, "steps_done": ["keychain", "claude_json"],
        }))
        .unwrap(),
    )
    .unwrap();
    w.set_live(&oauth("C"));
    let r = w.err(&["list"], "state_uncertain");
    assert_eq!(r.code, 2);
    assert_eq!(r.doc["state_uncertain"], true);
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("cma status")
    );
    assert_eq!(
        w.live_oauth(),
        oauth("C"),
        "the newer value is never overwritten"
    );
    // status still answers, and shows the kept journal.
    let r = w.run(&["status"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert_eq!(r.doc["state_uncertain"], true);
    assert_eq!(
        r.doc["data"]["pending_journal"]["backup_id"],
        backup.as_str()
    );
    assert_eq!(r.doc["data"]["sync_error"]["code"], "state_uncertain");
    // backups lists it without running recovery.
    let b = w.ok(&["backups"]);
    let item = b["backups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == backup.as_str())
        .unwrap()
        .clone();
    has_keys(
        &item,
        &["id", "op", "created_at", "entries", "in_journal", "problem"],
    );
    assert_eq!(item["in_journal"], true);
    // restore is itself journaled: it refuses while the journal is kept,
    // before any conflict check (the live item changed since the switch, so
    // that check alone would answer `restore_conflict` and suggest --force).
    for args in [
        &["restore", backup.as_str()][..],
        &["restore", backup.as_str(), "--force", "--yes"][..],
    ] {
        let r = w.err(args, "state_uncertain");
        assert_eq!(r.code, 2, "{args:?}");
        let hint = r.doc["error"]["hint"].as_str().unwrap();
        assert!(hint.contains("cma status"), "{hint}");
        assert!(hint.contains("cma resolve-journal"), "{hint}");
    }
    // clean never deletes the journal's backup.
    let c = w.ok(&["clean", "--keep", "0"]);
    has_keys(&c, &["removed", "skipped", "keep"]);
    assert!(
        c["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == backup.as_str())
    );
}

#[test]
fn resolve_journal_accepts_the_state_and_restore_still_works() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "B"]);
    let backup = d["backup_id"].as_str().unwrap().to_string();
    // Fault injection: an unfinished switch whose rollback cannot complete
    // (another writer replaced the live item with C).
    let journal = w.cma_home.join("op.journal");
    std::fs::write(
        &journal,
        serde_json::to_vec(&json!({
            "op": "switch", "target": "cli", "from": "A::oA", "to": "B::oB",
            "backup_id": backup, "steps_done": ["keychain", "claude_json"],
        }))
        .unwrap(),
    )
    .unwrap();
    w.set_live(&oauth("C"));
    let r = w.err(&["switch", "A"], "state_uncertain");
    assert_eq!(r.code, 2);
    let hint = r.doc["error"]["hint"].as_str().unwrap();
    assert!(hint.contains("cma resolve-journal"), "{hint}");
    let (_, status, _) = w.human(&["status"]);
    assert!(status.contains("cma resolve-journal"), "{status}");
    // Without a terminal it needs --yes, and resolves nothing.
    let r = w.err(&["resolve-journal"], "confirmation_required");
    assert_eq!(r.code, 1);
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--yes")
    );
    assert!(journal.exists());
    let d = w.ok(&["resolve-journal", "--yes"]);
    has_keys(&d, &["resolved", "recovered", "journal", "archived"]);
    assert_eq!(d["resolved"], true);
    assert_eq!(d["recovered"], false);
    assert_eq!(d["journal"]["backup_id"], backup.as_str());
    assert_eq!(d["journal"]["op"], "switch");
    assert!(
        d["archived"]
            .as_str()
            .unwrap()
            .ends_with("resolved-journal.json")
    );
    assert!(!journal.exists());
    // Commands work again; the live login C was never touched.
    w.ok(&["list"]);
    assert_eq!(w.live_oauth(), oauth("C"));
    let b = w.ok(&["backups"]);
    let item = b["backups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == backup.as_str())
        .unwrap()
        .clone();
    assert_eq!(item["in_journal"], false);
    assert!(item["problem"].is_null(), "{item}");
    // The kept backup still restores (over C, which changed since: forced).
    w.err(&["restore", &backup], "restore_conflict");
    let r = w.run(&["restore", &backup, "--force", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert_eq!(w.live_oauth(), oauth("A"));
    // Nothing left to resolve.
    w.err(&["resolve-journal", "--yes"], "not_found");
    // clean copes with the archived journal inside a backup dir.
    let c = w.ok(&["clean", "--keep", "0"]);
    assert!(
        c["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == backup.as_str()),
        "{c}"
    );
}

#[test]
fn restore_puts_back_what_a_switch_wrote() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "B"]);
    let backup = d["backup_id"].as_str().unwrap();
    let r = w.ok(&["restore", backup]);
    has_keys(
        &r,
        &["id", "restored", "unchanged", "uncertain", "backup_id"],
    );
    assert_eq!(w.live_oauth(), oauth("A"));
    // Restoring again over values changed since (another writer) refuses.
    w.set_live(&oauth("C"));
    let r = w.err(&["restore", backup], "restore_conflict");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--force")
    );
}

#[test]
fn restore_force_over_a_newer_live_token_needs_consent_and_can_be_undone() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "B"]);
    let backup = d["backup_id"].as_str().unwrap().to_string();
    // Claude Code refreshed B's token since the switch.
    w.set_live(&oauth("B2"));
    let r = w.err(&["restore", &backup], "restore_conflict");
    let hint = r.doc["error"]["hint"].as_str().unwrap();
    assert!(hint.contains("newer token"), "{hint}");
    assert!(hint.contains("cma switch <account>"), "{hint}");
    assert!(hint.contains("restore's own backup"), "{hint}");
    // --force alone is not consent without a terminal.
    let r = w.err(&["restore", &backup, "--force"], "confirmation_required");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--yes")
    );
    assert_eq!(w.live_oauth(), oauth("B2"), "nothing restored");
    w.err(&["restore", &backup, "--yes"], "usage");
    // With consent: restored, and the overwritten newer token is named.
    let r = w.run(&["restore", &backup, "--force", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert_eq!(w.live_oauth(), oauth("A"));
    let undo = r.doc["data"]["backup_id"].as_str().unwrap().to_string();
    let m = r.doc["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["code"] == "restore_undo")
        .map(|x| x["message"].as_str().unwrap().to_string())
        .unwrap();
    assert!(m.contains(&format!("cma restore {undo}")), "{m}");
    // Undoing brings the newer token back.
    w.ok(&["restore", &undo]);
    assert_eq!(w.live_oauth(), oauth("B2"));
}

#[test]
fn restore_refuses_an_older_login_when_cma_holds_a_newer_one() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "B"]);
    let backup = d["backup_id"].as_str().unwrap().to_string();
    // cma refreshed A after the switch: its stored grant is newer than the
    // one the switch backed up.
    w.profile("A2", "A", "oA", "a@x.test");
    w.set_stored("A::oA", &oauth("A2"));
    let r = w.err(&["restore", &backup], "restore_older_login");
    assert_eq!(r.code, 1);
    let hint = r.doc["error"]["hint"].as_str().unwrap();
    assert!(hint.contains("cma switch a@x.test"), "{hint}");
    assert_eq!(w.live_oauth(), oauth("B"), "nothing restored");
    w.err(&["restore", &backup, "--force"], "confirmation_required");
    // Forced: the warning says how to get back to a working login.
    let r = w.run(&["restore", &backup, "--force", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert_eq!(w.live_oauth(), oauth("A"));
    let undo = r.doc["data"]["backup_id"].as_str().unwrap().to_string();
    let m = r.doc["warnings"].to_string();
    assert!(m.contains(&format!("cma restore {undo}")), "{m}");
    assert!(m.contains("cma switch a@x.test"), "{m}");
    // Following that advice: undo, then switch, puts the newer A live.
    w.ok(&["restore", &undo]);
    assert_eq!(w.live_oauth(), oauth("B"));
    assert_eq!(w.ok(&["switch", "a@x.test"])["to"], "A::oA");
    assert_eq!(w.live_oauth(), oauth("A2"));
    assert_eq!(w.stored("A::oA"), oauth("A2"));
}

#[test]
fn needs_login_and_refresh_pending_are_distinct_codes_with_hints() {
    let w = World::two_accounts();
    let mut reg = w.registry();
    for a in reg["accounts"].as_array_mut().unwrap() {
        if a["key"] == "B::oB" {
            a["needs_login"] = json!(true);
        }
    }
    w.save_registry(&reg);
    let r = w.err(&["switch", "B"], "needs_login");
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("cma login")
    );
    let l = w.ok(&["list"]);
    assert_eq!(l["accounts"][1]["needs_login"], true);
    // A pending post-refresh copy that needs verification blocks the switch
    // with refresh_pending (run `cma usage`, then retry).
    reg["accounts"][1]["needs_login"] = json!(false);
    w.save_registry(&reg);
    let from = cma_core::cli_target::oauth_fingerprint(&oauth("B"));
    let copy = json!({"claudeAiOauth": oauth("B2"), "cmaRefresh": {"from": from}});
    w.set_secret(
        "claude-multi-auth-backup",
        "B::oB/post-refresh",
        &copy.to_string(),
    );
    let r = w.err(&["switch", "B"], "refresh_pending");
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("cma usage")
    );
    assert_eq!(w.live_oauth(), oauth("A"));
}

#[test]
fn import_identical_needs_no_consent_and_duplicates_are_refused() {
    let w = World::two_accounts();
    let dir = w.home.join("exp");
    let r = w.err(
        &["export", dir.to_str().unwrap(), "B"],
        "confirmation_required",
    );
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--yes")
    );
    let d = w.ok(&["export", dir.to_str().unwrap(), "B", "--yes"]);
    let files = d["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    // Re-importing the same grant: nothing to consent to.
    let d = w.ok(&["import", files[0].as_str().unwrap()]);
    assert_eq!(d["unchanged"], json!(["B::oB"]));
    assert_eq!(d["stored"], json!([]));
    // A different stored grant: needs --replace.
    w.profile("B9", "B", "oB", "b@x.test");
    let other = w.home.join("b9.credential.json");
    std::fs::write(&other, json!({"claudeAiOauth": oauth("B9")}).to_string()).unwrap();
    let r = w.err(
        &["import", other.to_str().unwrap()],
        "confirmation_required",
    );
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pass --replace")
    );
    let d = w.ok(&["import", other.to_str().unwrap(), "--replace"]);
    assert_eq!(d["stored"][0]["replaced"], true);
    // Duplicate keys.
    let dup = w.home.join("dup.credential.json");
    let b = oauth("B").to_string();
    std::fs::write(
        &dup,
        format!(r#"{{"claudeAiOauth": {b}, "claudeAiOauth": {b}}}"#),
    )
    .unwrap();
    let r = w.err(&["import", dup.to_str().unwrap()], "invalid");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("repeats a key")
    );
}

#[test]
fn identical_import_with_alias_sets_the_alias() {
    let w = World::two_accounts();
    let dir = w.home.join("exp");
    let d = w.ok(&["export", dir.to_str().unwrap(), "B", "--yes"]);
    let f = d["files"][0].as_str().unwrap().to_string();
    let d = w.ok(&["import", &f, "--alias", "work"]);
    assert_eq!(d["unchanged"], json!(["B::oB"]));
    assert_eq!(d["alias_set"], "work");
    assert_eq!(w.ok(&["switch", "work"])["to"], "B::oB");
    // Without --alias: nothing set.
    assert!(w.ok(&["import", &f])["alias_set"].is_null());
}

#[test]
fn config_set_validates_only_the_key_being_set() {
    let w = World::two_accounts();
    let mut reg = w.registry();
    reg["settings"]["live_interval_secs"] = json!(5);
    w.save_registry(&reg);
    assert_eq!(
        w.ok(&["config", "set", "session_follow", "on"])["value"],
        "on"
    );
    w.err(&["config", "set", "live_interval_secs", "5"], "invalid");
}

#[test]
fn import_current_does_not_warn_about_the_login_it_imports() {
    let w = World::new();
    w.profile("A", "A", "oA", "a@x.test");
    w.set_live(&oauth("A"));
    let r = w.run(&["import-current"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert!(
        !warning_codes(&r.doc).contains(&"live_account_changed".to_string()),
        "{}",
        r.doc
    );
}

#[test]
fn removing_the_active_account_says_its_login_stays_live() {
    let w = World::two_accounts();
    let r = w.run(&["remove", "A", "--force"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    let m = r.doc["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["code"] == "removed_active")
        .map(|x| x["message"].as_str().unwrap().to_string())
        .unwrap();
    assert!(m.contains("stays live in Claude Code"), "{m}");
    assert_eq!(w.live_oauth(), oauth("A"));
}

#[test]
fn human_output_and_stderr_never_carry_secrets() {
    let w = World::two_accounts();
    std::fs::write(w.fake.join("ps.txt"), "11 1 claude\n").unwrap();
    let dir = w.home.join("exp");
    for args in [
        &["list"][..],
        &["status"],
        &["switch", "B"],
        &["switch", "B", "--force"],
        &["backups"],
        &["usage"],
        &["export", dir.to_str().unwrap(), "--yes"],
        &["import", dir.to_str().unwrap()],
        &["config", "get"],
        &["remove", "B"],
    ] {
        w.human(args);
    }
    let backup = w.ok(&["backups"])["backups"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    w.human(&["restore", &backup]);
}

#[test]
fn a_panic_in_json_mode_is_one_internal_error_document() {
    let w = World::two_accounts();
    let out = w
        .cmd()
        .env("CMA_TEST_PANIC", "1")
        .args(["list", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_envelope(&doc);
    assert_eq!(doc["error"]["code"], "internal");
    assert!(
        doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("panic at")
    );
    assert!(doc["error"]["hint"].is_string());
    // Only the location is reported, never the panic's message.
    let all = format!("{doc}{}", String::from_utf8_lossy(&out.stderr));
    assert!(!all.contains("injected test panic"), "{all}");
}

#[test]
fn a_panic_while_a_journal_exists_exits_2() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "B"]);
    let backup = d["backup_id"].as_str().unwrap().to_string();
    write_journal(&w, &backup);
    let out = w
        .cmd()
        .env("CMA_TEST_PANIC", "1")
        .args(["list", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_envelope(&doc);
    assert_eq!(doc["error"]["code"], "state_uncertain");
    assert_eq!(doc["state_uncertain"], true);
    assert!(
        doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("panic at")
    );
    assert!(
        doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("cma status")
    );
}

#[test]
fn resolve_journal_runs_recovery_first() {
    let w = World::two_accounts();
    let d = w.ok(&["switch", "B"]);
    let backup = d["backup_id"].as_str().unwrap().to_string();
    // A crash right after the switch wrote B: nothing else changed, so
    // recovery rolls it back completely and nothing is left to resolve.
    write_journal(&w, &backup);
    let r = w.run(&["resolve-journal"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert_eq!(r.doc["data"]["resolved"], false);
    assert_eq!(r.doc["data"]["recovered"], true);
    assert_eq!(r.doc["data"]["journal"]["backup_id"], backup.as_str());
    assert!(r.doc["data"]["archived"].is_null());
    assert!(warning_codes(&r.doc).contains(&"recovered".to_string()));
    assert!(!w.cma_home.join("op.journal").exists());
    assert_eq!(w.live_oauth(), oauth("A"), "rolled back, not accepted");
    // The kept-journal case says why recovery could not finish.
    w.ok(&["switch", "B"]);
    let backup = w.ok(&["backups"])["backups"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    write_journal(&w, &backup);
    w.set_live(&oauth("C"));
    let r = w.err(&["resolve-journal"], "confirmation_required");
    let m = r.doc["error"]["message"].as_str().unwrap();
    assert!(m.contains("uncertain"), "{m}");
    assert!(m.contains("pass --yes"), "{m}");
    assert_eq!(w.ok(&["resolve-journal", "--yes"])["resolved"], true);
}

fn write_journal(w: &World, backup: &str) {
    std::fs::write(
        w.cma_home.join("op.journal"),
        serde_json::to_vec(&json!({
            "op": "switch", "target": "cli", "from": "A::oA", "to": "B::oB",
            "backup_id": backup, "steps_done": ["keychain", "claude_json"],
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn help_describes_every_subcommand_and_argument() {
    let w = World::new();
    let help = |args: &[&str]| {
        let out = w.cmd().args(args).arg("--help").output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let d = help(&["desktop"]);
    for sub in ["link", "unlink", "import-current"] {
        let line = d
            .lines()
            .find(|l| l.trim_start().starts_with(sub))
            .unwrap_or_else(|| panic!("{sub} missing: {d}"));
        assert!(line.trim().len() > sub.len() + 5, "no description: {line}");
    }
    assert!(help(&["restore"]).contains("Backup id"));
    assert!(help(&["switch"]).contains("row number"));
    assert!(help(&["resolve-journal"]).contains("--yes"));
}

#[test]
fn test_backend_refuses_the_real_home_and_claude_dirs() {
    let real = nix::unistd::User::from_uid(nix::unistd::getuid())
        .unwrap()
        .unwrap()
        .dir;
    let real_claude = real.join(".claude");
    let w = World::new();
    // `desktop unlink` changes nothing even if the guard were missing.
    let cases: [(&str, &Path); 3] = [
        ("HOME", &real),
        ("CLAUDE_CONFIG_DIR", &real_claude),
        ("CLAUDE_SECURESTORAGE_CONFIG_DIR", &real_claude),
    ];
    for (var, val) in cases {
        let out = w
            .cmd()
            .env(var, val)
            .args(["desktop", "unlink", "--json"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{var}");
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(doc["error"]["code"], "invalid", "{var}: {doc}");
        let m = doc["error"]["message"].as_str().unwrap();
        assert!(m.contains("inside the real home"), "{var}: {m}");
        assert!(m.contains(var), "{var}: {m}");
    }
    assert!(!w.cma_home.exists(), "nothing created");
}

#[test]
fn usage_fetches_windows_shows_disclaimer_once_and_refreshes_inactive_accounts() {
    let w = World::two_accounts();
    // B's stored token is expired and B was never active: it is refreshed.
    let mut b = oauth("B");
    b["expiresAt"] = json!(1_000);
    let item = json!({"claudeAiOauth": b});
    w.set_secret("claude-multi-auth", "B::oB", &item.to_string());
    w.write_fake(
        "token.json",
        &json!({"dummy-refresh-B": {
            "access_token": "dummy-access-B2", "refresh_token": "dummy-refresh-B2", "expires_in": 28800,
            "refresh_token_expires_in": 2_000_000, "scope": "user:inference user:profile",
            "token_type": "Bearer",
            "account": {"uuid": "B", "email_address": "b@x.test"},
            "organization": {"uuid": "oB", "name": "Org oB"},
        }}),
    );
    w.write_fake(
        "usage.json",
        &json!({
            "dummy-access-A": {"five_hour": {"utilization": 42.0, "resets_at": "2026-10-27T14:00:00+00:00"},
                     "seven_day": {"utilization": 10.0}},
            "dummy-access-B2": {"five_hour": {"utilization": 7.0}},
        }),
    );
    let r = w.run(&["usage"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert!(warning_codes(&r.doc).contains(&"usage_disclaimer".to_string()));
    let accts = r.doc["data"]["accounts"].as_array().unwrap();
    for a in accts {
        has_keys(
            a,
            &[
                "key",
                "label",
                "windows",
                "fetched_at",
                "fresh",
                "source",
                "refreshed",
                "note",
                "error",
                "needs_login",
            ],
        );
    }
    assert_eq!(accts[0]["source"], "live");
    assert_eq!(accts[0]["windows"]["five_hour"]["utilization"], 42.0);
    assert_eq!(accts[1]["refreshed"], true, "{}", accts[1]);
    assert_eq!(accts[1]["windows"]["five_hour"]["utilization"], 7.0);
    // The rotated pair is stored; the post-refresh copy is gone.
    let stored: Value =
        serde_json::from_str(&w.secret("claude-multi-auth", "B::oB").unwrap()).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "dummy-refresh-B2");
    assert!(
        w.secret("claude-multi-auth-backup", "B::oB/post-refresh")
            .is_none()
    );
    assert!(
        w.secret("claude-multi-auth-backup", "B::oB/pre-refresh")
            .is_none()
    );
    // Second run: no disclaimer; list shows the cached windows.
    let r = w.run(&["usage", "A"]);
    assert!(!warning_codes(&r.doc).contains(&"usage_disclaimer".to_string()));
    assert_eq!(r.doc["data"]["accounts"].as_array().unwrap().len(), 1);
    let l = w.ok(&["list"]);
    assert_eq!(
        l["accounts"][1]["usage"]["windows"]["five_hour"]["utilization"],
        7.0
    );
    // list --live --json: one live fetch, then the list.
    let l = w.ok(&["list", "--live"]);
    assert_eq!(l["accounts"].as_array().unwrap().len(), 2);
}

#[test]
fn config_alias_and_remove() {
    let w = World::two_accounts();
    let d = w.ok(&["config", "get"]);
    has_keys(
        &d["settings"],
        &[
            "session_follow",
            "live_usage",
            "live_interval_secs",
            "default_target",
            "refresh_grace_secs",
        ],
    );
    assert_eq!(
        w.ok(&["config", "set", "live_interval_secs", "30"])["value"],
        30
    );
    assert_eq!(w.ok(&["config", "get", "live_interval_secs"])["value"], 30);
    w.err(&["config", "set", "live_interval_secs", "abc"], "invalid");
    w.err(&["config", "set", "live_interval_secs", "1"], "invalid");
    w.err(
        &["config", "set", "usage_disclaimer_shown", "true"],
        "invalid",
    );
    assert_eq!(
        w.ok(&["config", "set", "session_follow", "on"])["value"],
        "on"
    );
    // Aliases.
    assert_eq!(w.ok(&["alias", "set", "B", "work"])["alias"], "work");
    assert_eq!(w.ok(&["switch", "work"])["to"], "B::oB");
    w.err(&["alias", "set", "A", "12"], "invalid");
    w.err(&["alias", "set", "A", "WORK"], "invalid");
    assert!(w.ok(&["alias", "clear", "work"])["alias"].is_null());
    // Removing the active account needs --force.
    let r = w.err(&["remove", "B"], "confirmation_required");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--force")
    );
    let d = w.ok(&["remove", "B", "--force"]);
    assert_eq!(d["removed"][0]["key"], "B::oB");
    assert!(w.secret("claude-multi-auth", "B::oB").is_none());
    w.ok(&["remove", "--all"]);
    assert_eq!(w.ok(&["list"])["accounts"], json!([]));
    w.err(&["switch", "nobody"], "not_found");
}

#[test]
fn usage_errors_and_picker_need_a_query_without_a_terminal() {
    let w = World::two_accounts();
    let r = w.err(&["switch"], "invalid");
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("cma list")
    );
    // The live view needs a terminal (the tests have none).
    let out = w.cmd().args(["list", "--live"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("needs a terminal")
    );
    let r = w.err(&["switch", "--bogus"], "usage");
    assert_eq!(r.code, 1, "never 2, which means state uncertain");
}

#[test]
fn waiting_for_another_processs_refresh_is_announced() {
    let w = World::two_accounts();
    let paths = cma_core::paths::Paths::from_env(&cma_core::paths::MapEnv::new([
        ("HOME", w.home.to_str().unwrap()),
        ("CMA_HOME", w.cma_home.to_str().unwrap()),
        ("CMA_ALLOW_HOME_OVERRIDE", "1"),
    ]))
    .unwrap();
    // Another process (here: this test) holds B's account lock, as a token
    // refresh would, for a moment.
    let guard = cma_core::lock::AccountLock::acquire(&paths, "B::oB").unwrap();
    let child = w
        .std_cmd()
        .args(["switch", "B", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    drop(guard);
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("waiting for a token refresh of b@x.test"),
        "{stderr}"
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["ok"], true, "{doc}");
    assert_eq!(w.live_oauth(), oauth("B"));
}

#[test]
fn existing_registry_from_the_dev_harness_loads_unchanged() {
    // The registry shape written by the earlier developer harness.
    let w = World::new();
    w.profile("X", "X", "oX", "x@x.test");
    w.profile("Y", "Y", "oY", "y@x.test");
    std::fs::create_dir_all(&w.cma_home).unwrap();
    std::fs::set_permissions(
        &w.cma_home,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let x = oauth("X");
    let y = oauth("Y");
    w.set_live(&x);
    w.set_secret(
        "claude-multi-auth",
        "X::oX",
        &json!({"claudeAiOauth": x}).to_string(),
    );
    w.set_secret(
        "claude-multi-auth",
        "Y::oY",
        &json!({"claudeAiOauth": y}).to_string(),
    );
    w.save_registry(&json!({
        "schema_version": 1,
        "active": {"cli": "X::oX", "desktop": null},
        "settings": {"session_follow": "off", "live_usage": false, "live_interval_secs": 60,
                     "default_target": "cli", "refresh_grace_secs": 300},
        "accounts": [
            {"key": "X::oX", "kind": "oauth", "account_uuid": "X", "org_uuid": "oX",
             "email": "x@x.test", "org_name": "Org oX", "plan": "max", "alias": "X",
             "added_at": 1, "last_active_at": 1, "has_cli": true, "needs_login": false,
             "usage": {"fetched_at": 0, "windows": {}, "error": null}},
            {"key": "Y::oY", "kind": "oauth", "account_uuid": "Y", "org_uuid": "oY",
             "email": "y@x.test", "org_name": "Org oY", "plan": "pro", "alias": "Y",
             "added_at": 2, "last_active_at": 0, "has_cli": true, "needs_login": false,
             "usage": {"fetched_at": 0, "windows": {}, "error": null}}
        ],
        "desktop": [],
        "fingerprints": {},
        "unknown_future_field": {"kept": true}
    }));
    let l = w.ok(&["list"]);
    assert_eq!(l["accounts"][0]["alias"], "X");
    assert_eq!(l["accounts"][1]["alias"], "Y");
    assert_eq!(w.ok(&["switch", "Y"])["to"], "Y::oY");
    assert_eq!(w.live_oauth(), oauth("Y"));
    assert_eq!(w.registry()["unknown_future_field"], json!({"kept": true}));
}

#[test]
fn test_backend_refuses_the_real_cma_home() {
    let w = World::new();
    let out = w
        .cmd()
        .env_remove("CMA_ALLOW_HOME_OVERRIDE")
        .args(["list", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["error"]["code"], "invalid");
    assert!(
        doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("CMA_ALLOW_HOME_OVERRIDE")
    );
    // Nothing was created under the (temp) HOME's default cma dir.
    assert!(!Path::new(&w.home).join(".claude-multi-auth").exists());
}

#[test]
fn login_args_file_options_are_used_literally() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new();
    w.profile("A", "A", "oA", "a@x.test");
    w.write_fake("login.json", &oauth("A"));
    let args = w.home.join("login-args.json");
    let alias = "\"; rm -rf ~";
    std::fs::write(&args, json!({"alias": alias}).to_string()).unwrap();
    std::fs::set_permissions(&args, std::fs::Permissions::from_mode(0o600)).unwrap();
    let path = args.to_str().unwrap();
    // The file replaces the flags; both together are refused.
    w.err(&["login", "--args-file", path, "--alias", "x"], "usage");
    let data = w.ok(&["login", "--args-file", path]);
    assert_eq!(data["key"], "A::oA");
    let reg = w.registry();
    assert_eq!(reg["accounts"][0]["alias"], alias);
    // A file others can read is refused before anything runs.
    std::fs::set_permissions(&args, std::fs::Permissions::from_mode(0o644)).unwrap();
    w.err(&["login", "--args-file", path], "invalid");
}

impl World {
    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Run {
        let mut c = self.cmd();
        c.args(args).arg("--json");
        for (k, v) in env {
            c.env(k, v);
        }
        let out = c.output().unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let doc: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout:?}"));
        assert_envelope(&doc);
        Run {
            code: out.status.code().unwrap(),
            doc,
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    /// A and B linked to Desktop; Claude Code and Desktop both on B, Desktop running.
    fn both_on_b() -> Self {
        let w = World::desktop_accounts();
        w.ok(&["desktop", "import-current"]);
        w.desktop_signin_b();
        let (code, out, err) = w.human_answering(&["desktop", "link", "b@x.test"], "y,y,n");
        assert_eq!(code, 0, "{out}\n{err}");
        w.ok(&["switch", "b@x.test", "--cli"]);
        assert_eq!(w.live_oauth(), oauth("B"));
        w
    }

    fn quits(&self) -> usize {
        self.desktop_log().iter().filter(|l| *l == "quit").count()
    }
}

#[test]
fn both_refuses_before_claude_code_changes_when_desktop_cannot_switch() {
    let w = World::both_on_b();
    let quits = w.quits();
    // Desktop runs and JSON mode has no --yes.
    let r = w.err(&["switch", "a@x.test", "--both"], "confirmation_required");
    assert_eq!(r.code, 1);
    assert_eq!(w.live_oauth(), oauth("B"));
    // A's stored Desktop login is incomplete: refused with and without --strict.
    let cookies = w.cma_home.join(format!("desktop/{DA}/files/Cookies"));
    std::fs::remove_file(&cookies).unwrap();
    for args in [
        &["switch", "a@x.test", "--both", "--yes"][..],
        &["switch", "a@x.test", "--both", "--strict", "--yes"],
    ] {
        let r = w.err(args, "not_found");
        assert_eq!(r.code, 1);
        assert_eq!(w.live_oauth(), oauth("B"), "{args:?}");
    }
    assert_eq!(w.quits(), quits, "Desktop was never quit");
    std::fs::write(&cookies, b"COOKIES-A").unwrap();
    // Everything in place: both switch.
    let s = w.ok(&["switch", "a@x.test", "--both", "--strict", "--yes"]);
    assert_eq!(s["desktop"]["switched"], true);
    assert_eq!(w.live_oauth(), oauth("A"));
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DA);
}

#[test]
fn both_puts_claude_code_back_when_the_desktop_half_fails() {
    let w = World::both_on_b();
    let r = w.run_env(
        &["switch", "a@x.test", "--both", "--yes"],
        &[("CMA_TEST_DESKTOP_HALF", "fail")],
    );
    assert_eq!(r.code, 1, "{}", r.doc);
    assert_eq!(r.doc["error"]["code"], "not_found");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("switched back")
    );
    assert_eq!(w.live_oauth(), oauth("B"), "Claude Code rolled back");
    assert_eq!(w.registry()["active"]["cli"], format!("{DB}::{DOB}"));
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);
    assert_eq!(w.desktop_log().last().map(String::as_str), Some("launch"));
    assert!(warning_codes(&r.doc).contains(&"desktop_relaunched".to_string()));
}

#[test]
fn both_exits_2_when_claude_code_cannot_be_put_back() {
    let w = World::both_on_b();
    let r = w.run_env(
        &["switch", "a@x.test", "--both", "--yes"],
        &[("CMA_TEST_DESKTOP_HALF", "fail_after_refresh")],
    );
    assert_eq!(r.code, 2, "{}", r.doc);
    assert_eq!(r.doc["error"]["code"], "state_uncertain");
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("putting Claude Code back failed")
    );
    // The record is kept, so status and resolve-journal see it.
    let st = w.run(&["status"]);
    assert!(st.doc["data"]["pending_both"].is_object(), "{}", st.doc);
    assert_eq!(st.doc["state_uncertain"], true);
    assert_eq!(w.ok(&["resolve-journal", "--yes"])["resolved"], true);
    assert!(!w.cma_home.join("both.journal").exists());
}

#[test]
fn both_reports_an_uncertain_desktop_half_as_exit_2() {
    let w = World::both_on_b();
    let r = w.run_env(
        &["switch", "a@x.test", "--both", "--yes"],
        &[("CMA_TEST_DESKTOP_HALF", "state_uncertain")],
    );
    assert_eq!(r.code, 2, "{}", r.doc);
    assert_eq!(r.doc["error"]["code"], "state_uncertain");
    assert_eq!(r.doc["state_uncertain"], true);
}

#[test]
fn restoring_a_desktop_switch_after_a_token_refresh_points_to_switch_and_force_keeps_it() {
    let w = World::both_on_b();
    let s = w.ok(&["switch", "a@x.test", "--desktop", "--yes"]);
    let id = s["backup_id"].as_str().unwrap().to_string();
    // Desktop (on A) refreshed its token, then the user quit it.
    let mut cfg = w.desktop_config();
    cfg["oauth:tokenCacheV2"] = json!("TOKENV2-A-ROTATED");
    std::fs::write(
        w.desktop_dir().join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    w.desktop_running(false);
    let r = w.err(&["restore", &id], "restore_conflict");
    let hint = r.doc["error"]["hint"].as_str().unwrap();
    assert!(hint.contains("cma switch --desktop b@x.test"), "{hint}");
    let r = w.run(&["restore", &id, "--force", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert!(warning_codes(&r.doc).contains(&"desktop_recaptured".to_string()));
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);
    w.ok(&["switch", "a@x.test", "--desktop", "--yes"]);
    assert_eq!(
        w.desktop_config()["oauth:tokenCacheV2"],
        "TOKENV2-A-ROTATED"
    );
}

fn backup_with_op(w: &World, op: &str) -> String {
    w.ok(&["backups"])["backups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["op"] == op)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn resolve_journal_never_rolls_back_desktop_while_it_runs() {
    let w = World::both_on_b();
    let s = w.ok(&["switch", "a@x.test", "--desktop", "--yes"]);
    let id = s["backup_id"].as_str().unwrap().to_string();
    // An interrupted Desktop op of that backup; Desktop runs (it was relaunched).
    let j = json!({"op": "desktop-switch", "target": "desktop", "from": DB, "to": DA, "backup_id": id, "steps_done": []});
    std::fs::write(
        w.cma_home.join("op.journal"),
        serde_json::to_vec(&j).unwrap(),
    )
    .unwrap();
    let r = w.err(&["resolve-journal", "--yes"], "desktop_running");
    assert_eq!(r.code, 1);
    assert!(w.cma_home.join("op.journal").exists());
    assert_eq!(
        w.desktop_config()["lastKnownAccountUuid"],
        DA,
        "nothing touched"
    );
    // Quit: recovery rolls it back.
    w.desktop_running(false);
    let d = w.ok(&["resolve-journal", "--yes"]);
    assert_eq!(d["recovered"], true);
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);
}

#[test]
fn a_forced_restore_of_a_link_backup_never_mixes_two_logins() {
    let w = World::desktop_accounts();
    // Desktop is signed in as an account cma does not store.
    let mut cfg = w.desktop_config();
    cfg["lastKnownAccountUuid"] = json!("0b0c0d0e-0000-4000-8000-00000000000c");
    std::fs::write(
        w.desktop_dir().join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    w.desktop_signin_b();
    // quit? y; move the unstored login away? y; signed in? y.
    let (code, out, err) = w.human_answering(&["desktop", "link", "b@x.test"], "y,y,y");
    assert_eq!(code, 0, "{out}\n{err}");
    let id = backup_with_op(&w, "desktop-link");
    w.desktop_running(false);
    // The parked login's files were tampered with: refused, nothing changed.
    let stashed = w.cma_home.join(format!("backups/{id}/stash/Cookies"));
    let keep = std::fs::read(&stashed).unwrap();
    std::fs::remove_file(&stashed).unwrap();
    let r = w.err(
        &["restore", &id, "--force", "--yes"],
        "desktop_restore_refused",
    );
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("cma switch --desktop")
    );
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);
    // Intact: B's login is moved under B first, then the old one comes back whole.
    std::fs::write(&stashed, keep).unwrap();
    let r = w.run(&["restore", &id, "--force", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    let cfg = w.desktop_config();
    assert_eq!(
        cfg["lastKnownAccountUuid"],
        "0b0c0d0e-0000-4000-8000-00000000000c"
    );
    assert_eq!(cfg["oauth:tokenCacheV2"], "TOKENV2-A");
    assert_eq!(
        std::fs::read(w.desktop_dir().join("Cookies")).unwrap(),
        b"COOKIES-A"
    );
    assert_eq!(
        std::fs::read(w.cma_home.join(format!("desktop/{DB}/files/Cookies"))).unwrap(),
        b"COOKIES-B"
    );
}

#[test]
fn an_interrupted_both_puts_claude_code_back_on_the_next_command() {
    let w = World::both_on_b();
    let out = w
        .cmd()
        .args(["switch", "a@x.test", "--both", "--yes", "--json"])
        .env("CMA_TEST_DESKTOP_HALF", "crash")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(9));
    assert_eq!(w.live_oauth(), oauth("A"), "Claude Code half done");
    assert!(w.cma_home.join("both.journal").exists());
    let r = w.run(&["status"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert!(
        warning_codes(&r.doc).contains(&"recovered".to_string()),
        "{}",
        r.doc
    );
    assert_eq!(w.live_oauth(), oauth("B"), "Claude Code put back too");
    assert_eq!(w.registry()["active"]["cli"], format!("{DB}::{DOB}"));
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DB);
    assert!(!w.cma_home.join("both.journal").exists());
}

#[test]
fn an_interrupted_both_that_cannot_be_put_back_stays_visible_until_resolved() {
    let w = World::both_on_b();
    let out = w
        .cmd()
        .args(["switch", "a@x.test", "--both", "--yes", "--json"])
        .env("CMA_TEST_DESKTOP_HALF", "crash")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(9));
    // Claude Code refreshed A's token meanwhile.
    let mut fresh = oauth("A");
    fresh["accessToken"] = json!("dummy-access-A-refreshed");
    w.set_live(&fresh);
    let r = w.err(&["list"], "state_uncertain");
    assert_eq!(r.code, 2);
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("switch --both")
    );
    let st = w.run(&["status"]);
    assert!(
        st.doc["data"]["pending_both"]["cli_backup_id"].is_string(),
        "{}",
        st.doc
    );
    assert_eq!(st.doc["state_uncertain"], true);
    let d = w.ok(&["resolve-journal", "--yes"]);
    assert_eq!(d["resolved"], true);
    assert!(!w.cma_home.join("both.journal").exists());
    w.ok(&["list"]);
}

#[test]
fn a_both_killed_while_desktop_starts_is_not_undone() {
    let w = World::both_on_b();
    let out = w
        .cmd()
        .args(["switch", "a@x.test", "--both", "--yes", "--json"])
        .env("CMA_TEST_DESKTOP_HALF", "crash_in_launch")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(9));
    // Both halves had finished: the next command keeps them.
    let r = w.run(&["status"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    assert!(
        !warning_codes(&r.doc).contains(&"recovered".to_string()),
        "{}",
        r.doc
    );
    assert_eq!(w.live_oauth(), oauth("A"));
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], DA);
    assert!(!w.cma_home.join("both.journal").exists());
}

#[test]
fn a_forced_restore_asks_before_moving_an_unstored_live_login_away() {
    let w = World::desktop_accounts();
    let mut cfg = w.desktop_config();
    cfg["lastKnownAccountUuid"] = json!("0b0c0d0e-0000-4000-8000-00000000000c");
    std::fs::write(
        w.desktop_dir().join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    w.desktop_signin_b();
    let (code, out, err) = w.human_answering(&["desktop", "link", "b@x.test"], "y,y,y");
    assert_eq!(code, 0, "{out}\n{err}");
    let id = backup_with_op(&w, "desktop-link");
    // Desktop now on another unstored login.
    let mut cfg = w.desktop_config();
    cfg["lastKnownAccountUuid"] = json!("0d0d0d0d-0000-4000-8000-00000000000d");
    std::fs::write(
        w.desktop_dir().join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    w.desktop_running(false);
    let r = w.err(
        &["restore", &id, "--force", "--yes"],
        "confirmation_required",
    );
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--replace-live")
    );
    assert_eq!(
        w.desktop_config()["lastKnownAccountUuid"],
        "0d0d0d0d-0000-4000-8000-00000000000d"
    );
    let r = w.run(&["restore", &id, "--force", "--yes", "--replace-live"]);
    assert_eq!(r.code, 0, "{}", r.doc);
    let parked = r.doc["data"]["parked_backup_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(parked.ends_with("desktop-park"));
    let msg = r.doc["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["code"] == "desktop_parked")
        .unwrap()["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(msg.contains(&parked), "{msg}");
    assert_eq!(
        w.desktop_config()["lastKnownAccountUuid"],
        "0b0c0d0e-0000-4000-8000-00000000000c"
    );
}

/// A `desktop-link` backup of an unstored login, then Desktop on another
/// unstored login (D) and quit.
fn link_backup_with_d_live() -> (World, String) {
    let w = World::desktop_accounts();
    let mut cfg = w.desktop_config();
    cfg["lastKnownAccountUuid"] = json!("0b0c0d0e-0000-4000-8000-00000000000c");
    std::fs::write(
        w.desktop_dir().join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    w.desktop_signin_b();
    let (code, out, err) = w.human_answering(&["desktop", "link", "b@x.test"], "y,y,y");
    assert_eq!(code, 0, "{out}\n{err}");
    let id = backup_with_op(&w, "desktop-link");
    let mut cfg = w.desktop_config();
    cfg["lastKnownAccountUuid"] = json!(D_UUID);
    std::fs::write(
        w.desktop_dir().join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    w.desktop_running(false);
    (w, id)
}

const D_UUID: &str = "0d0d0d0d-0000-4000-8000-00000000000d";

#[test]
fn a_restore_failing_after_the_park_puts_the_live_login_back() {
    let (w, id) = link_backup_with_d_live();
    let r = w.run_env(
        &["restore", &id, "--force", "--yes", "--replace-live"],
        &[("CMA_TEST_DESKTOP_HALF", "fail_after_park")],
    );
    assert_eq!(r.code, 1, "{}", r.doc);
    assert_eq!(r.doc["error"]["data"]["park_undone"], true, "{}", r.doc);
    assert!(r.doc["error"]["data"]["parked_backup_id"].is_string());
    assert!(
        r.doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("was put back")
    );
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], D_UUID);
    assert!(!w.cma_home.join("op.journal").exists());
}

#[test]
fn a_restore_failing_after_the_park_while_desktop_starts_waits_and_names_the_park() {
    let (w, id) = link_backup_with_d_live();
    let r = w.run_env(
        &["restore", &id, "--force", "--yes", "--replace-live"],
        &[("CMA_TEST_DESKTOP_HALF", "fail_after_park_running")],
    );
    assert_eq!(r.code, 1, "{}", r.doc);
    assert_eq!(r.doc["error"]["code"], "desktop_running");
    let park = r.doc["error"]["data"]["parked_backup_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(r.doc["error"]["data"]["park_undone"], false);
    assert!(r.doc["error"]["message"].as_str().unwrap().contains(&park));
    assert!(
        r.doc["error"]["hint"]
            .as_str()
            .unwrap()
            .contains(&format!("cma restore {park}"))
    );
    assert!(
        w.cma_home.join("op.journal").exists(),
        "journal kept while Desktop runs"
    );
    assert!(
        w.desktop_config().get("lastKnownAccountUuid").is_none(),
        "nothing written meanwhile"
    );
    // Quit Desktop: the next command puts the live login back.
    w.desktop_running(false);
    let st = w.run(&["status"]);
    assert_eq!(st.code, 0, "{}", st.doc);
    assert_eq!(w.desktop_config()["lastKnownAccountUuid"], D_UUID);
    assert!(!w.cma_home.join("op.journal").exists());
}
