//! Session follow: move an account's local Claude Desktop sessions into
//! the account Desktop switches to.
//!
//! Where Desktop keeps sessions comes from the shipped layout data
//! (`data/desktop_layout.json`, measured on Desktop 4.29.0): roots whose
//! children are named `<acct>/<org>`, `<org>/<acct>` (reversed) or
//! `<acct8>/<org8>` (8-character uuid prefixes). For every movable pattern,
//! the entries of **every** org directory of the old account move into the
//! new account's directory for its org. Names listed in a pattern's `keep`
//! (per-directory queues and indexes) stay where they are; non-movable
//! patterns are reported only. A name that already exists at the
//! destination is kept: the moved entry gets a `.cma-<ts>` suffix.
//!
//! The moves are recorded in the op's backup (with a signature of each
//! moved entry), so rollback moves them back and a user `restore` moves back
//! only what is still at its destination unchanged.
//!
//! Transcripts in `~/.claude/projects/` are not touched.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use crate::error::{Error, Result};

/// Shown whenever sessions moved.
pub const MOVED_SESSIONS_CAVEAT: &str = "moved sessions keep the old organization's server-side references (bridge session ids, remote MCP configs, environment ids): they resume from their local transcripts, but remote-control links may not work";

const LAYOUT_JSON: &str = include_str!("../data/desktop_layout.json");
const LAYOUT_SCHEMA: u32 = 1;

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        .expect("valid regex")
});
static UUID8_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{8}$").expect("valid regex"));

/// Whether `s` is a lowercase uuid (the form Desktop uses in paths).
pub fn is_uuid(s: &str) -> bool {
    UUID_RE.is_match(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Order {
    #[serde(rename = "<acct>/<org>")]
    AcctOrg,
    #[serde(rename = "<org>/<acct>")]
    OrgAcct,
    #[serde(rename = "<acct8>/<org8>")]
    Acct8Org8,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Pattern {
    /// Relative to the Desktop dir.
    pub root: String,
    pub order: Order,
    pub movable: bool,
    /// Entry names left in place inside a movable directory.
    #[serde(default)]
    pub keep: Vec<String>,
    /// Why a pattern is not movable.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Layout {
    pub schema_version: u32,
    pub patterns: Vec<Pattern>,
}

fn safe_rel(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && rel
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

impl Layout {
    pub fn parse(text: &str) -> Result<Layout> {
        let l: Layout =
            serde_json::from_str(text).map_err(|e| Error::json("desktop layout data", &e))?;
        if l.schema_version != LAYOUT_SCHEMA {
            return Err(Error::Invalid {
                what: "desktop layout data schema_version",
                value: l.schema_version.to_string(),
            });
        }
        for p in &l.patterns {
            if !safe_rel(&p.root) || p.keep.iter().any(|k| k.contains('/') || !safe_rel(k)) {
                return Err(Error::Invalid {
                    what: "desktop layout data path",
                    value: p.root.clone(),
                });
            }
        }
        Ok(l)
    }

    /// Every root, absolute (the backup allowlist).
    pub fn roots(&self, desktop_dir: &Path) -> Vec<PathBuf> {
        self.patterns
            .iter()
            .map(|p| desktop_dir.join(&p.root))
            .collect()
    }
}

/// The shipped layout.
pub fn layout() -> &'static Layout {
    static L: LazyLock<Layout> =
        LazyLock::new(|| Layout::parse(LAYOUT_JSON).expect("shipped desktop layout data is valid"));
    &L
}

/// Planned session moves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// (from, to), absolute.
    pub moves: Vec<(PathBuf, PathBuf)>,
    /// Destinations that got a `.cma-<ts>` suffix because the name existed.
    pub renamed: Vec<PathBuf>,
    /// What stays in place, as messages (non-movable patterns, kept names).
    pub left: Vec<String>,
}

fn children(dir: &Path) -> Result<Vec<String>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    let mut v = Vec::new();
    for e in rd {
        let e = e.map_err(|e| Error::io(dir, e))?;
        if let Ok(n) = e.file_name().into_string() {
            v.push(n);
        }
    }
    v.sort();
    Ok(v)
}

fn is_real_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

fn short(u: &str) -> &str {
    &u[..8.min(u.len())]
}

/// Source directories of `old` for one pattern, and the destination.
fn dirs_for(
    root: &Path,
    order: Order,
    old: &str,
    new: &str,
    new_org: &str,
) -> Result<(Vec<PathBuf>, PathBuf)> {
    Ok(match order {
        Order::AcctOrg => {
            let base = root.join(old);
            let src = children(&base)?
                .into_iter()
                .filter(|o| is_uuid(o))
                .map(|o| base.join(o))
                .filter(|p| is_real_dir(p))
                .collect();
            (src, root.join(new).join(new_org))
        }
        Order::OrgAcct => {
            let src = children(root)?
                .into_iter()
                .filter(|o| is_uuid(o))
                .map(|o| root.join(o).join(old))
                .filter(|p| is_real_dir(p))
                .collect();
            (src, root.join(new_org).join(new))
        }
        Order::Acct8Org8 => {
            let base = root.join(short(old));
            let src = children(&base)?
                .into_iter()
                .filter(|o| UUID8_RE.is_match(o))
                .map(|o| base.join(o))
                .filter(|p| is_real_dir(p))
                .collect();
            (src, root.join(short(new)).join(short(new_org)))
        }
    })
}

/// Plan moving `old`'s sessions (every org) into `new`'s directory for
/// `new_org`. `ts` is the collision suffix timestamp. Nothing is written.
pub fn plan(
    layout: &Layout,
    desktop_dir: &Path,
    old: &str,
    new: &str,
    new_org: &str,
    ts: &str,
) -> Result<Plan> {
    for (what, u) in [
        ("account", old),
        ("account", new),
        ("organization", new_org),
    ] {
        if !is_uuid(u) {
            return Err(Error::Invalid {
                what: "session follow uuid",
                value: format!("{what} {u}"),
            });
        }
    }
    let mut plan = Plan::default();
    let mut taken: HashSet<PathBuf> = HashSet::new();
    for p in &layout.patterns {
        let root = desktop_dir.join(&p.root);
        let (srcs, dest) = dirs_for(&root, p.order, old, new, new_org)?;
        for src in srcs {
            if src == dest {
                continue;
            }
            let names = children(&src)?;
            if names.is_empty() {
                continue;
            }
            let rel = src
                .strip_prefix(desktop_dir)
                .unwrap_or(&src)
                .display()
                .to_string();
            if !p.movable {
                plan.left.push(format!(
                    "{rel}: {} entr{} left in place ({})",
                    names.len(),
                    if names.len() == 1 { "y" } else { "ies" },
                    p.reason.as_deref().unwrap_or("not movable")
                ));
                continue;
            }
            let mut kept = Vec::new();
            for name in names {
                if p.keep.contains(&name) {
                    kept.push(name);
                    continue;
                }
                let mut to = dest.join(&name);
                if std::fs::symlink_metadata(&to).is_ok() || taken.contains(&to) {
                    let mut n = 0;
                    loop {
                        let cand = if n == 0 {
                            dest.join(format!("{name}.cma-{ts}"))
                        } else {
                            dest.join(format!("{name}.cma-{ts}-{n}"))
                        };
                        if std::fs::symlink_metadata(&cand).is_err() && !taken.contains(&cand) {
                            to = cand;
                            break;
                        }
                        n += 1;
                    }
                    plan.renamed.push(to.clone());
                }
                taken.insert(to.clone());
                plan.moves.push((src.join(&name), to));
            }
            if !kept.is_empty() {
                plan.left
                    .push(format!("{rel}: kept in place: {}", kept.join(", ")));
            }
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const A: &str = "3a000000-0000-4000-8000-00000000000a";
    pub const B: &str = "7b000000-0000-4000-8000-00000000000b";
    pub const O1: &str = "60000000-0000-4000-8000-0000000000c1";
    pub const O2: &str = "84000000-0000-4000-8000-0000000000c2";

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    /// Every pattern movable, to exercise each order.
    fn all_movable() -> Layout {
        let mut l = layout().clone();
        for p in &mut l.patterns {
            p.movable = true;
        }
        l
    }

    #[test]
    fn shipped_layout_parses_and_matches_the_census() {
        let l = layout();
        let roots: Vec<(&str, Order, bool)> = l
            .patterns
            .iter()
            .map(|p| (p.root.as_str(), p.order, p.movable))
            .collect();
        assert_eq!(
            roots,
            vec![
                ("claude-code-sessions", Order::AcctOrg, true),
                ("local-agent-mode-sessions", Order::AcctOrg, true),
                ("scratch-workspaces", Order::AcctOrg, true),
                (
                    "local-agent-mode-sessions/skills-plugin",
                    Order::OrgAcct,
                    false
                ),
                ("spaces-present", Order::Acct8Org8, false),
            ]
        );
        assert!(l.patterns[1].keep.contains(&"rpm".to_string()));
        assert!(Layout::parse(r#"{"schema_version":1,"patterns":[{"root":"../x","order":"<acct>/<org>","movable":true}]}"#).is_err());
        assert!(Layout::parse(r#"{"schema_version":2,"patterns":[]}"#).is_err());
    }

    #[test]
    fn every_org_and_every_order_moves_with_kept_names_left() {
        let t = tempfile::tempdir().unwrap();
        let dd = t.path();
        touch(&dd.join(format!("claude-code-sessions/{A}/{O1}/local_1.json")));
        touch(&dd.join(format!("claude-code-sessions/{A}/{O2}/local_2.json")));
        touch(&dd.join(format!(
            "claude-code-sessions/{A}/{O2}/scheduled-tasks.json"
        )));
        touch(&dd.join(format!("local-agent-mode-sessions/{A}/{O2}/local_3/t.json")));
        touch(&dd.join(format!("local-agent-mode-sessions/{A}/{O2}/rpm/m.json")));
        touch(&dd.join(format!(
            "local-agent-mode-sessions/skills-plugin/{O2}/{A}/manifest.json"
        )));
        touch(&dd.join(format!("spaces-present/{}/{}/link-key", &A[..8], &O1[..8])));
        // B's own session is untouched and not a source.
        touch(&dd.join(format!("claude-code-sessions/{B}/{O1}/local_b.json")));

        let p = plan(&all_movable(), dd, A, B, O1, "20261028T000000Z").unwrap();
        let rel = |x: &Path| x.strip_prefix(dd).unwrap().display().to_string();
        let mut got: Vec<(String, String)> =
            p.moves.iter().map(|(f, t)| (rel(f), rel(t))).collect();
        got.sort();
        let mut want = vec![
            (
                format!("claude-code-sessions/{A}/{O1}/local_1.json"),
                format!("claude-code-sessions/{B}/{O1}/local_1.json"),
            ),
            (
                format!("claude-code-sessions/{A}/{O2}/local_2.json"),
                format!("claude-code-sessions/{B}/{O1}/local_2.json"),
            ),
            (
                format!("local-agent-mode-sessions/{A}/{O2}/local_3"),
                format!("local-agent-mode-sessions/{B}/{O1}/local_3"),
            ),
            // Reversed order: <org>/<acct>.
            (
                format!("local-agent-mode-sessions/skills-plugin/{O2}/{A}/manifest.json"),
                format!("local-agent-mode-sessions/skills-plugin/{O1}/{B}/manifest.json"),
            ),
            // 8-character prefixes.
            (
                format!("spaces-present/{}/{}/link-key", &A[..8], &O1[..8]),
                format!("spaces-present/{}/{}/link-key", &B[..8], &O1[..8]),
            ),
        ];
        want.sort();
        assert_eq!(got, want);
        assert!(p.renamed.is_empty());
        assert!(p.left.iter().any(|l| l.contains("scheduled-tasks.json")));
        assert!(p.left.iter().any(|l| l.contains("rpm")));
    }

    #[test]
    fn shipped_data_reports_non_movable_patterns() {
        let t = tempfile::tempdir().unwrap();
        let dd = t.path();
        touch(&dd.join(format!(
            "local-agent-mode-sessions/skills-plugin/{O2}/{A}/manifest.json"
        )));
        touch(&dd.join(format!("spaces-present/{}/{}/link-key", &A[..8], &O2[..8])));
        let p = plan(layout(), dd, A, B, O1, "ts").unwrap();
        assert!(p.moves.is_empty());
        assert_eq!(p.left.len(), 2, "{:?}", p.left);
    }

    #[test]
    fn a_collision_keeps_both_with_a_suffix() {
        let t = tempfile::tempdir().unwrap();
        let dd = t.path();
        touch(&dd.join(format!("claude-code-sessions/{A}/{O1}/local_1.json")));
        touch(&dd.join(format!("claude-code-sessions/{A}/{O2}/local_1.json")));
        touch(&dd.join(format!("claude-code-sessions/{B}/{O1}/local_1.json")));
        let p = plan(layout(), dd, A, B, O1, "TS").unwrap();
        let dests: Vec<String> = p
            .moves
            .iter()
            .map(|(_, t)| t.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(dests, vec!["local_1.json.cma-TS", "local_1.json.cma-TS-1"]);
        assert_eq!(p.renamed.len(), 2);
    }

    #[test]
    fn bad_uuids_are_refused() {
        let t = tempfile::tempdir().unwrap();
        assert!(plan(layout(), t.path(), "../x", B, O1, "ts").is_err());
        assert!(plan(layout(), t.path(), A, B, "", "ts").is_err());
    }
}
