//! Developer harness for the CLI target, predating the `cma` command line.
//! Not shipped. Prints keys, emails, counts and
//! hash prefixes only: never a token or a credential.
//!
//! It acts on the REAL Keychain and `~/.claude.json` of the current user
//! (unless `CMA_HOME` + `CMA_ALLOW_HOME_OVERRIDE=1` move cma's own state).
//!
//! ```text
//! cargo run -p cma-core --example cli_target_dev -- status
//! cargo run -p cma-core --example cli_target_dev -- import-current [--alias A]
//! cargo run -p cma-core --example cli_target_dev -- login [--email E] [--sso] [--console] [--org O] [--alias A]
//! cargo run -p cma-core --example cli_target_dev -- switch <query> [--force] [--replace-live] [--json]
//! cargo run -p cma-core --example cli_target_dev -- remove <query> [--force]
//! cargo run -p cma-core --example cli_target_dev -- export <dir> <query>... --yes
//! cargo run -p cma-core --example cli_target_dev -- import <path> [--alias A] [--replace | --json]
//! ```

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use cma_core::cli_target::{Ctx, LiveTarget, Warning, oauth_fingerprint, oauth_of, system_now_ms};
use cma_core::identity::{ProfileClient, Resolved, resolve};
use cma_core::lock::ClaudeStorageLock;
use cma_core::login::{ClaudeLoginSpawner, DumpKeychainLister, LoginOpts, login};
use cma_core::paths::{Paths, SystemEnv};
use cma_core::procs::{PsLister, running_cli_sessions};
use cma_core::profile_curl::CurlProfileClient;
use cma_core::registry::Registry;
use cma_core::secret::SecurityCliStore;
use cma_core::switch::{Confirm, SwitchOpts, switch_cli};
use cma_core::{Error, Result, account, selector, sync, transfer};

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn positional(args: &[String]) -> Vec<String> {
    let takes_value = ["--alias", "--email", "--org"];
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
        } else if takes_value.contains(&a.as_str()) {
            skip = true;
        } else if !a.starts_with("--") {
            out.push(a.clone());
        }
    }
    out
}

fn print_warnings(w: &[Warning]) {
    for x in w {
        eprintln!("warning [{}]: {}", x.code, x.message);
    }
}

fn ask(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim(), "y" | "Y" | "yes")
}

fn key_for(reg: &Registry, query: &str) -> Result<String> {
    Ok(selector::select(&reg.accounts, query)?.key.clone())
}

fn status(ctx: &Ctx<'_>, profile: &dyn ProfileClient) -> Result<()> {
    let live = LiveTarget::from_env(ctx.env)?;
    println!(
        "live item: service={:?} account={:?}",
        live.service, live.account
    );
    let reg = Registry::load(&ctx.paths.registry_file())?;
    match ctx.store.get(&live.service, &live.account)? {
        None => println!("live item: absent"),
        Some(b) => {
            println!("live item: {} bytes", b.len());
            match oauth_of(b.expose())? {
                None => println!("live claudeAiOauth: absent"),
                Some(o) => {
                    println!(
                        "live claudeAiOauth fingerprint: {}",
                        &oauth_fingerprint(&o)[..12]
                    );
                    match resolve(&reg, profile, &o, ctx.now_ms(), None) {
                        Resolved::Identified {
                            key,
                            source,
                            profile,
                        } => println!(
                            "live identity: {key} via {source:?}{}",
                            profile
                                .map(|p| format!(" ({})", p.email))
                                .unwrap_or_default()
                        ),
                        other => println!("live identity: {other:?}"),
                    }
                }
            }
        }
    }
    println!("active.cli: {}", reg.active.cli.as_deref().unwrap_or("-"));
    for (i, a) in reg.accounts.iter().enumerate() {
        println!(
            "{:>2}. {} {} [{}] alias={} kind={:?}{}",
            i + 1,
            a.key,
            a.email,
            a.org_name,
            a.alias.as_deref().unwrap_or("-"),
            a.kind,
            if a.needs_login { " NEEDS LOGIN" } else { "" }
        );
    }
    println!(
        "running CLI sessions: {}",
        running_cli_sessions(&PsLister)?.len()
    );
    print_warnings(&ctx.env_warnings());
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    let env = SystemEnv;
    let paths = Paths::from_env(&env)?;
    let store = SecurityCliStore::new();
    let locker = ClaudeStorageLock::for_paths(&paths);
    let profile = CurlProfileClient::new(&env);
    let ctx = Ctx {
        paths: &paths,
        env: &env,
        store: &store,
        locker: &locker,
        profile: &profile,
        procs: &cma_core::procs::PsLister,
        now_ms: system_now_ms,
    };
    let cmd = args.first().map(String::as_str).unwrap_or("status");
    let rest = &args[args.len().min(1)..];
    let pos = positional(rest);
    match cmd {
        "status" => status(&ctx, &profile),
        "login" => {
            let r = login(
                &ctx,
                &ClaudeLoginSpawner,
                &DumpKeychainLister,
                &LoginOpts {
                    email: opt(rest, "--email"),
                    sso: flag(rest, "--sso"),
                    console: flag(rest, "--console"),
                    org: opt(rest, "--org"),
                    alias: opt(rest, "--alias"),
                },
            )?;
            print_warnings(&r.warnings);
            println!(
                "logged in: {} {} [{}] kind={:?} replaced={}",
                r.key, r.email, r.org_name, r.kind, r.replaced
            );
            Ok(())
        }
        "import-current" => {
            let mut s = sync::begin(&ctx)?;
            print_warnings(&s.warnings);
            let r = account::import_current(&mut s, opt(rest, "--alias").as_deref())?;
            println!("imported live login as {} (replaced={})", r.key, r.replaced);
            Ok(())
        }
        "switch" => {
            let q = pos.first().ok_or_else(|| Error::NotFound("query".into()))?;
            let mut s = sync::begin(&ctx)?;
            print_warnings(&s.warnings);
            let key = key_for(&s.registry, q)?;
            let ask_fn = |m: &str| ask(&format!("{m}\nSwitch anyway?"));
            let confirm = if flag(rest, "--json") || flag(rest, "--force") {
                Confirm::NonInteractive {
                    force: flag(rest, "--force"),
                }
            } else {
                Confirm::Interactive(&ask_fn)
            };
            let replace_live = if flag(rest, "--json") || flag(rest, "--replace-live") {
                Confirm::NonInteractive {
                    force: flag(rest, "--replace-live"),
                }
            } else {
                Confirm::Interactive(&ask_fn)
            };
            let r = switch_cli(
                &mut s,
                &key,
                &SwitchOpts {
                    confirm,
                    replace_live,
                    procs: &PsLister,
                },
            )?;
            print_warnings(&r.warnings);
            if r.already_active {
                println!("{key} is already the live CLI login");
            } else {
                println!(
                    "switched CLI: {} -> {} (backup {})",
                    r.from.as_deref().unwrap_or("-"),
                    r.to,
                    r.backup_id.as_deref().unwrap_or("-")
                );
            }
            Ok(())
        }
        "remove" => {
            let q = pos.first().ok_or_else(|| Error::NotFound("query".into()))?;
            let mut s = sync::begin(&ctx)?;
            print_warnings(&s.warnings);
            let key = key_for(&s.registry, q)?;
            print_warnings(&account::remove(&mut s, &key, flag(rest, "--force"))?);
            println!("removed {key}");
            Ok(())
        }
        "export" => {
            let (dir, queries) = pos
                .split_first()
                .ok_or_else(|| Error::NotFound("export dir".into()))?;
            let s = sync::begin(&ctx)?;
            print_warnings(&s.warnings);
            let keys = queries
                .iter()
                .map(|q| key_for(&s.registry, q))
                .collect::<Result<Vec<_>>>()?;
            let ok =
                flag(rest, "--yes") || ask(&format!("{}. Write them?", transfer::EXPORT_WARNING));
            for f in transfer::export(&s, Path::new(dir), &keys, ok)? {
                println!("wrote {}", f.display());
            }
            Ok(())
        }
        "import" => {
            let p = pos.first().ok_or_else(|| Error::NotFound("path".into()))?;
            let mut s = sync::begin(&ctx)?;
            print_warnings(&s.warnings);
            let alias = opt(rest, "--alias");
            let ask_fn = |m: &str| ask(&format!("{m}\nReplace?"));
            let replace = if flag(rest, "--json") || flag(rest, "--replace") {
                Confirm::NonInteractive {
                    force: flag(rest, "--replace"),
                }
            } else {
                Confirm::Interactive(&ask_fn)
            };
            let r = transfer::import(
                &mut s,
                Path::new(p),
                &transfer::ImportOpts {
                    alias: alias.as_deref(),
                    replace,
                },
            )?;
            print_warnings(&r.warnings);
            for r in r.stored {
                println!("imported {} (replaced={})", r.key, r.replaced);
            }
            Ok(())
        }
        other => Err(Error::NotFound(format!("command {other:?}"))),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error [{}]: {e}", e.code());
            if e.code() == "state_uncertain" {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}
