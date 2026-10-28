//! Core logic for claude-multi-auth.
//!
//! Profiles, secret store, locking, journal, switch and usage live here and
//! are shared by the `cma` CLI and the menubar app.

pub mod account;
pub mod backup;
pub mod cli_target;
pub mod desktop_app;
pub mod desktop_target;
pub mod error;
pub mod fsutil;
pub mod http;
pub mod identity;
pub mod journal;
pub mod lock;
pub mod login;
pub mod paths;
pub mod procs;
pub mod profile_curl;
pub mod refresh;
pub mod registry;
pub mod secret;
pub mod selector;
pub mod sessions;
pub mod switch;
pub mod sync;
pub mod transfer;
pub mod usage;

pub use error::{Error, Result};

/// Crate version, shared by the CLI and the app.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
