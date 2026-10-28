//! Error type shared by every core module.
//!
//! No variant may carry secret material: no `Secret`, no raw bytes, no command
//! arguments, stdout or stderr. External tool failures are reduced to the
//! program name, subcommand, exit code and a fixed classification.

use std::fmt;
use std::path::PathBuf;

/// Fixed classification of an external tool failure. Derived from the exit
/// code and from matching stderr against known phrases; the stderr text itself
/// is never kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolFailure {
    /// The item does not exist (exit 44 for `security`).
    NotFound,
    /// The user dismissed a Keychain prompt.
    UserCanceled,
    /// The Keychain refused because no UI interaction is possible.
    InteractionNotAllowed,
    /// Authorization or keychain access failure.
    AuthFailed,
    /// The tool was killed by a signal.
    Signaled,
    /// The tool could not be started.
    SpawnFailed,
    /// Anything else.
    Other,
}

impl fmt::Display for ToolFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ToolFailure::NotFound => "not found",
            ToolFailure::UserCanceled => "user canceled",
            ToolFailure::InteractionNotAllowed => "interaction not allowed",
            ToolFailure::AuthFailed => "authorization failed",
            ToolFailure::Signaled => "killed by signal",
            ToolFailure::SpawnFailed => "could not start",
            ToolFailure::Other => "failed",
        };
        f.write_str(s)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("registry schema_version {found} is newer than supported {supported}; upgrade cma")]
    RegistryTooNew { found: u64, supported: u64 },

    #[error("{what} is locked by another process")]
    Locked { what: String },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("{query:?} is ambiguous; candidates: {}", candidates.join(", "))]
    Ambiguous {
        query: String,
        candidates: Vec<String>,
    },

    #[error("Keychain write to {service:?}/{account:?} could not be verified by read-back")]
    WriteNotVerified { service: String, account: String },

    #[error("unsafe cma home {path}: {reason}")]
    UnsafeHome { path: PathBuf, reason: String },

    #[error("backup manifest rejected: {0}")]
    ManifestRejected(String),

    #[error("{program} {sub} {class} (exit {})", code.map_or_else(|| "none".to_string(), |c| c.to_string()))]
    ExternalTool {
        program: &'static str,
        sub: &'static str,
        code: Option<i32>,
        class: ToolFailure,
    },

    /// Rollback could not return every item to its pre-image because another
    /// writer changed it after cma's write. The backup and journal are kept.
    #[error("state uncertain: {0}")]
    StateUncertain(String),

    /// User restore refused because these entries changed after the op.
    #[error("restore refused: changed since the operation, so restoring would overwrite newer values: {} (--force overwrites them)", .0.join(", "))]
    RestoreConflict(Vec<String>),

    #[error("invalid {what}: {value:?}")]
    Invalid { what: &'static str, value: String },

    #[error("refusing to follow symlink at {0}")]
    Symlink(PathBuf),

    /// JSON parse failure. Only the position is kept: serde_json messages can
    /// quote input fragments, which may be secret.
    #[error("invalid JSON in {what} at line {line} column {column}")]
    Json {
        what: &'static str,
        line: usize,
        column: usize,
    },

    #[error("I/O error on {path}: {kind}")]
    Io {
        path: PathBuf,
        kind: std::io::ErrorKind,
    },

    /// A journal (or restore) names a backup whose directory or manifest is
    /// gone. Recovery cannot roll back; resolve the journal to continue.
    #[error("backup {id} is missing; resolve the unfinished operation journal to continue")]
    BackupMissing { id: String },

    /// Another writer changed an item between cma's read and its write; cma
    /// wrote nothing to it. Safe to retry with a new op (a new `Backup`):
    /// retrying inside the same `Backup` fails again by design, because its
    /// second-write check compares against the pre-image it already holds.
    #[error("changed by another writer during the operation, nothing written: {0}")]
    ConcurrentWrite(String),

    /// The live `Claude Code-credentials` item changed while an isolated
    /// login ran. cma wrote nothing to it and does not restore it; the
    /// pre-login backup is kept.
    #[error(
        "the live Claude Code credential changed during login (most likely a Claude Code token refresh); nothing was stored and the live item was not touched; pre-login backup {backup_id} kept"
    )]
    LiveItemChangedDuringLogin { backup_id: String },

    /// No trustworthy identity for a credential (sources disagree, none
    /// resolved, or the credential is blanked). Callers fail closed.
    #[error("credential identity unresolved: {0}")]
    Unidentified(String),

    /// A non-interactive caller must confirm explicitly (`--force`/`--yes`).
    #[error("confirmation required: {0}")]
    ConfirmationRequired(String),

    /// Interrupted by the user (Ctrl-C); temporary state was cleaned up.
    #[error("interrupted")]
    Interrupted,

    /// A flow the available evidence does not support; nothing was stored.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The login landed in a different organization than requested.
    #[error(
        "login landed in organization {got}, not the requested {wanted}; log in again and choose the other organization in the browser"
    )]
    OrgMismatch { wanted: String, got: String },

    /// The credential is signed out (blanked or flagged); log in again.
    #[error("needs login: {0}")]
    NeedsLogin(String),

    /// An interrupted token refresh left a rotated pair that could not be
    /// verified yet (no network, or the identity lookup failed). It is kept
    /// aside; the stored credential's refresh token is spent until then.
    #[error("token refresh pending: {0}")]
    RefreshPending(String),

    /// Called while this thread holds the cma lock, by something that takes
    /// it itself (it would wait for its own lock and time out).
    #[error("the cma lock is held by this thread: {0}")]
    CmaLockHeld(String),

    /// Claude Desktop runs where it must not (cma only touches its files
    /// while it is quit), or did not exit when asked to.
    #[error("Claude Desktop is running: {0}")]
    DesktopRunning(String),

    /// The account has no Claude Desktop login stored by cma.
    #[error("not linked to Claude Desktop: {0}")]
    DesktopNotLinked(String),

    /// A forced restore of a Desktop switch cannot keep the stored login of
    /// the account Desktop runs now consistent; switching is the safe undo.
    #[error("restore refused: {0}")]
    DesktopRestoreRefused(String),
}

impl Error {
    /// Stable machine-readable code (the JSON `error.code`).
    pub fn code(&self) -> &'static str {
        match self {
            Error::RegistryTooNew { .. } => "registry_too_new",
            Error::Locked { .. } => "locked",
            Error::NotFound(_) => "not_found",
            Error::Ambiguous { .. } => "ambiguous",
            Error::WriteNotVerified { .. } => "write_not_verified",
            Error::UnsafeHome { .. } => "unsafe_home",
            Error::ManifestRejected(_) => "manifest_rejected",
            Error::ExternalTool { .. } => "external_tool",
            Error::StateUncertain(_) => "state_uncertain",
            Error::RestoreConflict(_) => "restore_conflict",
            Error::Invalid { .. } => "invalid",
            Error::Symlink(_) => "symlink",
            Error::Json { .. } => "invalid_json",
            Error::Io { .. } => "io",
            Error::BackupMissing { .. } => "backup_missing",
            Error::ConcurrentWrite(_) => "concurrent_write",
            Error::LiveItemChangedDuringLogin { .. } => "live_item_changed_during_login",
            Error::Unidentified(_) => "unidentified",
            Error::ConfirmationRequired(_) => "confirmation_required",
            Error::Interrupted => "interrupted",
            Error::Unsupported(_) => "unsupported",
            Error::OrgMismatch { .. } => "org_mismatch",
            Error::NeedsLogin(_) => "needs_login",
            Error::CmaLockHeld(_) => "cma_lock_held",
            Error::RefreshPending(_) => "refresh_pending",
            Error::DesktopRunning(_) => "desktop_running",
            Error::DesktopNotLinked(_) => "desktop_not_linked",
            Error::DesktopRestoreRefused(_) => "desktop_restore_refused",
        }
    }

    pub(crate) fn io(path: impl Into<PathBuf>, e: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            kind: e.kind(),
        }
    }

    pub(crate) fn json(what: &'static str, e: &serde_json::Error) -> Self {
        Error::Json {
            what,
            line: e.line(),
            column: e.column(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
