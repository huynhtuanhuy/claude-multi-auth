# `cma --json` contract (schema_version 1)

Every `cma` command accepts `--json`. In JSON mode:

- stdout carries exactly **one** JSON document (below). Progress text, the
  output of `claude auth login`, and notices such as "waiting for a token
  refresh of …" go to stderr.
- `cma` never prompts. A step that needs consent fails with
  `error.code = "confirmation_required"` and a message naming the flag to
  pass (`--force`, `--replace-live`, `--replace` or `--yes`).
- A panic (a bug in cma) still ends in one document, with only the source
  location in `message`: `error.code = "internal"`, exit 1, or, when an
  operation journal exists at that point (a change may have begun),
  `error.code = "state_uncertain"`, exit 2. The next command rolls the
  interrupted operation back (warning `recovered`), or keeps its journal if
  it cannot.
- Within schema_version 1, changes are additive only: new fields, new
  warning codes, new error codes. Consumers must ignore unknown fields and
  treat unknown codes generically.
- No token, refresh token or credential ever appears in the document.

## Envelope

```json
{
  "schema_version": 1,
  "ok": true,
  "data": { },
  "warnings": [{ "code": "running_sessions", "message": "…" }],
  "error": null,
  "state_uncertain": false
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Always `1` for this contract. |
| `ok` | bool | The command succeeded (exit 0 or 3). |
| `data` | object \| null | Command-specific result (shapes below); `null` when `ok` is false. |
| `warnings` | array | `{code, message}` objects, possibly empty. Codes are listed below. |
| `error` | object \| null | `{code, message, hint, data}` when `ok` is false. `hint` is a string or `null`; `data` is `null` except where noted (a forced `restore` that failed after moving the live Claude Desktop login aside: `{"parked_backup_id", "park_undone": bool}`). |
| `state_uncertain` | bool | An interrupted operation could not be rolled back completely and its journal is kept. `true` with exit 2, and on `status` while such a journal exists. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Failed before any change, or failed and was rolled back completely (including argument errors: `error.code = "usage"`, and `internal`). |
| 2 | Failed after changes began and the automatic rollback did not complete: state uncertain, journal and backup kept (`error.code = "state_uncertain"`). Every command that changes state refuses until the journal is resolved; `cma status` and `cma backups` show what it touched. Any other command retries the rollback; `cma resolve-journal --yes` accepts the current state (journal archived, backup kept). |
| 3 | Partial success: some targets switched, others not (see `warnings`): `switch --both` to an account with no Claude Desktop login stored by cma (Claude Code switched, Desktop not: warning `desktop_not_linked`, `data.desktop.switched = false`); also `remove` when some accounts were removed and others failed (`remove_failed`). |

## Error codes

| Code | Meaning / what to do |
|---|---|
| `usage` | Invalid command line (unknown flag, missing argument). |
| `invalid` | An argument or file is invalid (bad setting value, numeric alias, export dir not 0700, credential file with a repeated JSON key, a query missing in `--json` mode, …). |
| `not_found` | No account matches the query, or a required item/file is missing (e.g. Claude Code was never run: `~/.claude` or `~/.claude.json` absent). |
| `ambiguous` | The query matches several accounts; the message lists them. |
| `confirmation_required` | Consent is needed. `--force`: switch while `claude` sessions run, or remove the active account. `--replace-live`: replace a live Claude Code login that cma does not store (it then survives only in the backup). `--replace`: import over a different stored login of the same account. `--yes`: export refresh tokens to files; with `restore --force`, overwrite items that changed since the operation; `resolve-journal`; quit a running Claude Desktop (`switch --desktop\|--both`, `desktop link`; cma starts it again afterwards); save a Desktop login no stored account matches as a Desktop-only account (`desktop import-current`). `--replace-live` also covers moving away a live Claude Desktop login cma does not store (`switch --desktop`, `desktop link`). The two switch consents are independent: `--force` never implies `--replace-live`. |
| `needs_login` | The account's login is signed out or its refresh token was refused. Hint: re-run `cma login` for that account. Distinct from `unidentified` and `refresh_pending`. |
| `unidentified` | cma could not determine which account a credential belongs to (profile lookup failed or disagreed); nothing was stored. Usually transient (network). |
| `refresh_pending` | An interrupted token refresh left a rotated login that is not verified yet; the stored refresh token is spent until it is. Hint: run `cma usage` (it finishes the refresh when the network is back), then retry. `switch` refuses rather than make a spent token live. |
| `cma_lock_held` | Internal ordering error: this process already holds the cma lock where an operation takes it itself. |
| `locked` | Another cma command or a token refresh holds a lock; retry. |
| `concurrent_write` | Another writer (usually Claude Code refreshing its token) changed an item during the operation; nothing was written. Retry. |
| `live_item_changed_during_login` | The live Claude Code login changed while `cma login` ran (most likely a token refresh); nothing stored, live item untouched, pre-login backup kept. Run `cma login` again. |
| `org_mismatch` | `cma login --org` landed in a different organization; nothing stored. |
| `state_uncertain` | Exit 2 (see above). |
| `backup_missing` | The unfinished operation's backup is gone. |
| `restore_conflict` | `restore` refused: the listed entries changed since the operation, usually because Claude Code refreshed the live login's token, so restoring would replace a newer token with an older one. The hint recommends `cma switch <account>` instead. `--force --yes` restores anyway; what it overwrites is kept in the restore's own backup (`data.backup_id`, warning `restore_undo`). |
| `restore_older_login` | `restore` (without `--force`) refused: it would put an older login of a stored account live while cma holds a newer one for it. The hint names `cma switch <account>`, which puts the newer one live. `--force` restores anyway after a prompt on a terminal; with `--json` or without a terminal it needs `--force --yes` (otherwise `confirmation_required`). |
| `internal` | A bug in cma (panic) with no operation journal on disk. Exit 1; see the note above the envelope (with a journal: `state_uncertain`, exit 2). |
| `manifest_rejected` | A backup manifest is invalid or names a path outside the allowlist. |
| `write_not_verified` | A Keychain write did not read back identically. |
| `external_tool` | `security`, `ps`, `claude` or an HTTP request failed (program, step and exit/HTTP status only). |
| `unsupported` | A flow cma does not support (e.g. switching to a Console account, `login --console` without a Claude.ai credential). |
| `desktop_not_linked` | The account has no Claude Desktop login stored by cma (`switch --desktop`, `switch --both --strict`, `desktop unlink`). Nothing changed. Hint: `cma desktop link <account>` once, or `cma desktop import-current` while Desktop is signed in as it. |
| `desktop_running` | Claude Desktop runs where cma needs it quit, or did not exit within 20 s of being asked (cma never force-quits it; the message lists `pid <n> <path>` of what still runs). Also: recovery of an interrupted Desktop operation, and `restore` of a backup that touches Desktop's files, wait until Desktop is quit; a Desktop relaunch during a Desktop operation (e.g. an auto-update) stops it **without rolling back** (cma never writes while Desktop runs): the journal is kept and the message says so; quit Desktop, then any command rolls the operation back. `Claude.app/Contents/Helpers/chrome-native-host` counts only when Desktop itself started it (its parent is a Desktop process). |
| `desktop_restore_refused` | A forced `restore` of a Claude Desktop op was refused because it would mix two logins or leave a stored login inconsistent: Desktop now names another account than the switch left, or added identity keys, paths or files after it, or part of the login the backup moved is gone (its files and its `config.json` keys are restored together or not at all). Nothing changed. Hint: `cma switch --desktop <account>` (it stores the current login first). Without `--force`, a Desktop switch whose login Desktop changed since is `restore_conflict`, with the same `switch --desktop` hint. |
| `desktop_unavailable` | Not produced by this version (kept for older clients). |
| `interrupted` | Ctrl-C, or the picker was cancelled. |
| `registry_too_new` | The registry was written by a newer cma. |
| `unsafe_home`, `symlink`, `io`, `invalid_json` | Filesystem problems with cma's own state. |

## Warning codes

Warnings never change `ok`. Known codes (others may appear):

`env_override` (`CLAUDE_CODE_OAUTH_TOKEN`/`ANTHROPIC_API_KEY` set: a CLI
switch has no effect in that shell), `plaintext_credentials`,
`time_machine`, `recovered` (an interrupted op was rolled back),
`live_account_changed`, `live_unidentified`, `live_unreadable`,
`needs_login`, `running_sessions`, `live_login_replaced`,
`oauth_account_reverted`, `storage_lock_slow` (Claude Code's
`.storage-write` lock was held > 5 s during a switch), `desktop_not_linked`,
`desktop_recaptured` (a forced `restore` of a Desktop switch first
stored the live Desktop login under its account; names that backup), `desktop_account_changed` (Desktop's login changed outside cma),
`desktop_relaunched` (a Desktop op failed and cma started Desktop again),
`desktop_launch_failed`, `desktop_not_started`, `desktop_verify_failed`
(after the switch Desktop names another account), `desktop_account_mismatch`
(`desktop link`: the user signed in as another account; that one was
linked), `desktop_org_unknown`, `desktop_config_unreadable`,
`sessions_moved` (session follow moved sessions; they keep the old org's
server-side references), `sessions_renamed` (a moved session's name existed:
both kept, the moved one with a `.cma-<ts>` suffix),
`session_follow_skipped`, `desktop_auto_linked` (a Desktop switch or link
found a stored but unlinked account signed in and linked it), `restore_skipped`,
`grant_replaced`, `grant_may_be_rotated`,
`live_login_updated`, `live_login_not_updated`, `login_cleanup`,
`login_swept`, `removed_active`, `backup`, `remove_failed`,
`export_skipped`, `restore`, `restore_undo` (a forced restore overwrote
newer values: names the backup that holds them and the `cma restore <id>`
that puts them back, to run before any other cma command),
`usage_disclaimer` (shown once, the first time
usage is fetched), `short_refresh_grace`, `process_list_failed`, and the
token-refresh family `refresh_interrupted`, `refresh_recovered`,
`refresh_restored`, `refresh_retried`, `refresh_superseded`,
`refresh_cleanup`, `refresh_cleanup_failed`, `refresh_copy_failed`,
`refresh_copy_unreadable`. Usage warnings about one account are prefixed
with that account's label in `message`.

## Shared shapes

**Account** (`list`):

```json
{
  "index": 1, "key": "<accountUuid>::<orgUuid>", "alias": "work" ,
  "email": "a@example.com", "org_name": "…", "plan": "max",
  "kind": "oauth",
  "cli_active": true, "desktop_active": false, "desktop_linked": false,
  "needs_login": false,
  "added_at": 1761500000, "last_active_at": 1761500000,
  "usage": { "fetched_at": 1761500000, "windows": { }, "error": null }
}
```

`index` is the row number queries accept. `kind` is `oauth` or `console`.
`desktop_active`: Claude Desktop is signed in as this account (by
`account_uuid`, so every org of the account shows it); `desktop_linked`: cma
stores a Desktop login for it. A Desktop-only account (added by `desktop
import-current`/`link` for a login no stored account matches) has an empty
`email` and no Claude Code login; `usage` shows it as not applicable.
Times are Unix seconds (`0` = never).

**Usage windows**: an object keyed by the raw window name (`five_hour`,
`seven_day`, `seven_day_opus`, `seven_day_sonnet`, …; unknown names are
kept), each `{ "utilization": <percent>, "resets_at": "<ISO-8601>" | null,
… }` with optional `limit_dollars`, `used_dollars`, `remaining_dollars`,
`locked_reason`.

**Account query**: row number, alias, email, email prefix, or key prefix
(case-insensitive; first matching stage wins; several matches in a stage ⇒
`ambiguous`).

## Commands and their `data`

| Command | `data` |
|---|---|
| `list` | `{ "active": {"cli": key\|null, "desktop": uuid\|null}, "accounts": [Account] }` (cached usage). |
| `list --live --json` | One live usage fetch (as `usage`), then the same as `list`. Without `--json`, `--live` is the interactive view and needs a terminal. |
| `status` | `{ "cli": {"active": key\|null, "live": Live\|null}, "desktop": {"active": uuid\|null, "available": true, "live_account": uuid\|null, "linked": [uuid], "running": bool\|null}, "running_cli_sessions": int\|null, "pending_journal": {"op","target","from","to","backup_id"}\|null, "pending_both": {"cli_from","cli_to","cli_backup_id"}\|null, "sync_error": {"code","message","hint"}\|null, "cma_home": path, "accounts": int }`. `Live` is `{"state": "absent"\|"no_credential"\|"identified"\|"needs_login"\|"unidentified", "key"?, "managed"?, "reason"?}`. Status succeeds even when sync fails (`sync_error`). |
| `login [--email E] [--sso] [--console] [--org O] [--alias A]` / `login --args-file PATH` | `{ "key", "email", "org_name", "kind", "replaced" }`. Opens the browser; `claude`'s own output goes to stderr in JSON mode. `--args-file` reads the options instead from a JSON file `{"email", "alias", "org", "sso", "console"}` (all optional; unknown keys refused) that must be a regular file owned by the user, mode 0600, not a symlink, at most 16 KiB; text values at most 256 characters, no control characters. It cannot be combined with the option flags (`usage`); a file that fails these checks is `invalid`. The menubar app uses it so no option passes through shell text. |
| `import-current [--alias A]` | `{ "key", "replaced", "backup_id" }`. |
| `import <path\|dir> [--alias A] [--replace]` | `{ "stored": [{"key","replaced","backup_id"}], "unchanged": [key], "alias_set": string\|null }`. A credential identical to the stored one is `unchanged` and needs no consent; `--alias` still applies to it (`alias_set`). |
| `export <dir> [query…] --yes` | `{ "files": [path] }` (no query: every Claude.ai account). |
| `switch [query] [--cli\|--desktop\|--both [--strict]] [--force] [--replace-live] [--yes]` | `{ "target": "cli"\|"desktop"\|"both", "from": key\|null, "to": key, "already_active", "running_sessions": int, "backup_id": id\|null, "elapsed_ms": int, "storage_lock_held_ms": int\|null, "desktop": null\|Desktop }`. A query is required in JSON mode. For `--desktop`, `from`/`to`/`already_active`/`backup_id` describe the Desktop switch (`running_sessions` 0). `Desktop` is `{"switched": true\|false, "from": uuid\|null, "to": uuid, "already_active", "backup_id", "session_follow": bool, "sessions_moved": int, "sessions_renamed": [path], "sessions_left": [string]}`, or, when `--both` targets an account not linked to Desktop, `{"switched": false, "reason": "desktop_not_linked", "message", "hint": null}` (exit 3). A running Desktop is quit first (`--yes`, or a prompt; JSON without `--yes` ⇒ `confirmation_required`), waited for up to 20 s, and started again afterwards; nothing is ever force-quit. **`--both`**: everything that can refuse the Desktop half (link, a complete stored login, one volume, the `--replace-live` and quit consents, Desktop exiting) is checked before Claude Code changes, so those failures exit 1 with nothing changed. `--both` is recorded as one unit (`both.journal` in `CMA_HOME`, written before Claude Code changes, removed as soon as the Desktop half's journal finishes, before Desktop is started). The record names its `cma` process (pid and start time): while that process runs, other commands leave it alone, and a `--both` whose Desktop half finished is never undone (also if it is killed while waiting for Desktop to start). If the Desktop half stopped because Desktop started during it (journal kept, `desktop_running`), Claude Code stays switched for now and both halves are rolled back by the first command after Desktop is quit. If the Desktop half still fails cleanly afterwards (e.g. Desktop started again), Claude Code is put back through its switch's backup (journaled): the result is Desktop's error, exit 1, with "switched back" in the message. If Claude Code cannot be put back (e.g. it refreshed its token meanwhile), `state_uncertain`, exit 2, and the record is kept: `status` shows it (`pending_both`, `state_uncertain: true`), every command retries putting Claude Code back (exit 2 until it works), `cma restore <id>` does it explicitly, and `cma resolve-journal --yes` accepts Claude Code staying switched. If cma dies during the Desktop half, the next command rolls the Desktop half back (its own journal) and then puts Claude Code back too (warning `recovered`). A Desktop half whose own rollback did not complete is `state_uncertain` (exit 2) too, never exit 3. `--strict` additionally refuses when the account is not linked. `--both` to a Desktop-only account is `invalid`. |
| `remove <query>… [--force]` / `remove --all [--force]` | `{ "removed": [{"key","label"}], "failed": [{"key","error": {"code","message"}}] }`. Removing the active account (`--force`) warns `removed_active`: its login stays live in Claude Code until the next `cma switch`. |
| `alias set <query> <alias>` / `alias clear <query>` | `{ "key", "alias": string\|null }`. |
| `usage [query]` | `{ "accounts": [{ "key", "label", "windows", "fetched_at", "fresh", "source": "live"\|"stored"\|null, "refreshed", "note": string\|null, "error": string\|null, "needs_login" }] }`. `note` is one of "n/a (API billing)", "refreshes when Claude Code next runs", "waiting for old sessions", "needs login". Per-account failures are in `error`, not in the envelope's `error`. |
| `config get [key]` | `{ "settings": {…} }` or `{ "key", "value" }`. |
| `config set <key> <value>` | `{ "key", "value" }`. Keys: `session_follow` (`off`\|`on`), `live_usage` (bool), `live_interval_secs` (≥ 10), `default_target` (`cli`\|`desktop`), `refresh_grace_secs`. With `default_target desktop`, `switch` without a target flag switches Claude Desktop. `session_follow on`: a Desktop switch also moves the previous account's local sessions (every org) into the new account's folder (`data.desktop.sessions_*`); off leaves them in place. |
| `backups` | `{ "backups": [{ "id", "op", "created_at", "entries": [string], "in_journal": bool, "problem": string\|null }] }`, newest first. |
| `restore <id> [--force [--yes] [--replace-live]]` | `{ "id", "restored": [string], "unchanged": [string], "uncertain": [string], "skipped": [string], "backup_id": id\|null, "parked_backup_id": id\|null, "recaptured_backup_id": id\|null }` (`backup_id`: the backup of what the restore overwrote; `cma restore <backup_id>` undoes it). `--force` needs `--yes` in JSON mode or without a terminal. While an unfinished operation's journal is kept it refuses first, with `state_uncertain` (exit 2), before any conflict check. A backup that touches Claude Desktop's files needs Desktop quit (`desktop_running`); moved sessions changed since the move are conflicts (with `--force` they stay where they are, are listed in `skipped` and warning `restore_skipped`, and the exit code stays 0). Afterwards `active.desktop` follows what Desktop's `config.json` names. A Desktop switch whose login Desktop changed since (token refresh, session state) conflicts; the hint recommends `cma switch --desktop <previous account>`. With `--force`, cma first moves the live Desktop login out of the way: for a switch it stores the live login's current values under the account the switch put in place; for a backup that only moved a login aside (`desktop link`'s first step) it moves the live login under its account when linked (a stored but unlinked account is linked first), otherwise, after the `--replace-live` consent (a prompt on a terminal), into a `desktop-park` backup with files and keys together; warning `desktop_parked` and `parked_backup_id` name it (`cma restore <that id>` puts it back). Warning `desktop_recaptured` names the backup of a switch's recapture. Every refusal that can be known up front happens before anything is moved, so Desktop is never left signed out by a refused restore. If the restore fails after that park, the parked login is put back right away (journaled; message "was put back", `error.data.park_undone: true`); if Desktop runs then, nothing is written: `desktop_running`, the journal is kept, and the message, hint and `error.data.parked_backup_id` name the park backup (quit Desktop, then any command puts it back; `cma restore <park id>` also does). Then the old login's files and keys come back together, or the restore is refused with `desktop_restore_refused`. A restore (and the rollback of an interrupted Desktop operation) checks before each write into the Desktop dir that Desktop is still quit; if it started, the operation stops with `desktop_running` and its journal is kept: quit Desktop and run any command. |
| `resolve-journal [--yes]` | `{ "resolved": bool, "recovered": bool, "journal": {"op","target","from","to","backup_id"}\|null, "archived": path\|null }` (plus `"both": true` when it handled an interrupted `switch --both`). Runs recovery first, like every mutating command, with the same Claude Desktop checks (refuses with `desktop_running` while Desktop runs and the journal or its backup touches Desktop's files; touches nothing then). Without an operation journal it handles a kept `--both` record: it retries putting Claude Code back (`recovered: true`), or after consent removes the record (`resolved: true`, Claude Code stays switched); resolving a journal also removes such a record. if it rolls the operation back completely, the journal is gone and the result is `resolved: false, recovered: true` (warning `recovered`, exit 0, no consent needed). Only a journal recovery keeps (rollback left items uncertain, backup missing, unreadable journal or manifest) is resolved: after consent it is archived as `resolved-journal.json` in its backup dir and removed, the backup is kept (`resolved: true`). Consent needs `--yes` in JSON mode or without a terminal; no journal ⇒ `not_found`. |
| `clean [--keep N]` | `{ "removed": [id], "skipped": [{"id","reason"}], "keep": int }`. |
| `desktop import-current [--alias A] [--yes]` | `{ "account_uuid", "org_uuid", "key", "created_desktop_only": bool, "already_linked": bool }`. Links the account Claude Desktop is signed in to now (Desktop keeps running; no Desktop file changes) and makes it `active.desktop`. A login no stored account matches becomes a Desktop-only account after consent (`--yes`). Its files are captured on the next switch away from it. |
| `desktop link <query> [--yes] [--replace-live]` | `{ "account_uuid", "org_uuid", "key", "created_desktop_only", "previous": uuid\|null, "stash_backup_id": id\|null, "restored_previous": Desktop\|null, "active": uuid }`. Needs a terminal or the app (JSON without an asker ⇒ `confirmation_required`, hint `desktop import-current`): quits Desktop, stores the live login under its account (it never logs out: that would revoke it), starts Desktop signed out, waits for the user to sign in as the account, quits again, links that login, then asks whether to switch back to the previous one. If Desktop already is signed in as the account, it behaves like `import-current` and returns that shape (`{ "account_uuid", "org_uuid", "key", "created_desktop_only", "already_linked" }`, without `previous`, `stash_backup_id`, `restored_previous` or `active`). |
| `desktop unlink [query]` | `{ "account_uuid", "backup_id": id, "removed_accounts": [key], "was_active": bool }`. Default: the active Desktop account. The stored login moves into the backup, its Keychain values are deleted (pre-images in the backup); the live Desktop login is not touched. A Desktop-only account is removed with it. |

An interrupted Claude Desktop operation that cannot be rolled back (for
example Desktop ran on the half-moved login) is `state_uncertain`; its
message says where nothing was lost: stored logins stay under
`~/.claude-multi-auth/desktop/<account uuid>/files/` and the replaced items in
the backup. Path: quit Desktop, `cma resolve-journal --yes` (keeps those
files), then `cma switch --desktop <account>`; if Desktop asks to sign in,
sign in and run `cma desktop import-current`.

`status`, `backups` and `clean` keep working while an unfinished
operation's journal is kept (exit 2 from the commands that run recovery);
`backups` and `clean` do not run recovery at all, and `clean` never deletes
the journal's backup. `restore` does not run recovery either, but refuses
(exit 2) while that journal exists, because a restore is itself a journaled
operation. `resolve-journal` ends that state.

Without `--json`, on a terminal, consents are asked as prompts instead.
cma never holds its locks while a prompt waits: it releases them, asks, then
re-checks under the locks and asks again if what needed consent changed.
