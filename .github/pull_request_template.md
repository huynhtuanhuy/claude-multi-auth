## What and why

<!-- What this changes and why. Link the issue it fixes, if any. -->

## How it was tested

<!-- Tests added or changed; anything you checked by hand (with which
Claude Code / Claude Desktop version). -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass
- [ ] `npm --prefix app run build` passes (if `app/` changed)
- [ ] Tests use the fake backend or an in-memory store; any real-Keychain test is `#[ignore]` and uses service `claude-multi-auth-test`
- [ ] No token, real email or account id in code, tests, fixtures or output
- [ ] README / `docs/` updated for user-visible changes; `docs/json-api.md` for `--json` changes
- [ ] CHANGELOG.md updated for user-visible changes
- [ ] Commits follow Conventional Commits
