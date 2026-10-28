# claude-multi-auth

Keep several Claude accounts logged in on one Mac and switch Claude Code and
Claude Desktop between them without logging out and back in. macOS 13 or
later, Apple silicon or Intel.

This package installs either or both parts:

- **`cma`**, the command line tool;
- **Claude Multi Auth.app**, the menubar app (downloaded from the GitHub
  release of the same version and checked against a SHA-256 that ships in
  this package).

```sh
npx claude-multi-auth            # asks: command line, menubar app, or both
npx claude-multi-auth --cli      # same as: npm install -g claude-multi-auth
npx claude-multi-auth --app      # the app, into /Applications
npx claude-multi-auth --all      # both
npx claude-multi-auth --uninstall --all
```

Run `npx claude-multi-auth --help` for every option. The installer never uses
`sudo` and never touches your accounts in `~/.claude-multi-auth`.

> **Unofficial.** claude-multi-auth is not affiliated with, endorsed by, or
> supported by Anthropic.

Documentation, what the tool changes on your Mac, and the source:
<https://github.com/huynhtuanhuy/claude-multi-auth#readme>

License: MIT.
