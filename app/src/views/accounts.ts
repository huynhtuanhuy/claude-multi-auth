// Accounts: status, stored accounts with usage bars and actions, and the
// Add account form (opens Terminal for `cma login`).
import { api, type Account, type State } from "../api";
import { busy, button, el, fmtTime, report, showBanner } from "./dom";

const WINDOW_LABELS: Record<string, string> = {
  five_hour: "5h",
  seven_day: "7d",
  seven_day_opus: "7d Opus",
  seven_day_sonnet: "7d Sonnet",
  seven_day_cowork: "7d Cowork",
  seven_day_oauth_apps: "7d OAuth apps",
};

export function accountLabel(a: Account): string {
  const base = a.email || a.key;
  return a.alias ? `${a.alias} (${base})` : base;
}

function usageBars(a: Account): HTMLElement {
  const box = el("div", { class: "usage" });
  const entries = Object.entries(a.usage.windows ?? {});
  for (const [k, w] of entries) {
    const pct = typeof w.utilization === "number" ? Math.max(0, Math.min(100, w.utilization)) : null;
    if (pct === null) continue;
    const bar = el("div", { class: "bar" }, el("div", { class: "fill" }));
    (bar.firstChild as HTMLElement).style.width = `${pct}%`;
    if (pct >= 90) bar.classList.add("high");
    const reset = w.resets_at ? `resets ${new Date(w.resets_at).toLocaleString()}` : "";
    box.append(
      el("div", { class: "window" },
        el("span", { class: "wlabel", text: WINDOW_LABELS[k] ?? k }),
        bar,
        el("span", { class: "wpct", text: `${Math.round(pct)}%` }),
        el("span", { class: "muted small", text: reset })),
    );
  }
  if (!box.childElementCount) box.append(el("span", { class: "muted small", text: "no usage fetched yet" }));
  const meta: string[] = [];
  if (a.usage.fetched_at) meta.push(`fetched ${fmtTime(a.usage.fetched_at)}`);
  if (a.usage.error) meta.push(`error: ${a.usage.error}`);
  if (meta.length) box.append(el("div", { class: "muted small", text: meta.join(" · ") }));
  return box;
}

function aliasEditor(a: Account, rerender: () => void): HTMLElement {
  const input = el("input", { attrs: { type: "text", maxlength: "64", placeholder: "alias", "aria-label": "Alias" } });
  input.value = a.alias ?? "";
  const save = button("Save alias", () =>
    void busy(save, async () => {
      const v = input.value.trim();
      if (report(await api.setAlias(a.key, v === "" ? null : v), "Alias saved.")) rerender();
    }),
  );
  const clear = button("Clear", () =>
    void busy(clear, async () => {
      if (report(await api.setAlias(a.key, null), "Alias cleared.")) rerender();
    }),
    { disabled: !a.alias },
  );
  return el("div", { class: "row" }, input, save, clear);
}

function accountCard(a: Account, s: State, rerender: () => void): HTMLElement {
  const desktop = s.app.desktop_available;
  // What Claude Desktop is signed in as now, not what cma last left it on.
  const live = s.status.data?.desktop.live_account ?? null;
  const desktopOn = live != null && a.key.startsWith(`${live}::`);
  const badges = el("div", { class: "badges" });
  if (a.cli_active) badges.append(el("span", { class: "badge active", text: "CLI active" }));
  if (desktopOn) badges.append(el("span", { class: "badge", text: "Desktop" }));
  if (a.needs_login) badges.append(el("span", { class: "badge warn", text: "needs login" }));
  if (a.kind === "console") badges.append(el("span", { class: "badge", text: "Console" }));

  const name = accountLabel(a);
  const sw = button("Switch CLI", () =>
    void busy(sw, async () => {
      if (report(await api.switch(a.key, "cli"), `Claude Code now uses ${name}. New claude sessions use it.`)) rerender();
    }),
    { disabled: a.cli_active, kind: "primary" },
  );
  const notLinked = "cma stores no Claude Desktop login for this account yet: Link Desktop first";
  const swd = button("Switch Desktop", () =>
    void busy(swd, async () => {
      if (report(await api.switch(a.key, "desktop"), `Claude Desktop now uses ${name}.`)) rerender();
    }),
    { disabled: !desktop || !a.desktop_linked || desktopOn, title: a.desktop_linked ? "" : notLinked },
  );
  const both = button("Switch CLI + Desktop", () =>
    void busy(both, async () => {
      const doc = await api.switch(a.key, "both");
      // A partial result: Claude Code switched, Desktop did not (cma says why in a warning).
      const d = (doc.data as { desktop?: { switched?: boolean; reason?: string | null } } | undefined)?.desktop;
      const cliOnly = doc.ok && d?.switched === false && d.reason != null;
      if (report(doc, cliOnly ? `Claude Code now uses ${name}; Claude Desktop was not switched.` : `Claude Code and Claude Desktop now use ${name}.`)) rerender();
    }),
    { disabled: !desktop || !a.desktop_linked || (a.cli_active && desktopOn), title: a.desktop_linked ? "" : notLinked },
  );
  const link = button(a.desktop_linked ? "Link Desktop again" : "Link Desktop", () =>
    void busy(link, async () => {
      const doc = await api.desktopLink(a.key);
      const back = doc.ok && doc.data?.restored_previous != null;
      // cma links whoever actually signed in, which may not be this card's account.
      const linkedKey = doc.data?.key;
      const linkedAcct = s.list.data?.accounts.find((x) => x.key === linkedKey);
      const who = linkedAcct ? accountLabel(linkedAcct) : linkedKey && linkedKey !== a.key ? "the account Desktop signed in as" : name;
      if (report(doc, back ? `Linked ${who} to Claude Desktop; Claude Desktop is back on the previous account.` : `Linked ${who} to Claude Desktop.`)) rerender();
    }),
    { disabled: !desktop, title: "Signs Claude Desktop in as this account while you watch (cma asks before quitting Desktop)" },
  );
  const rm = button("Remove", () =>
    void busy(rm, async () => {
      if (report(await api.remove(a.key), `Removed ${accountLabel(a)} (its credentials stay in a backup).`)) rerender();
    }),
    { kind: "danger" },
  );

  return el("section", { class: "card" },
    el("div", { class: "card-head" },
      el("div", {},
        el("div", { class: "title", text: accountLabel(a) }),
        el("div", { class: "muted small", text: [a.org_name, a.plan].filter(Boolean).join(" · ") })),
      badges),
    usageBars(a),
    el("div", { class: "row" }, sw, swd, both, link, rm),
    aliasEditor(a, rerender),
  );
}

function desktopText(s: State): string {
  const d = s.status.data?.desktop;
  if (!d) return "unknown";
  const running = d.running === null ? "" : d.running ? " · running" : " · not running";
  if (!d.live_account) return `not signed in${running}`;
  // Keys are `<account uuid>::<org uuid>`; any org of the account names it.
  const live = d.live_account;
  const acct = s.list.data?.accounts.find((a) => a.key.startsWith(`${live}::`));
  const who = acct ? accountLabel(acct) : "an account cma does not store";
  const linked = d.linked.includes(d.live_account) ? "" : " (not linked: Link Desktop stores its login)";
  return `${who}${linked}${running}`;
}

function statusBox(s: State, rerender: () => void): HTMLElement {
  const box = el("section", { class: "card status" });
  const st = s.status;
  if (!st.ok || !st.data) {
    box.append(el("p", { class: "error", text: st.error ? `${st.error.message}` : "status unavailable" }));
    if (st.error?.hint) box.append(el("p", { class: "muted small", text: st.error.hint }));
    return box;
  }
  const d = st.data;
  const live = d.cli.live;
  let liveText = "unknown";
  if (live) {
    const acct = s.list.data?.accounts.find((a) => a.key === live.key);
    switch (live.state) {
      case "identified":
        liveText = acct ? accountLabel(acct) : `${live.key} (not stored by cma)`;
        break;
      case "needs_login":
        liveText = `${acct ? accountLabel(acct) : live.key} (signed out: needs login)`;
        break;
      case "absent":
        liveText = "no Claude Code login";
        break;
      case "no_credential":
        liveText = "no Claude.ai credential in the Claude Code login";
        break;
      default:
        liveText = `unidentified${live.reason ? ` (${live.reason})` : ""}`;
    }
  }
  box.append(el("div", {}, el("strong", { text: "Claude Code: " }), liveText));
  box.append(el("div", {}, el("strong", { text: "Claude Desktop: " }), desktopText(s)));
  if (d.running_cli_sessions) {
    box.append(el("div", { class: "small", text: `${d.running_cli_sessions} claude session(s) running: switching asks first.` }));
  }
  if (d.sync_error) {
    box.append(el("p", { class: "error", text: d.sync_error.message }));
    if (d.sync_error.hint) box.append(el("p", { class: "muted small", text: d.sync_error.hint }));
  }
  if (d.pending_journal) {
    const j = d.pending_journal;
    const resolve = button("Resolve journal…", () =>
      void busy(resolve, async () => {
        if (report(await api.resolveJournal(), "Journal resolved.")) rerender();
      }),
      { kind: "danger" },
    );
    box.append(
      el("p", { class: "error", text: `An unfinished ${j.op} (${j.target}) could not be rolled back completely (backup ${j.backup_id}). cma refuses changes until it is resolved; see Backups.` }),
      el("div", { class: "row" }, resolve),
    );
  }
  for (const w of [...st.warnings, ...s.list.warnings]) {
    box.append(el("div", { class: "warn small", text: w.message }));
  }
  return box;
}

function addForm(s: State, rerender: () => void): HTMLElement {
  const email = el("input", { attrs: { type: "email", maxlength: "254", placeholder: "email (optional, pre-fills the browser)", "aria-label": "Email" } });
  const alias = el("input", { attrs: { type: "text", maxlength: "64", placeholder: "alias (optional)", "aria-label": "Alias" } });
  const org = el("input", { attrs: { type: "text", maxlength: "128", placeholder: "organization uuid or name (optional)", "aria-label": "Organization" } });
  const sso = el("input", { attrs: { type: "checkbox", id: "add-sso" } });
  const consoleBox = el("input", { attrs: { type: "checkbox", id: "add-console" } });
  const opt = (v: string) => (v.trim() === "" ? null : v.trim());
  const start = button("Log in in Terminal…", () =>
    void busy(start, async () => {
      const doc = await api.startLogin({
        email: opt(email.value),
        alias: opt(alias.value),
        org: opt(org.value),
        sso: sso.checked,
        console: consoleBox.checked,
      });
      if (report(doc, "Terminal opened: finish the login in the browser. The account appears here when it is done.")) rerender();
    }),
    { kind: "primary", disabled: s.app.login_in_progress },
  );
  return el("section", { class: "card", attrs: { id: "add" } },
    el("h2", { text: "Add account" }),
    el("p", { class: "muted small", text: "Opens Terminal and runs cma login there; the active Claude Code login is not touched." }),
    el("div", { class: "form" }, email, alias, org,
      el("label", { attrs: { for: "add-sso" } }, sso, " Single sign-on"),
      el("label", { attrs: { for: "add-console" } }, consoleBox, " Console (API billing) account")),
    el("div", { class: "row" }, start,
      s.app.login_in_progress ? el("span", { class: "muted small", text: "A login is in progress in Terminal…" }) : null),
  );
}

export function renderAccounts(root: HTMLElement, s: State, rerender: () => void): void {
  const refresh = button("Refresh usage", () =>
    void busy(refresh, async () => {
      if (report(await api.refreshUsage(), "Usage refreshed.")) rerender();
    }),
  );
  const accounts = s.list.data?.accounts ?? [];
  if (!s.list.ok && s.list.error) {
    showBanner("error", [s.list.error.message, ...(s.list.error.hint ? [`Hint: ${s.list.error.hint}`] : [])]);
  }
  root.replaceChildren(
    statusBox(s, rerender),
    el("div", { class: "row spread" }, el("h2", { text: `Accounts (${accounts.length})` }), refresh),
    ...(accounts.length
      ? accounts.map((a) => accountCard(a, s, rerender))
      : [el("p", { class: "muted", text: "No accounts stored yet. Add one below." })]),
    addForm(s, rerender),
  );
}
