// Backups: list and restore, with "changed since" refusals explained and a
// confirmed "Restore anyway" (the app asks again in a native dialog).
import { api, type Backup } from "../api";
import { busy, button, el, fmtTime, report } from "./dom";

async function restore(b: Backup, rerender: () => void, force: boolean): Promise<void> {
  const doc = await api.restore(b.id, force);
  const code = doc.error?.code;
  if (!force && (code === "restore_conflict" || code === "restore_older_login")) {
    const anyway = button("Restore anyway…", () => void busy(anyway, () => restore(b, rerender, true)), { kind: "danger" });
    report(doc, undefined, [anyway]);
    return;
  }
  if (report(doc, `Restored ${b.id}.`)) rerender();
}

export async function renderBackups(root: HTMLElement, rerender: () => void): Promise<void> {
  const doc = await api.listBackups();
  if (!doc.ok || !doc.data) {
    root.replaceChildren();
    report(doc);
    return;
  }
  const rows = doc.data.backups.map((b) => {
    const r = button("Restore", () => void busy(r, () => restore(b, rerender, false)), { disabled: !!b.problem });
    return el("section", { class: "card" },
      el("div", { class: "card-head" },
        el("div", {},
          el("div", { class: "title mono", text: b.id }),
          el("div", { class: "muted small", text: `${b.op} · ${fmtTime(b.created_at)}${b.in_journal ? " · unfinished operation" : ""}` })),
        r),
      b.problem
        ? el("div", { class: "error small", text: `unreadable: ${b.problem}` })
        : el("ul", { class: "entries small" }, ...b.entries.map((e) => el("li", { text: e }))),
    );
  });
  root.replaceChildren(
    el("p", { class: "muted small", text: "Restoring puts back only what that operation wrote. Items changed since then (for example a token Claude Code refreshed) are refused unless you confirm." }),
    ...(rows.length ? rows : [el("p", { class: "muted", text: "No backups yet." })]),
  );
}
