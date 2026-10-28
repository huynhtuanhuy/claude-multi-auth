// Settings window: three views, re-rendered when the app reports a state
// change (`poll` stamp: registry.json changed, or a command ran).
import { api, type State } from "./api";
import { renderAccounts } from "./views/accounts";
import { renderBackups } from "./views/backups";
import { clearBanner, el, showBanner } from "./views/dom";
import { renderSettings } from "./views/settings";

type View = "accounts" | "settings" | "backups";
let current: View = "accounts";
let lastStamp = -1;
let rendering = false;

const root = document.getElementById("view") as HTMLElement;

async function render(): Promise<void> {
  if (rendering) return;
  rendering = true;
  try {
    for (const b of document.querySelectorAll<HTMLButtonElement>(".tabs button")) {
      b.setAttribute("aria-selected", String(b.dataset.view === current));
    }
    if (current === "backups") {
      await renderBackups(root, rerender);
      return;
    }
    const s: State = await api.getState();
    if (current === "accounts") renderAccounts(root, s, rerender);
    else renderSettings(root, s, rerender);
  } catch (e) {
    root.replaceChildren(el("p", { class: "error", text: `The app could not load its state: ${String(e)}` }));
  } finally {
    rendering = false;
  }
}

function rerender(): void {
  void render();
}

let shownOnce = false;

function show(view: View): void {
  shownOnce = true;
  current = view;
  clearBanner();
  void render().then(() => {
    if (view === "accounts" && pendingAdd) {
      pendingAdd = false;
      document.getElementById("add")?.scrollIntoView();
      (document.querySelector("#add input") as HTMLInputElement | null)?.focus();
    }
  });
}

let pendingAdd = false;

async function poll(): Promise<void> {
  if (document.hidden) return;
  try {
    const p = await api.poll();
    if (p.section === "add") {
      pendingAdd = true;
      show("accounts");
    } else if (p.section === "settings" || p.section === "accounts" || p.section === "backups") {
      show(p.section);
    } else if (p.stamp !== lastStamp && lastStamp !== -1 && !rendering) {
      // Leave the view alone while a form is being edited.
      const editing = document.activeElement instanceof HTMLInputElement;
      if (!editing) rerender();
    }
    lastStamp = p.stamp;
  } catch (e) {
    showBanner("error", [`Lost contact with the app: ${String(e)}`]);
  }
}

for (const b of document.querySelectorAll<HTMLButtonElement>(".tabs button")) {
  b.addEventListener("click", () => show(b.dataset.view as View));
}
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) rerender();
});

void poll().then(() => {
  if (!shownOnce) show(current);
});
setInterval(() => void poll(), 2000);
