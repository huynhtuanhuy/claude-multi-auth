// DOM helpers. Text is only ever set through `textContent` (never
// innerHTML), so account names, aliases and error messages render as text.
import type { Doc } from "../api";

type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { class?: string; attrs?: Record<string, string>; text?: string } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (props.class) e.className = props.class;
  for (const [k, v] of Object.entries(props.attrs ?? {})) e.setAttribute(k, v);
  if (props.text !== undefined) e.textContent = props.text;
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

export function button(text: string, onClick: () => void, opts: { disabled?: boolean; title?: string; kind?: string } = {}): HTMLButtonElement {
  const b = el("button", { class: opts.kind ?? "", text, attrs: { type: "button" } });
  b.disabled = !!opts.disabled;
  if (opts.title) b.title = opts.title;
  b.addEventListener("click", onClick);
  return b;
}

/** Disable a button while `work` runs (a switch may wait on a lock). */
export async function busy(b: HTMLButtonElement, work: () => Promise<void>): Promise<void> {
  const was = b.disabled;
  b.disabled = true;
  try {
    await work();
  } finally {
    b.disabled = was;
  }
}

const banner = () => document.getElementById("banner") as HTMLDivElement;

export function clearBanner(): void {
  const b = banner();
  b.replaceChildren();
  b.hidden = true;
}

/** Show a message (and optional action buttons) above the view. */
export function showBanner(kind: "error" | "warn" | "ok", lines: string[], actions: HTMLElement[] = []): void {
  const b = banner();
  b.className = `banner ${kind}`;
  b.replaceChildren(
    ...lines.map((l) => el("p", { text: l })),
    ...(actions.length ? [el("div", { class: "actions" }, ...actions)] : []),
    button("Dismiss", clearBanner, { kind: "link" }),
  );
  b.hidden = false;
}

/** Report a command's document: its error (with hint) or its warnings. */
export function report<T>(doc: Doc<T>, success?: string, actions: HTMLElement[] = []): boolean {
  if (!doc.ok && doc.error?.code === "cancelled") {
    // The user answered Cancel in a dialog: their choice, not an error.
    // (`confirmation_required` without a Cancel, e.g. cma giving up on a
    // question that kept changing, is shown as an error with its hint.)
    showBanner("ok", ["Cancelled; nothing was changed."]);
    return false;
  }
  if (!doc.ok && doc.error) {
    const lines = [doc.error.message];
    if (doc.error.hint) lines.push(`Hint: ${doc.error.hint}`);
    for (const w of doc.warnings) lines.push(`Warning: ${w.message}`);
    showBanner("error", lines, actions);
    return false;
  }
  if (doc.warnings.length) {
    showBanner("warn", [...(success ? [success] : []), ...doc.warnings.map((w) => w.message)], actions);
  } else if (success) {
    showBanner("ok", [success], actions);
  }
  return doc.ok;
}

export function fmtTime(unixSecs: number): string {
  if (!unixSecs) return "never";
  return new Date(unixSecs * 1000).toLocaleString();
}
