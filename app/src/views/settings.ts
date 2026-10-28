// Settings: values stored in registry.json through `cma config set`, plus
// launch at login (a LaunchAgent) and Install CLI.
import { api, type State } from "../api";
import { busy, button, el, report } from "./dom";

const DISCLAIMER =
  "Live usage polls an unofficial Claude usage endpoint for every stored account. It is off by default.";

function field(label: string, control: HTMLElement, help?: string): HTMLElement {
  return el("div", { class: "field" },
    el("label", { text: label }),
    control,
    help ? el("div", { class: "muted small", text: help }) : null);
}

export function renderSettings(root: HTMLElement, s: State, rerender: () => void): void {
  const st = s.settings.data?.settings;
  if (!st) {
    root.replaceChildren(el("p", { class: "error", text: s.settings.error?.message ?? "settings unavailable" }));
    return;
  }
  const save = async (key: string, value: string, ok: string) => {
    if (report(await api.setSetting(key, value), ok)) rerender();
    else rerender();
  };

  const follow = el("select", { attrs: { "aria-label": "Session follow" } },
    el("option", { text: "Off", attrs: { value: "off" } }),
    el("option", { text: "On", attrs: { value: "on" } }));
  follow.value = st.session_follow;
  follow.addEventListener("change", () => void save("session_follow", follow.value, "Session follow saved."));

  const target = el("select", { attrs: { "aria-label": "Default target" } },
    el("option", { text: "Claude Code (CLI)", attrs: { value: "cli" } }),
    el("option", { text: "Claude Desktop", attrs: { value: "desktop" } }));
  (target.options[1] as HTMLOptionElement).disabled = !s.app.desktop_available;
  target.value = st.default_target;
  target.addEventListener("change", () => void save("default_target", target.value, "Default target saved."));

  const live = el("input", { attrs: { type: "checkbox", "aria-label": "Live usage" } });
  live.checked = st.live_usage;
  live.addEventListener("change", () => void save("live_usage", live.checked ? "true" : "false", live.checked ? `Live usage on. ${DISCLAIMER}` : "Live usage off."));

  const interval = el("input", { attrs: { type: "number", min: "10", step: "10", "aria-label": "Live usage interval" } });
  interval.value = String(st.live_interval_secs);
  interval.addEventListener("change", () => void save("live_interval_secs", interval.value, "Interval saved."));

  const grace = el("input", { attrs: { type: "number", min: "0", step: "30", "aria-label": "Refresh grace" } });
  grace.value = String(st.refresh_grace_secs);
  grace.addEventListener("change", () => void save("refresh_grace_secs", grace.value, "Refresh grace saved."));

  const atLogin = el("input", { attrs: { type: "checkbox", "aria-label": "Launch at login" } });
  atLogin.checked = !!s.app.launch_at_login;
  atLogin.disabled = s.app.launch_at_login === null;
  atLogin.addEventListener("change", () =>
    void (async () => {
      report(await api.setLaunchAtLogin(atLogin.checked), atLogin.checked ? "Launches at login." : "No longer launches at login.");
      rerender();
    })(),
  );

  const ci = s.app.cli_install;
  const install = button(ci.installed ? "Reinstall CLI" : "Install CLI", () =>
    void busy(install, async () => {
      report(await api.installCli(), "Installed.");
      rerender();
    }),
  );
  const installText = ci.installed
    ? `cma is linked at ${ci.link}.`
    : ci.other_link
      ? `${ci.link} links to ${ci.target ?? "another file"}, not to this app's cma; Install CLI asks before replacing it.`
      : ci.other_file
        ? `${ci.link} exists and is not a link; it is left alone.`
        : `Links ${ci.link} to the cma bundled with this app.`;

  root.replaceChildren(
    el("section", { class: "card" },
      el("h2", { text: "Switching" }),
      field("Session follow", follow, "Claude Desktop only: a Desktop switch also moves the previous account's local Code sessions to the new account."),
      field("Default target", target, "What cma switch switches when no --cli, --desktop or --both is given.")),
    el("section", { class: "card" },
      el("h2", { text: "Usage" }),
      field("Live usage", live, DISCLAIMER),
      field("Refresh interval (seconds, at least 10)", interval),
      field("Refresh grace (seconds)", grace, "Accounts active within this time are never refreshed by cma, so their running sessions keep working.")),
    el("section", { class: "card" },
      el("h2", { text: "App" }),
      field("Launch at login", atLogin),
      field("Command line", el("div", { class: "row" }, install), `${installText} Add ~/.local/bin to PATH if your shell does not find cma.`)),
  );
}
