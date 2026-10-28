// Typed wrappers over the app's Tauri commands. Every command returns a
// `cma --json` document (schema_version 1); no token ever reaches here.
import { invoke } from "@tauri-apps/api/core";

export interface Warning {
  code: string;
  message: string;
}

export interface ErrorInfo {
  code: string;
  message: string;
  hint: string | null;
}

export interface Doc<T> {
  schema_version: number;
  ok: boolean;
  data: T | null;
  warnings: Warning[];
  error: ErrorInfo | null;
  state_uncertain: boolean;
}

export interface UsageWindow {
  utilization?: number;
  resets_at?: string | null;
}

export interface Account {
  index: number;
  key: string;
  alias: string | null;
  email: string;
  org_name: string;
  plan: string;
  kind: string;
  cli_active: boolean;
  desktop_active: boolean;
  desktop_linked: boolean;
  needs_login: boolean;
  usage: {
    fetched_at: number;
    windows: Record<string, UsageWindow>;
    error: string | null;
  };
}

export interface ListData {
  active: { cli: string | null; desktop: string | null };
  accounts: Account[];
}

export interface StatusData {
  cli: {
    active: string | null;
    live: { state: string; key?: string; managed?: boolean; reason?: string } | null;
  };
  desktop: {
    active: string | null;
    available: boolean;
    live_account: string | null;
    linked: string[];
    running: boolean | null;
  };
  running_cli_sessions: number | null;
  pending_journal: { op: string; target: string; backup_id: string } | null;
  sync_error: ErrorInfo | null;
}

export interface Settings {
  session_follow: "off" | "on";
  live_usage: boolean;
  live_interval_secs: number;
  default_target: "cli" | "desktop";
  refresh_grace_secs: number;
}

export interface AppInfo {
  desktop_available: boolean;
  launch_at_login: boolean | null;
  login_in_progress: boolean;
  cli_install: { link: string; installed: boolean; other_link: boolean; other_file: boolean; target: string | null };
}

export interface State {
  list: Doc<ListData>;
  status: Doc<StatusData>;
  settings: Doc<{ settings: Settings }>;
  app: AppInfo;
}

export interface Backup {
  id: string;
  op: string;
  created_at: number;
  entries: string[];
  in_journal: boolean;
  problem: string | null;
}

export interface Poll {
  stamp: number;
  section: string | null;
}

export type SwitchTarget = "cli" | "desktop" | "both";

export interface LoginOptions {
  email: string | null;
  alias: string | null;
  org: string | null;
  sso: boolean;
  console: boolean;
}

type AnyDoc = Doc<Record<string, unknown>>;

export const api = {
  getState: () => invoke<State>("get_state"),
  poll: () => invoke<Poll>("poll"),
  switch: (key: string, target: SwitchTarget) => invoke<AnyDoc>("switch", { key, target }),
  desktopLink: (key: string) => invoke<AnyDoc>("desktop_link", { key }),
  remove: (key: string) => invoke<AnyDoc>("remove", { key }),
  setAlias: (key: string, alias: string | null) => invoke<AnyDoc>("set_alias", { key, alias }),
  setSetting: (key: string, value: string) => invoke<AnyDoc>("set_setting", { key, value }),
  refreshUsage: () => invoke<AnyDoc>("refresh_usage"),
  listBackups: () => invoke<Doc<{ backups: Backup[] }>>("list_backups"),
  restore: (id: string, force: boolean) => invoke<AnyDoc>("restore", { id, force }),
  resolveJournal: () => invoke<AnyDoc>("resolve_journal"),
  installCli: () => invoke<AnyDoc>("install_cli"),
  startLogin: (options: LoginOptions) => invoke<AnyDoc>("start_login", { options }),
  setLaunchAtLogin: (enabled: boolean) => invoke<AnyDoc>("set_launch_at_login", { enabled }),
};
