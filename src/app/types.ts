import type {
  ConnectionSummary,
  DashboardCard,
  DashboardCpuCard,
  DashboardMemoryCard,
  DashboardNetworkCard,
  DashboardStorageCard,
  DashboardUptimeCard,
} from "../types";

/** Frontend-only navigation and presentation state. */
export type View = "dashboard" | "terminal" | "processes" | "services" | "files" | "disk" | "docker" | "logs" | "network" | "cron" | "packages" | "accounts" | "administration" | "commands" | "tunnels";
export type DiskTab = "mounts" | "files" | "dirs" | "docker" | "varlog";
export type DockerSection = "containers" | "images" | "volumes" | "networks";
export type ContainerPlatformTab = "runtime" | "compose";
export type AdministrationTab = "firewall" | "keys" | "security" | "actions";
export type ServerToolTab = AdministrationTab | "commands" | "tunnels";
export type ModalKind = "server" | "workspace-tab-rename" | "service" | "editor" | "folder" | "docker" | "inspect" | "input-prompt" | "compose-scale" | "security" | "master-password" | "host-key" | "change-password" | "reset-credentials" | "cron" | "user" | "user-password" | "package-details" | "command" | "tunnel" | null;
export type MasterPasswordPromptMode = "setup" | "unlock";
export type DashboardCardName = DashboardCard["kind"];

export interface HostKeyMismatch {
  host: string;
  port: number;
  keyType: string;
  oldFingerprints: string[];
  newFingerprint: string;
}

/** First contact: the server is not yet in ~/.ssh/known_hosts. */
export interface HostKeyUnknown {
  host: string;
  port: number;
  keyType: string;
  fingerprint: string;
}

export interface DashboardState {
  profile?: ConnectionSummary;
  cpu?: DashboardCpuCard;
  memory?: DashboardMemoryCard;
  storage?: DashboardStorageCard;
  uptime?: DashboardUptimeCard;
  network?: DashboardNetworkCard;
  loading?: boolean;
  errors: Partial<Record<DashboardCardName, string>>;
}

export type LogSource = "system" | "container" | "compose" | "file";
export type LogViewerStatus = "idle" | "loading" | "live" | "paused" | "polling" | "stopped";

export interface LogTarget {
  source: LogSource;
  label: string;
  container?: string;
  composePath?: string;
  filePath?: string;
  service?: string;
}

export interface LogViewerState {
  target: LogTarget;
  text: string;
  lines: number;
  since: string;
  query: string;
  severity: "all" | "error" | "warn";
  following: boolean;
  status: LogViewerStatus;
  streamId?: string;
}

export interface WorkspaceTab {
  id: string;
  serverId: string;
  /** Optional per-tab label; defaults to the saved server name. */
  label?: string;
}

export interface ActiveOperation {
  id: string;
  label: string;
  serverId?: string;
  cancelled: boolean;
}
