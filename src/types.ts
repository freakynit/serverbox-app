export type AuthMethod = "password" | "privateKey";

export interface ServerProfile {
  id: string;
  name: string;
  host: string;
  username: string;
  port: number;
  authMethod: AuthMethod;
  keyPath?: string;
  jumpHostId?: string;
  groupName?: string;
  tags: string[];
  notes: string;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
  lastConnectedAt?: string;
}

export interface ServerSaveResult {
  server: ServerProfile;
  invalidatedServerIds: string[];
}

export interface SshKey {
  path: string;
  name: string;
  kind: string;
  sizeBytes: number;
}

export interface SshConfigEntry {
  alias: string;
  host?: string;
  username?: string;
  port?: number;
  keyPath?: string;
}

export interface AppStateSnapshot {
  version: number;
  servers: ServerProfile[];
  sshKeys: SshKey[];
  sshConfigEntries: SshConfigEntry[];
}

export interface CredentialStatus {
  configured: boolean;
  unlocked: boolean;
}

export interface ServerCapabilities {
  distro?: string;
  packageManager?: string;
  initSystem?: string;
  systemd: boolean;
  docker: boolean;
  podman: boolean;
  sudo: boolean;
  networkTool?: string;
  journalctl: boolean;
  logread: boolean;
  cron: boolean;
  architecture: string;
  coreutilsVariant: string;
  root: boolean;
}

export interface ConnectionSummary {
  serverId: string;
  hostname: string;
  os: string;
  kernel: string;
  architecture: string;
  capabilities: ServerCapabilities;
  connectedAt: string;
}

export interface ServerConnection {
  serverId: string;
  connectedAt: string;
}

export interface MemoryStats {
  usedBytes: number;
  freeBytes: number;
  totalBytes: number;
  percent: number;
}

export interface SwapStats {
  usedBytes: number;
  totalBytes: number;
  percent: number;
}

export interface DiskUsage {
  mount: string;
  filesystem: string;
  usedBytes: number;
  availableBytes: number;
  totalBytes: number;
  percent: number;
}

export interface NetworkInterface {
  name: string;
  addresses: string[];
}

export interface DiskMount {
  mount: string;
  filesystem: string;
  usedBytes: number;
  availableBytes: number;
  totalBytes: number;
  percent: number;
  inodeUsed?: number;
  inodeTotal?: number;
  inodePercent?: number;
}

export interface LargestFile {
  path: string;
  sizeBytes: number;
  modifiedAt?: number;
}

export interface LargestDirectory {
  path: string;
  sizeBytes: number;
  depth: number;
}

export interface DockerDiskUsage {
  imagesBytes: number;
  containersBytes: number;
  volumesBytes: number;
  buildCacheBytes: number;
  otherBytes: number;
  totalBytes: number;
  reclaimableBytes: number;
}

export interface DiskExplorerSnapshot {
  mounts: DiskMount[];
  largestFiles: LargestFile[];
  largestDirs: LargestDirectory[];
  dockerUsage?: DockerDiskUsage;
}

export interface DashboardCpuCard {
  cpuPercent: number;
  cpuCores: number;
  cpuModel: string;
}

export interface DashboardMemoryCard {
  memory: MemoryStats;
  swap: SwapStats;
}

export interface DashboardStorageCard {
  disks: DiskUsage[];
}

export interface DashboardUptimeCard {
  uptimeSeconds: number;
  loadAverages: [number, number, number];
}

export interface DashboardNetworkCard {
  interfaces: NetworkInterface[];
}

export type DashboardCard =
  | { kind: "profile"; summary: ConnectionSummary }
  | ({ kind: "cpu" } & DashboardCpuCard)
  | ({ kind: "memory" } & DashboardMemoryCard)
  | ({ kind: "storage" } & DashboardStorageCard)
  | ({ kind: "uptime" } & DashboardUptimeCard)
  | ({ kind: "network" } & DashboardNetworkCard);

export interface ProcessInfo {
  pid: number;
  user: string;
  cpuPercent: number;
  memoryPercent: number;
  rssBytes: number;
  runtimeSeconds: number;
  command: string;
}

export interface Page<T> {
  items: T[];
  hasMore: boolean;
}

export interface ServiceInfo {
  name: string;
  loadState: string;
  activeState: string;
  subState: string;
  description: string;
  enabled?: boolean;
}

export interface ServiceDetails {
  name: string;
  properties: Array<[string, string]>;
  journal: string;
  unitFile?: string;
}

export interface RemoteFile {
  name: string;
  path: string;
  kind: "directory" | "file" | "symlink";
  sizeBytes: number;
  modifiedAt?: number;
  permissions?: string;
  uid?: number;
  gid?: number;
  hidden: boolean;
}

export interface TransferProgress {
  transferId: string;
  direction: "upload" | "download";
  path: string;
  completedBytes: number;
  totalBytes: number;
  completedFiles: number;
  totalFiles: number;
  done: boolean;
  error?: string;
}

export interface ContainerInfo {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  ports: string;
  cpuPercent?: number;
  memoryUsageBytes?: number;
  memoryLimitBytes?: number;
  memoryPercent?: number;
  networkRxBytes?: number;
  networkTxBytes?: number;
  blockReadBytes?: number;
  blockWriteBytes?: number;
}

export interface DockerImage {
  id: string;
  repository: string;
  tag: string;
  size: string;
  created: string;
}

export interface DockerVolume {
  name: string;
  driver: string;
  mountpoint: string;
}

export interface DockerNetwork {
  id: string;
  name: string;
  driver: string;
  scope: string;
}

export interface DockerSnapshot {
  runtime: string;
  containers: ContainerInfo[];
  images: DockerImage[];
  volumes: DockerVolume[];
  networks: DockerNetwork[];
}

export interface DockerPage extends DockerSnapshot {
  section: "containers" | "images" | "volumes" | "networks";
  hasMore: boolean;
}

export interface PortInfo {
  protocol: string;
  state: string;
  localAddress: string;
  remoteAddress: string;
  process: string;
  pid?: number;
}

export interface TerminalStarted {
  sessionId: string;
  serverId: string;
}

export interface TerminalEvent {
  sessionId: string;
  data: string;
}

export interface LogStreamStarted {
  sessionId: string;
  serverId: string;
}

export interface TerminalTab {
  id: string;
  serverId: string;
  workspaceTabId: string;
  sessionId?: string;
  title: string;
  command?: string;
  buffer: string;
  connecting: boolean;
  cols?: number;
  rows?: number;
  closed?: boolean;
}

export interface CronJob {
  id: string;
  source: string;
  user: string;
  schedule: string;
  command: string;
  enabled: boolean;
  humanSchedule: string;
  nextRun?: string;
  editable: boolean;
}

export interface PackageInfo {
  name: string;
  version: string;
  architecture: string;
  description: string;
  installed: boolean;
  upgradeVersion?: string;
}

export interface PackagePage {
  manager: string;
  packages: Page<PackageInfo>;
  pendingUpgrades: number;
}

export interface LinuxUser {
  name: string;
  uid: number;
  gid: number;
  home: string;
  shell: string;
  groups: string[];
  lastLogin?: string;
  locked: boolean;
}

export interface LinuxGroup {
  name: string;
  gid: number;
  members: string[];
}

export interface AccountSnapshot {
  users: LinuxUser[];
  groups: LinuxGroup[];
}

export interface ComposeProject { name: string; path: string; services: string[]; running: number; topology: string[]; environment: string[]; }
export interface ContainerExec { command: string; shell: string; }
export interface FirewallSnapshot { provider?: string; enabled: boolean; rules: string[]; }
export interface AuthorizedKey { id: string; kind: string; fingerprint: string; comment: string; key: string; }
export interface SecuritySnapshot { updates: number; securityUpdates: number; rebootRequired: boolean; lastPackageUpdate?: string; kernelVersion: string; containerVersion?: string; containerUpdateAvailable: boolean; packageUpdatesAvailable: boolean; }
export interface SavedCommand { id: string; serverId?: string; name: string; command: string; }
export interface TunnelConfig { id: string; serverId: string; name: string; kind: "local" | "remote" | "socks"; bindHost: string; bindPort: number; targetHost: string; targetPort: number; }
export interface TunnelStatus { id: string; running: boolean; error?: string; }
export interface CommandResult { serverId: string; serverName: string; stdout: string; stderr: string; exitCode: number; error?: string; }
