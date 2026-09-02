use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

pub const APP_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthMethod {
    Password,
    PrivateKey,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::Password
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub username: String,
    pub port: u16,
    pub auth_method: AuthMethod,
    pub key_path: Option<String>,
    pub jump_host_id: Option<String>,
    pub group_name: Option<String>,
    pub tags: Vec<String>,
    pub notes: String,
    pub favorite: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_connected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSaveResult {
    pub server: ServerProfile,
    pub invalidated_server_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerDraft {
    pub id: Option<String>,
    pub name: String,
    pub host: String,
    pub username: String,
    // Keep this wide enough for validation to return a useful error rather than
    // failing while deserializing an out-of-range port.
    pub port: u32,
    #[serde(default)]
    pub auth_method: AuthMethod,
    pub key_path: Option<String>,
    #[serde(default)]
    pub jump_host_id: Option<String>,
    pub group_name: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub favorite: bool,
    pub password: Option<String>,
    pub key_passphrase: Option<String>,
    pub sudo_password: Option<String>,
}

impl Drop for ServerDraft {
    fn drop(&mut self) {
        self.password.zeroize();
        self.key_passphrase.zeroize();
        self.sudo_password.zeroize();
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigEntry {
    pub alias: String,
    pub host: Option<String>,
    pub username: Option<String>,
    pub port: Option<u16>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateSnapshot {
    pub version: u32,
    pub servers: Vec<ServerProfile>,
    pub ssh_keys: Vec<SshKey>,
    pub ssh_config_entries: Vec<SshConfigEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub configured: bool,
    pub unlocked: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    pub distro: Option<String>,
    pub package_manager: Option<String>,
    pub init_system: Option<String>,
    pub systemd: bool,
    pub docker: bool,
    pub podman: bool,
    pub sudo: bool,
    pub network_tool: Option<String>,
    pub journalctl: bool,
    pub logread: bool,
    pub cron: bool,
    pub architecture: String,
    pub coreutils_variant: String,
    pub root: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSummary {
    pub server_id: String,
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub architecture: String,
    pub capabilities: ServerCapabilities,
    pub connected_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConnection {
    pub server_id: String,
    pub connected_at: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MemoryStats {
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SwapStats {
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskUsage {
    pub mount: String,
    pub filesystem: String,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum DashboardCard {
    Profile {
        summary: ConnectionSummary,
    },
    Cpu {
        cpu_percent: f64,
        cpu_cores: u32,
        cpu_model: String,
    },
    Memory {
        memory: MemoryStats,
        swap: SwapStats,
    },
    Storage {
        disks: Vec<DiskUsage>,
    },
    Uptime {
        uptime_seconds: u64,
        load_averages: [f64; 3],
    },
    Network {
        interfaces: Vec<NetworkInterface>,
    },
}

/// One bounded snapshot for the Disk workspace: mount overview (including
/// inode pressure), the largest files and directories found in common
/// high-consumption roots, and Docker disk usage when a usable runtime exists.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiskExplorerSnapshot {
    pub mounts: Vec<DiskMount>,
    pub largest_files: Vec<LargestFile>,
    pub largest_dirs: Vec<LargestDirectory>,
    pub docker_usage: Option<DockerDiskUsage>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiskMount {
    pub mount: String,
    pub filesystem: String,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub percent: f64,
    /// Inode figures are populated only when `df -i` succeeded per device;
    /// many network and virtual filesystems do not report them.
    pub inode_used: Option<u64>,
    pub inode_total: Option<u64>,
    pub inode_percent: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LargestFile {
    pub path: String,
    pub size_bytes: u64,
    /// Unix epoch seconds; absent on fallback paths without GNU find or stat.
    pub modified_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LargestDirectory {
    pub path: String,
    pub size_bytes: u64,
    /// Number of path components below root (`/var/log` is depth 1).
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DockerDiskUsage {
    pub images_bytes: u64,
    pub containers_bytes: u64,
    pub volumes_bytes: u64,
    pub build_cache_bytes: u64,
    /// Sizes reported under any other type so the total stays consistent.
    pub other_bytes: u64,
    pub total_bytes: u64,
    pub reclaimable_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub user: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub rss_bytes: u64,
    pub runtime_seconds: u64,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub items: Vec<T>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub name: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDetails {
    pub name: String,
    pub properties: Vec<(String, String)>,
    pub journal: String,
    pub unit_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteFile {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub modified_at: Option<i64>,
    pub permissions: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub hidden: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemotePathRequest {
    pub path: String,
    #[serde(default)]
    pub show_hidden: bool,
    #[serde(default)]
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub transfer_id: String,
    pub direction: String,
    pub path: String,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub completed_files: u64,
    pub total_files: u64,
    pub done: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub ports: String,
    pub cpu_percent: Option<f64>,
    pub memory_usage_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub memory_percent: Option<f64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub block_read_bytes: Option<u64>,
    pub block_write_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerVolume {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerNetwork {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerPage {
    pub runtime: String,
    pub section: String,
    pub containers: Vec<ContainerInfo>,
    pub images: Vec<DockerImage>,
    pub volumes: Vec<DockerVolume>,
    pub networks: Vec<DockerNetwork>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerExec {
    pub command: String,
    pub shell: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCreateInput {
    pub image: String,
    pub name: Option<String>,
    pub command: Option<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub environment: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    pub restart_policy: Option<String>,
    #[serde(default)]
    pub detached: bool,
    #[serde(default)]
    pub remove_on_exit: bool,
    pub memory_limit: Option<String>,
    pub cpu_limit: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortInfo {
    pub protocol: String,
    pub state: String,
    pub local_address: String,
    pub remote_address: String,
    pub process: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsRequest {
    pub source: String,
    pub service: Option<String>,
    pub container: Option<String>,
    pub compose_path: Option<String>,
    pub file_path: Option<String>,
    pub lines: u32,
    pub since: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogStreamRequest {
    pub session_id: String,
    pub server_id: String,
    pub logs: LogsRequest,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogStreamStarted {
    pub session_id: String,
    pub server_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogStreamEvent {
    pub session_id: String,
    pub data: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalRequest {
    pub session_id: String,
    pub server_id: String,
    pub cols: u32,
    pub rows: u32,
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalStarted {
    pub session_id: String,
    pub server_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalResize {
    pub session_id: String,
    pub cols: u32,
    pub rows: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalEvent {
    pub session_id: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CronJob {
    pub id: String,
    pub source: String,
    pub user: String,
    pub schedule: String,
    pub command: String,
    pub enabled: bool,
    pub human_schedule: String,
    pub next_run: Option<String>,
    pub editable: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronJobInput {
    pub id: Option<String>,
    pub schedule: String,
    pub command: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub description: String,
    pub installed: bool,
    pub upgrade_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePage {
    pub manager: String,
    pub packages: Page<PackageInfo>,
    pub pending_upgrades: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub groups: Vec<String>,
    pub last_login: Option<String>,
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxGroup {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSnapshot {
    pub users: Vec<LinuxUser>,
    pub groups: Vec<LinuxGroup>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCreateInput {
    pub name: String,
    pub home: Option<String>,
    pub shell: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub password: Option<String>,
}

impl Drop for UserCreateInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposeProject {
    pub name: String,
    pub path: String,
    pub services: Vec<String>,
    pub running: usize,
    pub topology: Vec<String>,
    pub environment: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallSnapshot {
    pub provider: Option<String>,
    pub enabled: bool,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedKey {
    pub id: String,
    pub kind: String,
    pub fingerprint: String,
    pub comment: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySnapshot {
    pub updates: usize,
    pub security_updates: usize,
    pub reboot_required: bool,
    pub last_package_update: Option<String>,
    pub kernel_version: String,
    pub container_version: Option<String>,
    pub container_update_available: bool,
    pub package_updates_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedCommand {
    pub id: String,
    pub server_id: Option<String>,
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedCommandInput {
    pub id: Option<String>,
    pub server_id: Option<String>,
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelConfig {
    pub id: String,
    pub server_id: String,
    pub name: String,
    pub kind: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInput {
    pub id: Option<String>,
    pub server_id: String,
    pub name: String,
    pub kind: String,
    pub bind_host: String,
    pub bind_port: u32,
    pub target_host: String,
    pub target_port: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    pub id: String,
    pub running: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandResult {
    pub server_id: String,
    pub server_name: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub error: Option<String>,
}
