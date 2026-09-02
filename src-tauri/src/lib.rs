mod credentials;
mod disk;
mod log_stream;
mod models;
mod providers;
mod ssh;
mod storage;
mod terminal;
mod tier3;
mod tunnels;

use log_stream::LogSessions;
use models::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{
    AppHandle, Manager, PhysicalPosition, PhysicalRect, PhysicalSize, Runtime, State, WebviewWindow,
};
use terminal::TerminalSessions;
use zeroize::Zeroizing;

/// Structured error payloads serialized over the Tauri IPC boundary. Control
/// flow (credential prompts, host-key review) is expressed as a typed `kind`
/// instead of prose prefixes the frontend has to scrape out of strings —
/// remote output can never forge one of these variants.
#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum AppError {
    Message {
        message: String,
    },
    MasterPasswordRequired {
        message: String,
    },
    MasterPasswordSetupRequired {
        message: String,
    },
    MasterPasswordInvalid {
        message: String,
    },
    HostKeyMismatch {
        host: String,
        port: u16,
        key_type: String,
        old_fingerprints: Vec<String>,
        new_fingerprint: String,
    },
    HostKeyUnknown {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
    },
    UploadConflict {
        paths: Vec<String>,
        count: usize,
    },
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostKeyMismatchPayload {
    host: String,
    port: u16,
    key_type: String,
    #[serde(default)]
    old_fingerprints: Vec<String>,
    new_fingerprint: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostKeyUnknownPayload {
    host: String,
    port: u16,
    key_type: String,
    fingerprint: String,
}

#[derive(serde::Deserialize)]
struct UploadConflictPayload {
    paths: Vec<String>,
    count: usize,
}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        if let Some(payload) = value.strip_prefix("HOST_KEY_MISMATCH:") {
            if let Ok(parsed) = serde_json::from_str::<HostKeyMismatchPayload>(payload) {
                return AppError::HostKeyMismatch {
                    host: parsed.host,
                    port: parsed.port,
                    key_type: parsed.key_type,
                    old_fingerprints: parsed.old_fingerprints,
                    new_fingerprint: parsed.new_fingerprint,
                };
            }
        }
        if let Some(payload) = value.strip_prefix("HOST_KEY_UNKNOWN:") {
            if let Ok(parsed) = serde_json::from_str::<HostKeyUnknownPayload>(payload) {
                return AppError::HostKeyUnknown {
                    host: parsed.host,
                    port: parsed.port,
                    key_type: parsed.key_type,
                    fingerprint: parsed.fingerprint,
                };
            }
        }
        if let Some(payload) = value.strip_prefix("UPLOAD_CONFLICT:") {
            if let Ok(parsed) = serde_json::from_str::<UploadConflictPayload>(payload) {
                return AppError::UploadConflict {
                    paths: parsed.paths,
                    count: parsed.count,
                };
            }
        }
        const MARKERS: [(&str, fn(String) -> AppError); 3] = [
            ("MASTER_PASSWORD_SETUP_REQUIRED:", |message| {
                AppError::MasterPasswordSetupRequired { message }
            }),
            ("MASTER_PASSWORD_REQUIRED:", |message| {
                AppError::MasterPasswordRequired { message }
            }),
            ("MASTER_PASSWORD_INVALID:", |message| {
                AppError::MasterPasswordInvalid { message }
            }),
        ];
        for (marker, build) in MARKERS {
            if let Some(rest) = value.strip_prefix(marker) {
                return build(rest.trim().to_string());
            }
        }
        AppError::Message { message: value }
    }
}

impl From<&str> for AppError {
    fn from(value: &str) -> Self {
        AppError::from(value.to_string())
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: storage::Store,
    pub terminals: TerminalSessions,
    pub log_streams: LogSessions,
}

impl AppState {
    fn open(data_path: PathBuf) -> Result<Self, String> {
        Ok(Self {
            store: storage::Store::open(
                &data_path.join("serverbox.sqlite3"),
                &data_path.join("serverbox.credentials"),
            )?,
            terminals: Arc::new(Mutex::new(HashMap::new())),
            log_streams: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

#[tauri::command(async)]
fn get_credential_status(state: State<'_, AppState>) -> CredentialStatus {
    state.store.credential_status()
}

#[tauri::command(async)]
fn unlock_credentials(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<CredentialStatus, AppError> {
    let master_password = Zeroizing::new(master_password);
    Ok(state.store.unlock_credentials(master_password.as_str())?)
}

#[tauri::command(async)]
fn change_master_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> Result<CredentialStatus, AppError> {
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);
    tunnels::stop_all();
    log_stream::close_all(&state.log_streams);
    terminal::close_all(&state.terminals);
    ssh::disconnect_all();
    Ok(state
        .store
        .change_master_password(current_password.as_str(), new_password.as_str())?)
}

#[tauri::command(async)]
fn reset_credentials(state: State<'_, AppState>, master_password: String) -> Result<(), AppError> {
    let master_password = Zeroizing::new(master_password);
    tunnels::stop_all();
    log_stream::close_all(&state.log_streams);
    terminal::close_all(&state.terminals);
    ssh::disconnect_all();
    Ok(state.store.reset_credentials(master_password.as_str())?)
}

#[tauri::command(async)]
fn get_state(state: State<'_, AppState>) -> Result<AppStateSnapshot, AppError> {
    let (ssh_keys, ssh_config_entries) = scan_ssh_material()?;
    Ok(AppStateSnapshot {
        version: APP_VERSION,
        servers: state.store.list_servers()?,
        ssh_keys,
        ssh_config_entries,
    })
}

#[tauri::command(async)]
fn save_server(
    state: State<'_, AppState>,
    draft: ServerDraft,
) -> Result<ServerSaveResult, AppError> {
    let credentials_changed = draft.password.is_some() || draft.key_passphrase.is_some();
    let previous = draft
        .id
        .as_deref()
        .and_then(|id| state.store.get_server(id).ok());
    let saved = state.store.save_server(&draft)?;
    // Connectivity changes invalidate this server and every profile routed
    // through it. Metadata-only edits must not disturb unrelated activity.
    let changed = credentials_changed
        || !previous
            .as_ref()
            .is_some_and(|old| ssh::profile_key(old) == ssh::profile_key(&saved));
    let invalidated_server_ids = if changed {
        let affected = affected_server_ids(&state.store, &saved.id)?;
        close_server_activity(&state, &affected)?;
        affected
    } else {
        Vec::new()
    };
    Ok(ServerSaveResult {
        server: saved,
        invalidated_server_ids,
    })
}

#[tauri::command(async)]
fn rename_server(
    state: State<'_, AppState>,
    server_id: String,
    name: String,
) -> Result<ServerProfile, AppError> {
    Ok(state.store.rename_server(&server_id, &name)?)
}

#[tauri::command(async)]
fn delete_server(state: State<'_, AppState>, server_id: String) -> Result<(), AppError> {
    let affected = affected_server_ids(&state.store, &server_id)?;
    close_server_activity(&state, &affected)?;
    state.store.delete_server(&server_id)?;
    Ok(())
}

fn affected_server_ids(
    store: &storage::Store,
    changed_server_id: &str,
) -> Result<Vec<String>, AppError> {
    let profiles = store.list_servers()?;
    let mut affected = HashSet::from([changed_server_id.to_string()]);
    loop {
        let mut added = false;
        for profile in &profiles {
            if !affected.contains(&profile.id)
                && profile
                    .jump_host_id
                    .as_ref()
                    .is_some_and(|jump_id| affected.contains(jump_id))
            {
                affected.insert(profile.id.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    let mut affected = affected.into_iter().collect::<Vec<_>>();
    affected.sort_unstable();
    Ok(affected)
}

fn close_server_activity(state: &AppState, server_ids: &[String]) -> Result<(), AppError> {
    for server_id in server_ids {
        for tunnel in state.store.list_tunnels(server_id)? {
            tunnels::stop(&tunnel.id)?;
        }
        log_stream::close_server(&state.log_streams, server_id);
        terminal::close_server(&state.terminals, server_id);
        ssh::disconnect_server(server_id)?;
    }
    Ok(())
}

#[tauri::command(async)]
fn duplicate_server(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<ServerProfile, AppError> {
    Ok(state.store.duplicate_server(&server_id)?)
}

#[tauri::command(async)]
fn get_cron_jobs(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<Vec<CronJob>, AppError> {
    Ok(providers::cron_jobs(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn save_cron_job(
    state: State<'_, AppState>,
    server_id: String,
    input: CronJobInput,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::save_cron_job(
        &state.store,
        &server_id,
        &input,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn cron_action(
    state: State<'_, AppState>,
    server_id: String,
    id: String,
    action: String,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::cron_action(
        &state.store,
        &server_id,
        &id,
        &action,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_packages(
    state: State<'_, AppState>,
    server_id: String,
    query: String,
    upgrades_only: bool,
    offset: usize,
    limit: usize,
    operation_id: Option<String>,
) -> Result<PackagePage, AppError> {
    Ok(providers::packages(
        &state.store,
        &server_id,
        &query,
        upgrades_only,
        offset,
        limit,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_package_details(
    state: State<'_, AppState>,
    server_id: String,
    name: String,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::package_details(
        &state.store,
        &server_id,
        &name,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn package_action(
    state: State<'_, AppState>,
    server_id: String,
    action: String,
    name: Option<String>,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::package_action(
        &state.store,
        &server_id,
        &action,
        name.as_deref(),
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_accounts(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<AccountSnapshot, AppError> {
    Ok(providers::accounts(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn create_user(
    state: State<'_, AppState>,
    server_id: String,
    input: UserCreateInput,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::create_user(
        &state.store,
        &server_id,
        &input,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn account_action(
    state: State<'_, AppState>,
    server_id: String,
    action: String,
    name: String,
    value: Option<String>,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::account_action(
        &state.store,
        &server_id,
        &action,
        &name,
        value.as_deref(),
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn reset_user_password(
    state: State<'_, AppState>,
    server_id: String,
    name: String,
    password: String,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    let password = Zeroizing::new(password);
    Ok(providers::reset_user_password(
        &state.store,
        &server_id,
        &name,
        password.as_str(),
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_compose_projects(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<Vec<ComposeProject>, AppError> {
    Ok(tier3::compose_projects(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn compose_action(
    state: State<'_, AppState>,
    server_id: String,
    path: String,
    action: String,
    service: Option<String>,
    command: Option<String>,
    operation_id: Option<String>,
    lines: Option<u32>,
    since: Option<String>,
) -> Result<String, AppError> {
    Ok(tier3::compose_action(
        &state.store,
        &server_id,
        &path,
        &action,
        service.as_deref(),
        command.as_deref(),
        operation_id.as_deref(),
        lines,
        since.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_firewall(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<FirewallSnapshot, AppError> {
    Ok(tier3::firewall(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn firewall_action(
    state: State<'_, AppState>,
    server_id: String,
    action: String,
    port: Option<u32>,
    protocol: Option<String>,
    source: Option<String>,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(tier3::firewall_action(
        &state.store,
        &server_id,
        &action,
        port,
        protocol.as_deref(),
        source.as_deref(),
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_authorized_keys(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<Vec<AuthorizedKey>, AppError> {
    Ok(tier3::authorized_keys(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn authorized_key_action(
    state: State<'_, AppState>,
    server_id: String,
    action: String,
    key: String,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(tier3::authorized_key_action(
        &state.store,
        &server_id,
        &action,
        &key,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_security_snapshot(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<SecuritySnapshot, AppError> {
    Ok(tier3::security(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn run_quick_action(
    state: State<'_, AppState>,
    server_id: String,
    action: String,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(tier3::quick_action(
        &state.store,
        &server_id,
        &action,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_saved_commands(
    state: State<'_, AppState>,
    server_id: Option<String>,
) -> Result<Vec<SavedCommand>, AppError> {
    Ok(state.store.list_saved_commands(server_id.as_deref())?)
}

#[tauri::command(async)]
fn save_saved_command(
    state: State<'_, AppState>,
    input: SavedCommandInput,
) -> Result<SavedCommand, AppError> {
    Ok(state.store.save_saved_command(&input)?)
}

#[tauri::command(async)]
fn delete_saved_command(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    Ok(state.store.delete_saved_command(&id)?)
}

#[tauri::command(async)]
fn run_saved_command(
    state: State<'_, AppState>,
    server_id: String,
    command: String,
    operation_id: Option<String>,
) -> Result<CommandResult, AppError> {
    Ok(tier3::run_command(
        &state.store,
        &server_id,
        &command,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_tunnels(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<TunnelConfig>, AppError> {
    Ok(state.store.list_tunnels(&server_id)?)
}

#[tauri::command(async)]
fn save_tunnel(state: State<'_, AppState>, input: TunnelInput) -> Result<TunnelConfig, AppError> {
    Ok(state.store.save_tunnel(&input)?)
}

#[tauri::command(async)]
fn delete_tunnel(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    Ok(state.store.delete_tunnel(&id)?)
}

#[tauri::command(async)]
fn get_tunnel_statuses(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<TunnelStatus>, AppError> {
    let ids = state
        .store
        .list_tunnels(&server_id)?
        .into_iter()
        .map(|tunnel| tunnel.id)
        .collect::<Vec<_>>();
    Ok(tunnels::statuses(&ids))
}

#[tauri::command(async)]
fn start_tunnel(state: State<'_, AppState>, id: String) -> Result<TunnelStatus, AppError> {
    let tunnel = state.store.get_tunnel(&id)?;
    Ok(tunnels::start(state.store.clone(), tunnel)?)
}

#[tauri::command(async)]
fn stop_tunnel(id: String) -> Result<(), AppError> {
    Ok(tunnels::stop(&id)?)
}

#[tauri::command(async)]
fn connect_server(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<ServerConnection, AppError> {
    Ok(providers::connect(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn replace_host_key(
    state: State<'_, AppState>,
    server_id: String,
    expected_host: String,
    expected_port: u16,
    expected_fingerprint: String,
) -> Result<(), AppError> {
    Ok(ssh::replace_host_key(
        &state.store,
        &server_id,
        &expected_host,
        expected_port,
        &expected_fingerprint,
    )?)
}

#[tauri::command(async)]
fn accept_host_key(
    state: State<'_, AppState>,
    server_id: String,
    expected_host: String,
    expected_port: u16,
    expected_fingerprint: String,
) -> Result<(), AppError> {
    Ok(ssh::accept_host_key(
        &state.store,
        &server_id,
        &expected_host,
        expected_port,
        &expected_fingerprint,
    )?)
}

#[tauri::command(async)]
fn get_dashboard(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<Vec<DashboardCard>, AppError> {
    Ok(providers::dashboard(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_disk_snapshot(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<DiskExplorerSnapshot, AppError> {
    Ok(disk::disk_snapshot(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_disk_varlog(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<Vec<LargestDirectory>, AppError> {
    Ok(disk::varlog_usage(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_processes(
    state: State<'_, AppState>,
    server_id: String,
    offset: usize,
    limit: usize,
    operation_id: Option<String>,
) -> Result<Page<ProcessInfo>, AppError> {
    Ok(providers::processes(
        &state.store,
        &server_id,
        offset,
        limit,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn signal_process(
    state: State<'_, AppState>,
    server_id: String,
    pid: u32,
    force: bool,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::signal_process(
        &state.store,
        &server_id,
        pid,
        force,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_services(
    state: State<'_, AppState>,
    server_id: String,
    offset: usize,
    limit: usize,
    operation_id: Option<String>,
) -> Result<Page<ServiceInfo>, AppError> {
    Ok(providers::services(
        &state.store,
        &server_id,
        offset,
        limit,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_service_details(
    state: State<'_, AppState>,
    server_id: String,
    service: String,
    operation_id: Option<String>,
) -> Result<ServiceDetails, AppError> {
    Ok(providers::service_details(
        &state.store,
        &server_id,
        &service,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn service_action(
    state: State<'_, AppState>,
    server_id: String,
    service: String,
    action: String,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::service_action(
        &state.store,
        &server_id,
        &service,
        &action,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_docker(
    state: State<'_, AppState>,
    server_id: String,
    section: String,
    offset: usize,
    limit: usize,
    operation_id: Option<String>,
) -> Result<DockerPage, AppError> {
    Ok(providers::docker_snapshot(
        &state.store,
        &server_id,
        &section,
        offset,
        limit,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn docker_action(
    state: State<'_, AppState>,
    server_id: String,
    action: String,
    target: String,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::docker_action(
        &state.store,
        &server_id,
        &action,
        &target,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn container_exec(
    state: State<'_, AppState>,
    server_id: String,
    container: String,
    operation_id: Option<String>,
) -> Result<ContainerExec, AppError> {
    Ok(providers::container_exec(
        &state.store,
        &server_id,
        &container,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn docker_logs(
    state: State<'_, AppState>,
    server_id: String,
    container: String,
    lines: u32,
    since: Option<String>,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::docker_logs(
        &state.store,
        &server_id,
        &container,
        lines,
        since.as_deref(),
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn docker_inspect(
    state: State<'_, AppState>,
    server_id: String,
    target: String,
    kind: String,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::docker_inspect(
        &state.store,
        &server_id,
        &target,
        &kind,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn docker_pull(
    state: State<'_, AppState>,
    server_id: String,
    image: String,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::docker_pull(
        &state.store,
        &server_id,
        &image,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn docker_create(
    state: State<'_, AppState>,
    server_id: String,
    input: DockerCreateInput,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::docker_create(
        &state.store,
        &server_id,
        &input,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_logs(
    state: State<'_, AppState>,
    server_id: String,
    request: LogsRequest,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::logs(
        &state.store,
        &server_id,
        &request,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn get_log_files(
    state: State<'_, AppState>,
    server_id: String,
    operation_id: Option<String>,
) -> Result<Vec<String>, AppError> {
    Ok(providers::log_files(
        &state.store,
        &server_id,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn start_log_stream(
    app: AppHandle,
    state: State<'_, AppState>,
    request: LogStreamRequest,
) -> Result<LogStreamStarted, AppError> {
    Ok(log_stream::start(
        app,
        state.store.clone(),
        state.log_streams.clone(),
        request,
    )?)
}

#[tauri::command]
fn close_log_stream(state: State<'_, AppState>, session_id: String) -> Result<(), AppError> {
    Ok(log_stream::close(&state.log_streams, &session_id)?)
}

#[tauri::command(async)]
fn get_ports(
    state: State<'_, AppState>,
    server_id: String,
    offset: usize,
    limit: usize,
    operation_id: Option<String>,
) -> Result<Page<PortInfo>, AppError> {
    Ok(providers::ports(
        &state.store,
        &server_id,
        offset,
        limit,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn list_remote_files(
    state: State<'_, AppState>,
    server_id: String,
    request: RemotePathRequest,
    operation_id: Option<String>,
) -> Result<Page<RemoteFile>, AppError> {
    Ok(providers::list_files(
        &state.store,
        &server_id,
        &request,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn read_remote_file(
    state: State<'_, AppState>,
    server_id: String,
    path: String,
    operation_id: Option<String>,
) -> Result<String, AppError> {
    Ok(providers::read_file(
        &state.store,
        &server_id,
        &path,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn write_remote_file(
    state: State<'_, AppState>,
    server_id: String,
    path: String,
    content: String,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::write_file(
        &state.store,
        &server_id,
        &path,
        &content,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn remote_file_action(
    state: State<'_, AppState>,
    server_id: String,
    action: String,
    path: String,
    target: Option<String>,
    mode: Option<String>,
    operation_id: Option<String>,
) -> Result<(), AppError> {
    Ok(providers::file_action(
        &state.store,
        &server_id,
        &action,
        &path,
        target,
        mode,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn upload_path(
    app: AppHandle,
    state: State<'_, AppState>,
    server_id: String,
    local_path: String,
    remote_path: String,
    overwrite: bool,
    operation_id: Option<String>,
) -> Result<TransferProgress, AppError> {
    Ok(providers::upload_path(
        &state.store,
        &server_id,
        &local_path,
        &remote_path,
        overwrite,
        app,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn download_path(
    app: AppHandle,
    state: State<'_, AppState>,
    server_id: String,
    remote_path: String,
    local_path: String,
    operation_id: Option<String>,
) -> Result<TransferProgress, AppError> {
    Ok(providers::download_path(
        &state.store,
        &server_id,
        &remote_path,
        &local_path,
        app,
        operation_id.as_deref(),
    )?)
}

#[tauri::command(async)]
fn cancel_operation(operation_id: String) -> Result<(), AppError> {
    Ok(ssh::cancel_operation(&operation_id)?)
}

#[tauri::command(async)]
fn disconnect_server(state: State<'_, AppState>, server_id: String) -> Result<(), AppError> {
    // Explicit disconnect also closes independent forwarding sessions for this profile.
    // Tunnel definitions remain saved and can be started again later.
    for tunnel in state.store.list_tunnels(&server_id)? {
        tunnels::stop(&tunnel.id)?;
    }
    log_stream::close_server(&state.log_streams, &server_id);
    terminal::close_server(&state.terminals, &server_id);
    Ok(ssh::disconnect_server(&server_id)?)
}

#[tauri::command(async)]
fn start_terminal(
    app: AppHandle,
    state: State<'_, AppState>,
    request: TerminalRequest,
    operation_id: Option<String>,
) -> Result<TerminalStarted, AppError> {
    Ok(terminal::start(
        app,
        state.store.clone(),
        state.terminals.clone(),
        request,
        operation_id.as_deref(),
    )?)
}

#[tauri::command]
fn terminal_input(
    state: State<'_, AppState>,
    session_id: String,
    data: String,
) -> Result<(), AppError> {
    Ok(terminal::input(&state.terminals, &session_id, data)?)
}

#[tauri::command]
fn terminal_resize(state: State<'_, AppState>, request: TerminalResize) -> Result<(), AppError> {
    Ok(terminal::resize(&state.terminals, request)?)
}

#[tauri::command]
fn close_terminal(state: State<'_, AppState>, session_id: String) -> Result<(), AppError> {
    Ok(terminal::close(&state.terminals, &session_id)?)
}

fn scan_ssh_material() -> Result<(Vec<SshKey>, Vec<SshConfigEntry>), String> {
    let Some(home) = dirs::home_dir() else {
        return Ok((Vec::new(), Vec::new()));
    };
    let ssh_dir = home.join(".ssh");
    let mut keys = Vec::new();
    if let Ok(entries) = fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file()
                || path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| {
                        name.ends_with(".pub")
                            || ["config", "known_hosts", "authorized_keys"].contains(&name)
                    })
            {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            let key_like =
                name.starts_with("id_") || name.ends_with(".pem") || name.ends_with(".key");
            if key_like {
                keys.push(SshKey {
                    path: path.to_string_lossy().to_string(),
                    name: name.to_string(),
                    kind: if name.starts_with("id_ed25519") {
                        "Ed25519"
                    } else if name.starts_with("id_rsa") {
                        "RSA"
                    } else if name.starts_with("id_ecdsa") {
                        "ECDSA"
                    } else {
                        "Private key"
                    }
                    .to_string(),
                    size_bytes: metadata.len(),
                });
            }
        }
    }
    keys.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((keys, parse_ssh_config(&ssh_dir.join("config"))))
}

fn parse_ssh_config(path: &std::path::Path) -> Vec<SshConfigEntry> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut aliases: Vec<String> = Vec::new();
    let mut host: Option<String> = None;
    let mut username: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut key_path: Option<String> = None;
    let mut entries = Vec::new();
    let flush = |entries: &mut Vec<SshConfigEntry>,
                 aliases: &mut Vec<String>,
                 host: &mut Option<String>,
                 username: &mut Option<String>,
                 port: &mut Option<u16>,
                 key_path: &mut Option<String>| {
        for alias in aliases.drain(..) {
            if alias.contains('*') || alias.contains('?') || alias.starts_with('!') {
                continue;
            }
            entries.push(SshConfigEntry {
                alias,
                host: host.clone(),
                username: username.clone(),
                port: *port,
                key_path: key_path.clone().map(|value| ssh_config_path(&value)),
            });
        }
        *host = None;
        *username = None;
        *port = None;
        *key_path = None;
    };
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        let value = fields.collect::<Vec<_>>().join(" ");
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                flush(
                    &mut entries,
                    &mut aliases,
                    &mut host,
                    &mut username,
                    &mut port,
                    &mut key_path,
                );
                aliases = value.split_whitespace().map(str::to_string).collect();
            }
            "hostname" => host = Some(value),
            "user" => username = Some(value),
            "port" => port = value.parse().ok(),
            "identityfile" => key_path = Some(value),
            _ => {}
        }
    }
    flush(
        &mut entries,
        &mut aliases,
        &mut host,
        &mut username,
        &mut port,
        &mut key_path,
    );
    entries.sort_by(|left, right| left.alias.cmp(&right.alias));
    entries
}

fn ssh_config_path(value: &str) -> String {
    if value.starts_with("~/") {
        dirs::home_dir()
            .map(|home| home.join(&value[2..]).to_string_lossy().to_string())
            .unwrap_or_else(|| value.to_string())
    } else {
        value.to_string()
    }
}

#[derive(Clone, Copy)]
struct WindowGeometry {
    position: PhysicalPosition<i32>,
    size: PhysicalSize<u32>,
}

fn clamp_position(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

fn constrained_window_geometry(
    geometry: WindowGeometry,
    work_area: PhysicalRect<i32, u32>,
    center: bool,
) -> WindowGeometry {
    let width = geometry.size.width.min(work_area.size.width.max(1));
    let height = geometry.size.height.min(work_area.size.height.max(1));
    let work_left = i64::from(work_area.position.x);
    let work_top = i64::from(work_area.position.y);
    let work_right = work_left + i64::from(work_area.size.width);
    let work_bottom = work_top + i64::from(work_area.size.height);
    let max_left = work_right - i64::from(width);
    let max_top = work_bottom - i64::from(height);
    let x = if center {
        work_left + (i64::from(work_area.size.width) - i64::from(width)) / 2
    } else {
        i64::from(geometry.position.x).clamp(work_left, max_left)
    };
    let y = if center {
        work_top + (i64::from(work_area.size.height) - i64::from(height)) / 2
    } else {
        i64::from(geometry.position.y).clamp(work_top, max_top)
    };

    WindowGeometry {
        position: PhysicalPosition::new(clamp_position(x), clamp_position(y)),
        size: PhysicalSize::new(width, height),
    }
}

fn monitor_for_window<R: Runtime>(window: &WebviewWindow<R>) -> Option<tauri::Monitor> {
    window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| window.primary_monitor().ok().flatten())
        .or_else(|| {
            window
                .available_monitors()
                .ok()
                .and_then(|monitors| monitors.into_iter().next())
        })
}

fn fit_initial_window_to_work_area<R: Runtime>(window: &WebviewWindow<R>) {
    let Some(monitor) = monitor_for_window(window) else {
        return;
    };
    let work_area = *monitor.work_area();
    let Ok(inner_size) = window.inner_size() else {
        return;
    };
    let Ok(outer_size) = window.outer_size() else {
        return;
    };
    let horizontal_chrome = outer_size.width.saturating_sub(inner_size.width);
    let vertical_chrome = outer_size.height.saturating_sub(inner_size.height);
    let position = window
        .outer_position()
        .unwrap_or_else(|_| PhysicalPosition::new(work_area.position.x, work_area.position.y));
    let constrained = constrained_window_geometry(
        WindowGeometry {
            position,
            size: outer_size,
        },
        work_area,
        true,
    );
    let target_inner_size = PhysicalSize::new(
        constrained
            .size
            .width
            .saturating_sub(horizontal_chrome)
            .max(1),
        constrained
            .size
            .height
            .saturating_sub(vertical_chrome)
            .max(1),
    );
    if target_inner_size != inner_size {
        let _ = window.set_size(target_inner_size);
    }

    let Ok(final_outer_size) = window.outer_size() else {
        return;
    };
    let Ok(final_position) = window.outer_position() else {
        return;
    };
    let final_geometry = constrained_window_geometry(
        WindowGeometry {
            position: final_position,
            size: final_outer_size,
        },
        work_area,
        true,
    );
    if final_geometry.position != final_position {
        let _ = window.set_position(final_geometry.position);
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            let state = AppState::open(data_dir).map_err(std::io::Error::other)?;
            app.manage(state);
            if let Some(window) = app.get_webview_window("main") {
                fit_initial_window_to_work_area(&window);
                window.show()?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_credential_status,
            unlock_credentials,
            change_master_password,
            reset_credentials,
            get_state,
            save_server,
            rename_server,
            delete_server,
            duplicate_server,
            cancel_operation,
            disconnect_server,
            connect_server,
            replace_host_key,
            accept_host_key,
            get_dashboard,
            get_disk_snapshot,
            get_disk_varlog,
            get_processes,
            signal_process,
            get_services,
            get_service_details,
            service_action,
            get_cron_jobs,
            save_cron_job,
            cron_action,
            get_packages,
            get_package_details,
            package_action,
            get_accounts,
            create_user,
            account_action,
            reset_user_password,
            get_compose_projects,
            compose_action,
            get_firewall,
            firewall_action,
            get_authorized_keys,
            authorized_key_action,
            get_security_snapshot,
            run_quick_action,
            get_saved_commands,
            save_saved_command,
            delete_saved_command,
            run_saved_command,
            get_tunnels,
            save_tunnel,
            delete_tunnel,
            get_tunnel_statuses,
            start_tunnel,
            stop_tunnel,
            get_docker,
            docker_action,
            container_exec,
            docker_logs,
            docker_inspect,
            docker_pull,
            docker_create,
            get_logs,
            get_log_files,
            start_log_stream,
            close_log_stream,
            get_ports,
            list_remote_files,
            read_remote_file,
            write_remote_file,
            remote_file_action,
            upload_path,
            download_path,
            start_terminal,
            terminal_input,
            terminal_resize,
            close_terminal
        ])
        .run(tauri::generate_context!())
        .expect("error while running Serverbox application");
}
