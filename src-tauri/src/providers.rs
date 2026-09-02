use crate::models::*;
use crate::ssh::{
    bounded_output, command_error, detect_capabilities, ensure_not_cancelled, execute_privileged,
    execute_privileged_bounded, execute_privileged_long, execute_privileged_posix_script_bounded,
    execute_privileged_with_input, is_permission_error, is_permission_message,
    parse_capabilities_probe, quote_shell, with_client, MAX_LOG_OUTPUT_BYTES,
};
use crate::storage::Store;
use chrono::Utc;
use cron::Schedule;
use serde_json::Value;
use ssh2::{ErrorCode, FileStat, RenameFlags};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use uuid::Uuid;
use walkdir::WalkDir;
use zeroize::Zeroizing;

const MAX_PAGE_SIZE: usize = 5_000;
const MAX_OVERVIEW_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_DOCKER_PAGE_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RUNTIME_PROBE_OUTPUT_BYTES: usize = 64 * 1024;
const RUNTIME_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const OVERVIEW_SECTION_MARKER: &str = "__SERVERBOX_OVERVIEW_V1__";
const DOCKER_ITEMS_MARKER: &str = "__SERVERBOX_DOCKER_ITEMS_V1__";
const DOCKER_STATS_MARKER: &str = "__SERVERBOX_DOCKER_STATS_V1__";
const OVERVIEW_SCRIPT: &str = r#"
marker() { printf '\n__SERVERBOX_OVERVIEW_V1__%s\n' "$1"; }

cpu_before=$(awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8,$9; exit}' /proc/stat 2>/dev/null)

marker profile
hostname_value=$(hostname 2>/dev/null || uname -n 2>/dev/null)
kernel_value=$(uname -r 2>/dev/null)
printf 'hostname\t%s\n' "${hostname_value:-unknown}"
printf 'kernel\t%s\n' "${kernel_value:-unknown}"

marker capabilities
printf 'distro\t'
os_release=
if [ -r /etc/os-release ]; then os_release=/etc/os-release
elif [ -r /usr/lib/os-release ]; then os_release=/usr/lib/os-release
fi
if [ -n "$os_release" ]; then
  . "$os_release"
  printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}"
else
  uname -s 2>/dev/null || printf Linux
fi
printf '\narchitecture\t'
uname -m 2>/dev/null || printf unknown
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  printf 'command\tsystemctl\n'
fi
for name in docker podman sudo ss netstat journalctl crontab; do
  if command -v "$name" >/dev/null 2>&1; then printf 'command\t%s\n' "$name"; fi
done
printf 'root\t'
if [ "$(id -u 2>/dev/null)" = 0 ]; then printf true; else printf false; fi
printf '\nlogread\t'
if command -v logread >/dev/null 2>&1 && logread -l 1 >/dev/null 2>&1; then printf true; else printf false; fi
printf '\ncoreutils\t'
case "$(ls --version 2>/dev/null | sed -n '1p')" in
  *'GNU coreutils'*) printf GNU ;;
  *) if command -v busybox >/dev/null 2>&1; then printf BusyBox; else printf POSIX/other; fi ;;
esac
printf '\npackageManager\t'
for name in apt-get dnf yum zypper pacman apk; do
  if command -v "$name" >/dev/null 2>&1; then printf '%s' "$name"; break; fi
done
printf '\n'

marker memory
cat /proc/meminfo 2>/dev/null || true

marker storage
df -Pk 2>/dev/null || df -kP 2>/dev/null || true

marker uptime
awk '{print int($1); exit}' /proc/uptime 2>/dev/null || printf '0\n'
cat /proc/loadavg 2>/dev/null || printf '0 0 0\n'

marker network
network_value=
if command -v ip >/dev/null 2>&1; then
  network_value=$(ip -o addr show scope global 2>/dev/null || true)
fi
if [ -z "$network_value" ]; then network_value=$(hostname -I 2>/dev/null || true); fi
printf '%s\n' "$network_value"

if ! sleep 0.25 2>/dev/null; then sleep 1 2>/dev/null || true; fi
marker cpu
printf 'before\t%s\n' "$cpu_before"
printf 'after\t'
awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8,$9; exit}' /proc/stat 2>/dev/null
printf '\n'
printf 'cores\t'
(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || awk '/^processor[[:space:]]*:/ {count++} END {print count+0}' /proc/cpuinfo 2>/dev/null || printf 1)
printf 'model\t'
awk -F: '/model name|Hardware|Processor/ {gsub(/^[[:space:]]+/, "", $2); if ($2 != "") {print $2; exit}}' /proc/cpuinfo 2>/dev/null
"#;
const DOCKER_COLLECTION_SCRIPT: &str = r#"
runtime=$1
section=$2
offset=$3
limit=$4
case "$offset:$limit" in *[!0-9:]*|:*) printf 'Invalid page bounds\n' >&2; exit 64 ;; esac
start=$((offset + 1))
end=$((offset + limit + 1))

case "$section" in
  containers)
    "$runtime" ps -a --format '{{json .}}' >/dev/null || exit $?
    items=$("$runtime" ps -a --format '{{json .}}' | sed -n "${start},${end}p")
    ;;
  images)
    "$runtime" image ls --format '{{json .}}' >/dev/null || exit $?
    items=$("$runtime" image ls --format '{{json .}}' | sed -n "${start},${end}p")
    ;;
  volumes)
    "$runtime" volume ls --format '{{json .}}' >/dev/null || exit $?
    items=$("$runtime" volume ls --format '{{json .}}' | sed -n "${start},${end}p")
    ;;
  networks)
    "$runtime" network ls --format '{{json .}}' >/dev/null || exit $?
    items=$("$runtime" network ls --format '{{json .}}' | sed -n "${start},${end}p")
    ;;
  *) printf 'Unknown container resource section\n' >&2; exit 64 ;;
esac

printf '__SERVERBOX_DOCKER_ITEMS_V1__\n%s\n' "$items"
printf '__SERVERBOX_DOCKER_STATS_V1__\n'
if [ "$section" = containers ] && [ -n "$items" ]; then
  ids=$(printf '%s\n' "$items" | sed -n 's/.*"ID"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '/^[[:alnum:]_.:-][[:alnum:]_.:-]*$/p' | sed -n "1,${limit}p")
  if [ -n "$ids" ]; then
    # Identifiers are allowlisted above, so intentional field splitting passes
    # the page as individual runtime arguments without evaluating shell syntax.
    "$runtime" stats --no-stream --format '{{json .}}' $ids 2>/dev/null || true
  fi
fi
"#;

fn page_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_PAGE_SIZE)
}

fn page<T>(mut items: Vec<T>, limit: usize) -> Page<T> {
    let has_more = items.len() > limit;
    items.truncate(limit);
    Page { items, has_more }
}

pub fn connect(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<ServerConnection, String> {
    with_client(store, server_id, operation_id, |client, profile| {
        client.check_cancelled()?;
        Ok(ServerConnection {
            server_id: profile.id.clone(),
            connected_at: Utc::now().to_rfc3339(),
        })
    })
}

pub fn dashboard(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<Vec<DashboardCard>, String> {
    with_client(store, server_id, operation_id, |client, profile| {
        let output =
            client.exec_posix_script_bounded(OVERVIEW_SCRIPT, &[], MAX_OVERVIEW_OUTPUT_BYTES)?;
        let sections = parse_overview_sections(&output);
        let capabilities = parse_capabilities_probe(section(&sections, "capabilities"));
        client.remember_capabilities(capabilities.clone());
        let profile_values = parse_keyed_section(section(&sections, "profile"));
        let cpu_values = parse_keyed_section(section(&sections, "cpu"));
        let mut uptime_lines = section(&sections, "uptime").lines();
        let uptime_seconds = uptime_lines
            .next()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        let mut interfaces = parse_interfaces(section(&sections, "network"));
        if interfaces.is_empty() {
            let addresses = section(&sections, "network")
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            if !addresses.is_empty() {
                interfaces.push(NetworkInterface {
                    name: "network".to_string(),
                    addresses,
                });
            }
        }
        let cpu_model = cpu_values.get("model").copied().unwrap_or_default().trim();
        Ok(vec![
            DashboardCard::Profile {
                summary: ConnectionSummary {
                    server_id: profile.id.clone(),
                    hostname: profile_values
                        .get("hostname")
                        .copied()
                        .unwrap_or("unknown")
                        .trim()
                        .to_string(),
                    os: capabilities
                        .distro
                        .clone()
                        .unwrap_or_else(|| "Linux".to_string()),
                    kernel: profile_values
                        .get("kernel")
                        .copied()
                        .unwrap_or("unknown")
                        .trim()
                        .to_string(),
                    architecture: capabilities.architecture.clone(),
                    capabilities,
                    connected_at: Utc::now().to_rfc3339(),
                },
            },
            DashboardCard::Cpu {
                cpu_percent: parse_cpu_utilization(
                    cpu_values.get("before").copied().unwrap_or_default(),
                    cpu_values.get("after").copied().unwrap_or_default(),
                ),
                cpu_cores: cpu_values
                    .get("cores")
                    .and_then(|value| value.trim().parse().ok())
                    .filter(|cores| *cores > 0)
                    .unwrap_or(1),
                cpu_model: if cpu_model.is_empty() {
                    "Unknown CPU".to_string()
                } else {
                    cpu_model.to_string()
                },
            },
            DashboardCard::Memory {
                memory: parse_memory(section(&sections, "memory")),
                swap: parse_swap(section(&sections, "memory")),
            },
            DashboardCard::Storage {
                disks: parse_disks(section(&sections, "storage")),
            },
            DashboardCard::Uptime {
                uptime_seconds,
                load_averages: parse_load_averages(uptime_lines.next().unwrap_or_default()),
            },
            DashboardCard::Network { interfaces },
        ])
    })
}

fn parse_overview_sections(output: &str) -> HashMap<String, String> {
    let mut sections = HashMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        if let Some(name) = line.strip_prefix(OVERVIEW_SECTION_MARKER) {
            current = Some(name.trim().to_string());
            sections
                .entry(name.trim().to_string())
                .or_insert_with(String::new);
        } else if let Some(name) = current.as_ref() {
            let value = sections.entry(name.clone()).or_insert_with(String::new);
            value.push_str(line);
            value.push('\n');
        }
    }
    sections
}

fn section<'a>(sections: &'a HashMap<String, String>, name: &str) -> &'a str {
    sections.get(name).map(String::as_str).unwrap_or_default()
}

fn parse_keyed_section(value: &str) -> HashMap<&str, &str> {
    value
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect()
}

pub fn processes(
    store: &Store,
    server_id: &str,
    offset: usize,
    limit: usize,
    operation_id: Option<&str>,
) -> Result<Page<ProcessInfo>, String> {
    with_client(store, server_id, operation_id, |client, _| {
        let limit = page_limit(limit);
        let start = offset.saturating_add(1);
        let end = offset.saturating_add(limit).saturating_add(1);
        let fallback_start = start.saturating_add(1);
        let fallback_end = end.saturating_add(1);
        let output = client.exec_ok(&format!(
            "if ps -eo pid=,user=,%cpu=,%mem=,rss=,etimes=,args= --sort=-%cpu >/dev/null 2>&1; then printf 'serverbox-eo\\n'; ps -eo pid=,user=,%cpu=,%mem=,rss=,etimes=,args= --sort=-%cpu | sed -n '{start},{end}p'; else printf 'serverbox-aux\\n'; ps aux | sed -n '1p;{fallback_start},{fallback_end}p'; fi",
        ))?;
        let mut lines = output.lines();
        let layout = lines.next().unwrap_or_default();
        let mut processes = Vec::new();
        if layout == "serverbox-aux" {
            let headers = lines
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>();
            let column = |names: &[&str]| {
                headers
                    .iter()
                    .position(|header| names.iter().any(|name| header.eq_ignore_ascii_case(name)))
            };
            let Some(pid_index) = column(&["PID"]) else {
                return Ok(page(processes, limit));
            };
            let Some(user_index) = column(&["USER"]) else {
                return Ok(page(processes, limit));
            };
            let cpu_index = column(&["%CPU", "CPU"]);
            let memory_index = column(&["%MEM", "MEM"]);
            let rss_index = column(&["RSS"]);
            let command_index =
                column(&["COMMAND", "CMD"]).unwrap_or(headers.len().saturating_sub(1));
            for line in lines {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                let Some(pid) = fields.get(pid_index).and_then(|value| value.parse().ok()) else {
                    continue;
                };
                let Some(user) = fields.get(user_index) else {
                    continue;
                };
                processes.push(ProcessInfo {
                    pid,
                    user: (*user).to_string(),
                    cpu_percent: cpu_index
                        .and_then(|index| fields.get(index))
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0.0),
                    memory_percent: memory_index
                        .and_then(|index| fields.get(index))
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0.0),
                    rss_bytes: rss_index
                        .and_then(|index| fields.get(index))
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0)
                        * 1024,
                    runtime_seconds: 0,
                    command: fields.get(command_index..).unwrap_or_default().join(" "),
                });
            }
            return Ok(page(processes, limit));
        }
        for line in lines {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 7 {
                continue;
            }
            let Ok(pid) = fields[0].parse() else { continue };
            let command_index = 6;
            processes.push(ProcessInfo {
                pid,
                user: fields[1].to_string(),
                cpu_percent: fields[2].parse().unwrap_or(0.0),
                memory_percent: fields[3].parse().unwrap_or(0.0),
                rss_bytes: fields[4].parse::<u64>().unwrap_or(0) * 1024,
                runtime_seconds: fields[5].parse().unwrap_or(0),
                command: fields[command_index..].join(" "),
            });
        }
        Ok(page(processes, limit))
    })
}

pub fn signal_process(
    store: &Store,
    server_id: &str,
    pid: u32,
    force: bool,
    operation_id: Option<&str>,
) -> Result<(), String> {
    if pid == 0 {
        return Err("Refusing to signal PID 0".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let signal = if force { "KILL" } else { "TERM" };
        let command = format!("kill -{signal} {pid}");
        let output = client.exec(&command)?;
        if output.exit_code == 0 {
            return Ok(());
        }
        if is_permission_error(&output) {
            execute_privileged(client, profile, store, &command).map(|_| ())
        } else {
            Err(command_error(&output))
        }
    })
}

pub fn cron_jobs(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<Vec<CronJob>, String> {
    with_client(store, server_id, operation_id, |client, profile| {
        let user_text = client.exec("crontab -l 2>/dev/null || true")?.stdout;
        let mut jobs = parse_user_crontab(&user_text, &profile.username);
        let system = client.exec(
            "for f in /etc/crontab /etc/cron.d/*; do [ -r \"$f\" ] || continue; awk -v f=\"$f\" 'NF { print f \"\\t\" $0 }' \"$f\"; done",
        )?.stdout;
        for (index, line) in system.lines().enumerate() {
            let Some((source, cron_line)) = line.split_once('\t') else {
                continue;
            };
            let trimmed = cron_line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.contains('=') && !trimmed.contains(' ')
            {
                continue;
            }
            let fields = trimmed.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 7 {
                continue;
            }
            let schedule = fields[..5].join(" ");
            jobs.push(CronJob {
                id: format!("system:{source}:{index}"),
                source: source.to_string(),
                user: fields[5].to_string(),
                command: fields[6..].join(" "),
                enabled: true,
                human_schedule: human_cron(&schedule),
                next_run: next_cron_run(&schedule),
                schedule,
                editable: false,
            });
        }
        Ok(jobs)
    })
}

pub fn save_cron_job(
    store: &Store,
    server_id: &str,
    input: &CronJobInput,
    operation_id: Option<&str>,
) -> Result<(), String> {
    validate_cron(&input.schedule)?;
    if input.command.trim().is_empty()
        || input.command.contains('\n')
        || input.command.contains('\r')
    {
        return Err("Enter a single-line cron command".to_string());
    }
    with_client(store, server_id, operation_id, |client, _| {
        let existing = client.exec("crontab -l 2>/dev/null || true")?.stdout;
        let id = input
            .id
            .as_deref()
            .filter(|id| id.starts_with("user:"))
            .map(str::to_string)
            .unwrap_or_else(|| format!("user:{}", Uuid::new_v4()));
        let replacement = cron_job_line(&id, &input.schedule, &input.command, input.enabled);
        let updated = replace_cron_line(&existing, input.id.as_deref(), Some(&replacement))?;
        let output = client.exec_with_input("crontab -", Some(updated.as_bytes()))?;
        if output.exit_code == 0 {
            Ok(())
        } else {
            Err(command_error(&output))
        }
    })
}

pub fn cron_action(
    store: &Store,
    server_id: &str,
    id: &str,
    action: &str,
    operation_id: Option<&str>,
) -> Result<(), String> {
    if !id.starts_with("user:") || !matches!(action, "delete" | "enable" | "disable") {
        return Err("Unsupported cron action".to_string());
    }
    with_client(store, server_id, operation_id, |client, _| {
        let existing = client.exec("crontab -l 2>/dev/null || true")?.stdout;
        let mut found = false;
        let mut result = Vec::new();
        for (index, line) in existing.lines().enumerate() {
            if cron_line_id(line, index) == id {
                found = true;
                if action == "delete" {
                    continue;
                }
                let raw = line
                    .trim()
                    .strip_prefix("# SERVERBOX_DISABLED ")
                    .unwrap_or(line.trim());
                result.push(if action == "disable" {
                    format!("# SERVERBOX_DISABLED {raw}")
                } else {
                    raw.to_string()
                });
            } else {
                result.push(line.to_string());
            }
        }
        if !found {
            return Err("That cron job no longer exists".to_string());
        }
        let text = format!("{}\n", result.join("\n"));
        let output = client.exec_with_input("crontab -", Some(text.as_bytes()))?;
        if output.exit_code == 0 {
            Ok(())
        } else {
            Err(command_error(&output))
        }
    })
}

pub fn packages(
    store: &Store,
    server_id: &str,
    query: &str,
    upgrades_only: bool,
    offset: usize,
    limit: usize,
    operation_id: Option<&str>,
) -> Result<PackagePage, String> {
    with_client(store, server_id, operation_id, |client, _| {
        let capabilities = detect_capabilities(client)?;
        let manager = capabilities.package_manager.unwrap_or_default();
        if manager != "apt-get" {
            return Err(
                "Package management currently supports Debian and Ubuntu APT servers".to_string(),
            );
        }
        let upgrade_output = client
            .exec("LC_ALL=C apt list --upgradable 2>/dev/null || true")?
            .stdout;
        let mut upgrades = std::collections::HashMap::new();
        for line in upgrade_output.lines().skip(1) {
            let Some((name_arch, rest)) = line.split_once('/') else {
                continue;
            };
            let version = rest.split_whitespace().nth(1).unwrap_or_default();
            if !name_arch.is_empty() && !version.is_empty() {
                upgrades.insert(name_arch.to_string(), version.to_string());
            }
        }
        let raw = if query.trim().is_empty() {
            client.exec_ok("dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\t${binary:Summary}\\n' 2>/dev/null || true")?
        } else {
            client.exec_ok(&format!(
                "apt-cache search --names-only {} 2>/dev/null || true",
                quote_shell(query.trim())
            ))?
        };
        let installed_names = if query.trim().is_empty() {
            std::collections::HashSet::new()
        } else {
            client
                .exec("dpkg-query -W -f='${binary:Package}\\n' 2>/dev/null || true")?
                .stdout
                .lines()
                .map(str::to_string)
                .collect()
        };
        let mut items = Vec::new();
        for line in raw.lines() {
            let (name, version, architecture, description, installed) = if query.trim().is_empty() {
                let fields = line.splitn(4, '\t').collect::<Vec<_>>();
                if fields.len() < 4 {
                    continue;
                }
                (fields[0], fields[1], fields[2], fields[3], true)
            } else {
                let Some((name, description)) = line.split_once(" - ") else {
                    continue;
                };
                (name, "", "", description, installed_names.contains(name))
            };
            let upgrade_version = upgrades.get(name).cloned().or_else(|| {
                upgrades.iter().find_map(|(qualified_name, version)| {
                    qualified_name
                        .split_once(':')
                        .and_then(|(base_name, _)| (base_name == name).then(|| version.clone()))
                })
            });
            if upgrades_only && upgrade_version.is_none() {
                continue;
            }
            items.push(PackageInfo {
                name: name.to_string(),
                version: version.to_string(),
                architecture: architecture.to_string(),
                description: description.to_string(),
                installed,
                upgrade_version,
            });
        }
        let limit = page_limit(limit);
        let slice = items
            .into_iter()
            .skip(offset)
            .take(limit + 1)
            .collect::<Vec<_>>();
        Ok(PackagePage {
            manager: "APT".to_string(),
            packages: page(slice, limit),
            pending_upgrades: upgrades.len(),
        })
    })
}

pub fn package_details(
    store: &Store,
    server_id: &str,
    name: &str,
    operation_id: Option<&str>,
) -> Result<String, String> {
    validate_package_name(name)?;
    with_client(store, server_id, operation_id, |client, _| {
        client.exec_ok(&format!(
            "apt-cache show {} 2>/dev/null | sed -n '1,100p'",
            quote_shell(name)
        ))
    })
}

pub fn package_action(
    store: &Store,
    server_id: &str,
    action: &str,
    name: Option<&str>,
    operation_id: Option<&str>,
) -> Result<String, String> {
    let command = match action {
        "update" => "DEBIAN_FRONTEND=noninteractive apt-get update".to_string(),
        "upgrade-all" => "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade".to_string(),
        "install" | "remove" | "upgrade" => {
            let name = name.ok_or_else(|| "Choose a package".to_string())?;
            validate_package_name(name)?;
            let verb = if action == "upgrade" {
                "install --only-upgrade"
            } else {
                action
            };
            format!(
                "DEBIAN_FRONTEND=noninteractive apt-get -y {verb} {}",
                quote_shell(name)
            )
        }
        _ => return Err("Unsupported package action".to_string()),
    };
    with_client(store, server_id, operation_id, |client, profile| {
        // apt-get update/upgrade can stay silent for minutes at a time.
        execute_privileged_long(client, profile, store, &command)
    })
}

pub fn accounts(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<AccountSnapshot, String> {
    with_client(store, server_id, operation_id, |client, profile| {
        let passwd = client.exec_ok("if command -v getent >/dev/null 2>&1; then getent passwd; elif [ -r /etc/passwd ]; then cat /etc/passwd; else echo 'Neither getent nor a readable /etc/passwd is available' >&2; exit 69; fi")?;
        let group_text = client.exec_ok("if command -v getent >/dev/null 2>&1; then getent group; elif [ -r /etc/group ]; then cat /etc/group; else echo 'Neither getent nor a readable /etc/group is available' >&2; exit 69; fi")?;
        let lastlog = client.exec("LC_ALL=C lastlog 2>/dev/null || true")?.stdout;
        let last_logins = lastlog
            .lines()
            .skip(1)
            .filter_map(|line| {
                let name = line.split_whitespace().next()?;
                if name.is_empty() || line.contains("Never logged in") {
                    None
                } else {
                    let summary = line[name.len()..]
                        .trim()
                        .chars()
                        .filter(|ch| !matches!(ch, '<' | '>' | '&' | '"' | '\''))
                        .collect();
                    Some((name.to_string(), summary))
                }
            })
            .collect::<std::collections::HashMap<_, _>>();
        let shadow = execute_privileged(
            client,
            profile,
            store,
            "if command -v getent >/dev/null 2>&1; then getent shadow; elif [ -r /etc/shadow ]; then cat /etc/shadow; fi",
        )
        .unwrap_or_default();
        let locked = shadow
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                let hash = fields.next()?;
                (hash.starts_with('!') || hash.starts_with('*')).then(|| name.to_string())
            })
            .collect::<std::collections::HashSet<_>>();
        let groups = group_text
            .lines()
            .filter_map(|line| {
                let fields = line.split(':').collect::<Vec<_>>();
                if fields.len() < 4 {
                    return None;
                }
                Some(LinuxGroup {
                    name: fields[0].to_string(),
                    gid: fields[2].parse().ok()?,
                    members: fields[3]
                        .split(',')
                        .filter(|v| !v.is_empty())
                        .map(str::to_string)
                        .collect(),
                })
            })
            .collect::<Vec<_>>();
        let gid_names = groups
            .iter()
            .map(|group| (group.gid, group.name.clone()))
            .collect::<std::collections::HashMap<_, _>>();
        let users = passwd
            .lines()
            .filter_map(|line| {
                let fields = line.split(':').collect::<Vec<_>>();
                if fields.len() < 7 {
                    return None;
                }
                let name = fields[0].to_string();
                let uid = fields[2].parse().ok()?;
                let gid = fields[3].parse().ok()?;
                let mut memberships = groups
                    .iter()
                    .filter(|group| group.members.contains(&name))
                    .map(|group| group.name.clone())
                    .collect::<Vec<_>>();
                if let Some(primary) = gid_names.get(&gid) {
                    if !memberships.contains(primary) {
                        memberships.insert(0, primary.clone());
                    }
                }
                Some(LinuxUser {
                    name: name.clone(),
                    uid,
                    gid,
                    home: fields[5].to_string(),
                    shell: fields[6].to_string(),
                    groups: memberships,
                    last_login: last_logins.get(&name).cloned(),
                    locked: locked.contains(&name),
                })
            })
            .collect();
        Ok(AccountSnapshot { users, groups })
    })
}

pub fn create_user(
    store: &Store,
    server_id: &str,
    input: &UserCreateInput,
    operation_id: Option<&str>,
) -> Result<(), String> {
    validate_account_name(&input.name, "username")?;
    for group in &input.groups {
        validate_account_name(group, "group")?;
    }
    let mut useradd = "useradd -m".to_string();
    let mut adduser = "adduser -D".to_string();
    if let Some(home) = input.home.as_deref().filter(|v| !v.trim().is_empty()) {
        useradd.push_str(&format!(" -d {}", quote_shell(home)));
        adduser.push_str(&format!(" -h {}", quote_shell(home)));
    }
    if let Some(shell) = input.shell.as_deref().filter(|v| !v.trim().is_empty()) {
        useradd.push_str(&format!(" -s {}", quote_shell(shell)));
        adduser.push_str(&format!(" -s {}", quote_shell(shell)));
    }
    if !input.groups.is_empty() {
        useradd.push_str(&format!(" -G {}", quote_shell(&input.groups.join(","))));
    }
    useradd.push_str(&format!(" {}", quote_shell(&input.name)));
    adduser.push_str(&format!(" {}", quote_shell(&input.name)));
    for group in &input.groups {
        adduser.push_str(&format!(
            " && addgroup {} {}",
            quote_shell(&input.name),
            quote_shell(group)
        ));
    }
    let command = format!(
        "if command -v useradd >/dev/null 2>&1; then {useradd}; elif [ -e /etc/alpine-release ] && command -v adduser >/dev/null 2>&1 && command -v addgroup >/dev/null 2>&1; then {adduser}; else echo 'User creation requires shadow-utils/useradd or Alpine BusyBox adduser/addgroup' >&2; exit 69; fi"
    );
    with_client(store, server_id, operation_id, |client, profile| {
        execute_privileged(client, profile, store, &command)?;
        if let Some(password) = input.password.as_deref().filter(|v| !v.is_empty()) {
            let password_input = Zeroizing::new(format!("{}:{}\n", input.name, password));
            execute_privileged_with_input(
                client,
                profile,
                store,
                "if command -v chpasswd >/dev/null 2>&1; then chpasswd; else echo 'Password changes require chpasswd, which is not installed on this server' >&2; exit 69; fi",
                password_input.as_bytes(),
            )?;
        }
        Ok(())
    })
}

pub fn account_action(
    store: &Store,
    server_id: &str,
    action: &str,
    name: &str,
    value: Option<&str>,
    operation_id: Option<&str>,
) -> Result<(), String> {
    validate_account_name(
        name,
        if action.contains("group") {
            "group"
        } else {
            "username"
        },
    )?;
    let command = match action {
        "delete-user" => format!(
            "if command -v userdel >/dev/null 2>&1; then userdel -r {name}; elif command -v deluser >/dev/null 2>&1; then deluser --remove-home {name}; else echo 'User deletion requires userdel or deluser' >&2; exit 69; fi",
            name = quote_shell(name)
        ),
        "lock" | "unlock" => {
            let usermod_flag = if action == "lock" { "-L" } else { "-U" };
            let passwd_flag = if action == "lock" { "-l" } else { "-u" };
            format!(
                "if command -v usermod >/dev/null 2>&1; then usermod {usermod_flag} {name}; elif command -v passwd >/dev/null 2>&1; then passwd {passwd_flag} {name}; else echo 'Account locking requires usermod or passwd' >&2; exit 69; fi",
                name = quote_shell(name)
            )
        }
        "shell" => format!(
            "if command -v usermod >/dev/null 2>&1; then usermod -s {shell} {name}; elif command -v chsh >/dev/null 2>&1; then chsh -s {shell} {name}; else echo 'Changing login shells requires usermod or chsh' >&2; exit 69; fi",
            shell = quote_shell(value.ok_or_else(|| "Enter a shell".to_string())?),
            name = quote_shell(name)
        ),
        "groups" => format!(
            "if command -v usermod >/dev/null 2>&1; then usermod -G {groups} {name}; else echo 'Replacing supplementary groups requires usermod on this Linux distribution' >&2; exit 69; fi",
            groups = quote_shell(value.unwrap_or_default()),
            name = quote_shell(name)
        ),
        "create-group" => format!(
            "if command -v groupadd >/dev/null 2>&1; then groupadd {name}; elif [ -e /etc/alpine-release ] && command -v addgroup >/dev/null 2>&1; then addgroup -S {name}; else echo 'Group creation requires groupadd or Alpine BusyBox addgroup' >&2; exit 69; fi",
            name = quote_shell(name)
        ),
        "delete-group" => format!(
            "if command -v groupdel >/dev/null 2>&1; then groupdel {name}; elif command -v delgroup >/dev/null 2>&1; then delgroup {name}; else echo 'Group deletion requires groupdel or delgroup' >&2; exit 69; fi",
            name = quote_shell(name)
        ),
        _ => return Err("Unsupported account action".to_string()),
    };
    with_client(store, server_id, operation_id, |client, profile| {
        if matches!(action, "delete-user" | "lock") && (name == "root" || name == profile.username)
        {
            return Err("Refusing to delete or lock root or the active SSH user".to_string());
        }
        execute_privileged(client, profile, store, &command).map(|_| ())
    })
}

pub fn reset_user_password(
    store: &Store,
    server_id: &str,
    name: &str,
    password: &str,
    operation_id: Option<&str>,
) -> Result<(), String> {
    validate_account_name(name, "username")?;
    if password.is_empty() || password.contains('\n') {
        return Err("Enter a password".to_string());
    }
    let password_input = Zeroizing::new(format!("{name}:{password}\n"));
    with_client(store, server_id, operation_id, |client, profile| {
        execute_privileged_with_input(
            client,
            profile,
            store,
            "if command -v chpasswd >/dev/null 2>&1; then chpasswd; else echo 'Password changes require chpasswd, which is not installed on this server' >&2; exit 69; fi",
            password_input.as_bytes(),
        )
        .map(|_| ())
    })
}

fn validate_account_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '.'))
    {
        return Err(format!("Invalid {label}"));
    }
    Ok(())
}

fn validate_package_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.' | ':'))
    {
        return Err("Invalid package name".to_string());
    }
    Ok(())
}

fn parse_user_crontab(text: &str, user: &str) -> Vec<CronJob> {
    text.lines()
        .enumerate()
        .filter_map(|(index, original)| {
            let trimmed = original.trim();
            let (enabled, line) = if let Some(line) = trimmed.strip_prefix("# SERVERBOX_DISABLED ")
            {
                (false, line)
            } else {
                (true, trimmed)
            };
            if line.is_empty() || line.starts_with('#') || line.contains('=') && !line.contains(' ')
            {
                return None;
            }
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 6 {
                return None;
            }
            let schedule = fields[..5].join(" ");
            let command = fields[5..]
                .join(" ")
                .split(" # serverbox:")
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            Some(CronJob {
                id: cron_line_id(original, index),
                source: "User crontab".to_string(),
                user: user.to_string(),
                human_schedule: human_cron(&schedule),
                next_run: next_cron_run(&schedule),
                schedule,
                command,
                enabled,
                editable: true,
            })
        })
        .collect()
}

fn cron_line_id(line: &str, index: usize) -> String {
    line.rsplit_once(" # serverbox:")
        .map(|(_, id)| id.trim().to_string())
        .filter(|id| id.starts_with("user:"))
        .unwrap_or_else(|| format!("user:line:{index}"))
}

fn cron_job_line(id: &str, schedule: &str, command: &str, enabled: bool) -> String {
    let line = format!("{} {} # serverbox:{}", schedule.trim(), command.trim(), id);
    if enabled {
        line
    } else {
        format!("# SERVERBOX_DISABLED {line}")
    }
}

fn replace_cron_line(
    existing: &str,
    id: Option<&str>,
    replacement: Option<&str>,
) -> Result<String, String> {
    let mut found = id.is_none();
    let mut lines = Vec::new();
    for (index, line) in existing.lines().enumerate() {
        if id.is_some_and(|id| cron_line_id(line, index) == id) {
            found = true;
            if let Some(replacement) = replacement {
                lines.push(replacement.to_string());
            }
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        return Err("That cron job no longer exists".to_string());
    }
    if id.is_none() {
        if let Some(replacement) = replacement {
            lines.push(replacement.to_string());
        }
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn validate_cron(value: &str) -> Result<(), String> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 5 {
        return Err("Cron schedules need exactly five fields".to_string());
    }
    Schedule::from_str(&format!("0 {value}"))
        .map(|_| ())
        .map_err(|_| "That cron expression is not valid".to_string())
}

fn next_cron_run(value: &str) -> Option<String> {
    Schedule::from_str(&format!("0 {value}"))
        .ok()?
        .upcoming(Utc)
        .next()
        .map(|time| time.to_rfc3339())
}

fn human_cron(value: &str) -> String {
    match value.trim() {
        "* * * * *" => "Every minute",
        "0 * * * *" => "Every hour",
        "0 0 * * *" => "Every day at midnight",
        "0 0 * * 0" => "Every Sunday at midnight",
        "0 0 1 * *" => "On the first day of every month",
        other if other.starts_with("*/") && other.ends_with(" * * * *") => {
            "At a regular minute interval"
        }
        _ => "Custom schedule",
    }
    .to_string()
}

pub fn services(
    store: &Store,
    server_id: &str,
    offset: usize,
    limit: usize,
    operation_id: Option<&str>,
) -> Result<Page<ServiceInfo>, String> {
    with_client(store, server_id, operation_id, |client, _| {
        let limit = page_limit(limit);
        let start = offset.saturating_add(1);
        let end = offset.saturating_add(limit).saturating_add(1);
        let output = client.exec_ok(&format!(
            "systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null | sed -n '{start},{end}p' || true",
        ))?;
        let mut services = Vec::new();
        for line in output.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || !fields[0].ends_with(".service") {
                continue;
            }
            services.push(ServiceInfo {
                name: fields[0].to_string(),
                load_state: fields[1].to_string(),
                active_state: fields[2].to_string(),
                sub_state: fields[3].to_string(),
                description: fields[4..].join(" "),
                enabled: None,
            });
        }
        let visible_count = services.len().min(limit);
        if visible_count > 0 {
            let names = services[..visible_count]
                .iter()
                .map(|service| quote_shell(&service.name))
                .collect::<Vec<_>>()
                .join(" ");
            let states = client
                .exec(&format!(
                    "for unit in {names}; do state=\"$(LC_ALL=C systemctl is-enabled \"$unit\" 2>/dev/null || true)\"; printf '%s\\t%s\\n' \"$unit\" \"$state\"; done"
                ))?
                .stdout
                .lines()
                .filter_map(|line| {
                    let (name, state) = line.split_once('\t')?;
                    (!state.is_empty()).then(|| (name.to_string(), state.to_string()))
                })
                .collect::<std::collections::HashMap<_, _>>();
            for service in services.iter_mut().take(visible_count) {
                service.enabled = states.get(&service.name).map(|state| state == "enabled");
            }
        }
        Ok(page(services, limit))
    })
}

pub fn service_details(
    store: &Store,
    server_id: &str,
    service: &str,
    operation_id: Option<&str>,
) -> Result<ServiceDetails, String> {
    validate_unit_name(service)?;
    with_client(store, server_id, operation_id, |client, _| {
        let properties = client
            .exec(&format!(
                "systemctl show {} --no-pager 2>/dev/null || true",
                quote_shell(service)
            ))?
            .stdout
            .lines()
            .filter_map(|line| {
                line.split_once('=')
                    .map(|(key, value)| (key.to_string(), value.to_string()))
            })
            .filter(|(key, value)| {
                !value.is_empty()
                    && [
                        "Description",
                        "ActiveState",
                        "SubState",
                        "UnitFileState",
                        "FragmentPath",
                        "MainPID",
                        "ExecStart",
                        "MemoryCurrent",
                        "TasksCurrent",
                    ]
                    .contains(&key.as_str())
            })
            .collect();
        let journal = client
            .exec(&format!(
                "journalctl -u {} -n 60 --no-pager -o short-iso 2>/dev/null || true",
                quote_shell(service)
            ))?
            .stdout;
        let unit_file = client
            .exec(&format!(
                "systemctl show {} -p FragmentPath --value --no-pager 2>/dev/null || true",
                quote_shell(service)
            ))?
            .stdout
            .trim()
            .to_string();
        Ok(ServiceDetails {
            name: service.to_string(),
            properties,
            journal,
            unit_file: (!unit_file.is_empty()).then_some(unit_file),
        })
    })
}

pub fn service_action(
    store: &Store,
    server_id: &str,
    service: &str,
    action: &str,
    operation_id: Option<&str>,
) -> Result<(), String> {
    validate_unit_name(service)?;
    if !["start", "stop", "restart", "reload", "enable", "disable"].contains(&action) {
        return Err("Unsupported service action".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        execute_privileged(
            client,
            profile,
            store,
            &format!("systemctl {action} {}", quote_shell(service)),
        )
        .map(|_| ())
    })
}

pub fn docker_snapshot(
    store: &Store,
    server_id: &str,
    section: &str,
    offset: usize,
    limit: usize,
    operation_id: Option<&str>,
) -> Result<DockerPage, String> {
    if !["containers", "images", "volumes", "networks"].contains(&section) {
        return Err("Unknown Docker section".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let runtime = docker_runtime(client)?;
        let limit = page_limit(limit);
        let (items_output, stats_output) =
            docker_collection(client, profile, store, &runtime, section, offset, limit)?;
        let mut result = DockerPage {
            runtime: runtime.clone(),
            section: section.to_string(),
            containers: Vec::new(),
            images: Vec::new(),
            volumes: Vec::new(),
            networks: Vec::new(),
            has_more: false,
        };
        match section {
            "containers" => {
                let container_page = page(parse_docker_containers(&items_output), limit);
                let stats = parse_docker_stats(&stats_output);
                result.containers = container_page
                    .items
                    .into_iter()
                    .map(|mut container| {
                        if let Some(stat) = stats
                            .iter()
                            .find(|stat| stat.id == container.id || stat.name == container.name)
                        {
                            container.cpu_percent = stat.cpu_percent;
                            container.memory_usage_bytes = stat.memory_usage_bytes;
                            container.memory_limit_bytes = stat.memory_limit_bytes;
                            container.memory_percent = stat.memory_percent;
                            container.network_rx_bytes = stat.network_rx_bytes;
                            container.network_tx_bytes = stat.network_tx_bytes;
                            container.block_read_bytes = stat.block_read_bytes;
                            container.block_write_bytes = stat.block_write_bytes;
                        }
                        container
                    })
                    .collect();
                result.has_more = container_page.has_more;
            }
            "images" => {
                let items = page(parse_docker_images(&items_output), limit);
                result.images = items.items;
                result.has_more = items.has_more;
            }
            "volumes" => {
                let items = page(parse_docker_volumes(&items_output), limit);
                result.volumes = items.items;
                result.has_more = items.has_more;
            }
            "networks" => {
                let items = page(parse_docker_networks(&items_output), limit);
                result.networks = items.items;
                result.has_more = items.has_more;
            }
            _ => unreachable!(),
        }
        Ok(result)
    })
}

pub fn docker_action(
    store: &Store,
    server_id: &str,
    action: &str,
    target: &str,
    operation_id: Option<&str>,
) -> Result<(), String> {
    if ![
        "start",
        "stop",
        "restart",
        "pause",
        "unpause",
        "rm",
        "rmi",
        "volume-rm",
        "network-rm",
        "volume-create",
        "network-create",
    ]
    .contains(&action)
    {
        return Err("Unsupported Docker action".to_string());
    }
    if target.trim().is_empty() {
        return Err("Choose a Docker resource first".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let runtime = docker_runtime(client)?;
        let command = match action {
            "volume-create" => format!("{runtime} volume create {}", quote_shell(target)),
            "network-create" => format!("{runtime} network create {}", quote_shell(target)),
            "volume-rm" => format!("{runtime} volume rm {}", quote_shell(target)),
            "network-rm" => format!("{runtime} network rm {}", quote_shell(target)),
            "rmi" => format!("{runtime} image rm {}", quote_shell(target)),
            "rm" => format!("{runtime} rm {}", quote_shell(target)),
            _ => format!("{runtime} {action} {}", quote_shell(target)),
        };
        let output = client.exec(&command)?;
        if output.exit_code == 0 {
            return Ok(());
        }
        if is_permission_error(&output) {
            execute_privileged(client, profile, store, &command).map(|_| ())
        } else {
            Err(command_error(&output))
        }
    })
}

pub fn container_exec(
    store: &Store,
    server_id: &str,
    container: &str,
    operation_id: Option<&str>,
) -> Result<ContainerExec, String> {
    if container.trim().is_empty() {
        return Err("Choose a container first".to_string());
    }
    with_client(store, server_id, operation_id, |client, _| {
        let runtime = docker_runtime(client)?;
        let access = ensure_container_running(client, &runtime, container)?;
        let shell = resolve_container_terminal_shell(client, &runtime, container, access)?;
        let privilege = if access == ContainerRuntimeAccess::PasswordlessSudo {
            "sudo -n "
        } else {
            ""
        };
        Ok(ContainerExec {
            command: format!(
                "exec {privilege}{runtime} exec -it {} {}",
                quote_shell(container),
                quote_shell(shell)
            ),
            shell: shell.to_string(),
        })
    })
}

pub fn docker_logs(
    store: &Store,
    server_id: &str,
    container: &str,
    lines: u32,
    since: Option<&str>,
    operation_id: Option<&str>,
) -> Result<String, String> {
    if container.trim().is_empty() {
        return Err("Choose a container first".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let runtime = docker_runtime(client)?;
        let command = docker_logs_command(&runtime, container, lines, since)?;
        run_log_command(client, profile, store, &command)
    })
}

pub fn docker_inspect(
    store: &Store,
    server_id: &str,
    target: &str,
    kind: &str,
    operation_id: Option<&str>,
) -> Result<String, String> {
    if target.trim().is_empty() {
        return Err("Choose a Docker resource first".to_string());
    }
    let kind = match kind {
        "container" | "image" | "volume" | "network" => kind,
        _ => return Err("Unsupported Docker resource".to_string()),
    };
    with_client(store, server_id, operation_id, |client, profile| {
        let runtime = docker_runtime(client)?;
        let command = if kind == "container" {
            format!("{runtime} inspect {}", quote_shell(target))
        } else {
            format!("{runtime} {kind} inspect {}", quote_shell(target))
        };
        run_log_command(client, profile, store, &command)
    })
}

pub fn docker_pull(
    store: &Store,
    server_id: &str,
    image: &str,
    operation_id: Option<&str>,
) -> Result<String, String> {
    if image.trim().is_empty() {
        return Err("Enter an image name".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let runtime = docker_runtime(client)?;
        let command = format!("{runtime} pull {}", quote_shell(image));
        // Image pulls can stay silent for minutes on slow links.
        let output = client.exec_long(&command)?;
        if output.exit_code == 0 {
            Ok(output.stdout)
        } else if is_permission_error(&output) {
            execute_privileged_long(client, profile, store, &command)
        } else {
            Err(command_error(&output))
        }
    })
}

pub fn docker_create(
    store: &Store,
    server_id: &str,
    input: &DockerCreateInput,
    operation_id: Option<&str>,
) -> Result<String, String> {
    if input.image.trim().is_empty() {
        return Err("Enter a Docker image".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let runtime = docker_runtime(client)?;
        let mut command = format!("{runtime} run");
        if input.detached {
            command.push_str(" -d");
        }
        if input.remove_on_exit {
            command.push_str(" --rm");
        }
        if let Some(name) = input
            .name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            command.push_str(&format!(" --name {}", quote_shell(name)));
        }
        if let Some(policy) = input
            .restart_policy
            .as_deref()
            .filter(|value| ["no", "always", "unless-stopped", "on-failure"].contains(value))
        {
            command.push_str(&format!(" --restart {}", quote_shell(policy)));
        }
        if let Some(memory) = input
            .memory_limit
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            command.push_str(&format!(" --memory {}", quote_shell(memory)));
        }
        if let Some(cpu) = input
            .cpu_limit
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            command.push_str(&format!(" --cpus {}", quote_shell(cpu)));
        }
        for port in &input.ports {
            if !port.trim().is_empty() {
                command.push_str(&format!(" -p {}", quote_shell(port)));
            }
        }
        for env in &input.environment {
            if !env.trim().is_empty() {
                command.push_str(&format!(" -e {}", quote_shell(env)));
            }
        }
        for volume in &input.volumes {
            if !volume.trim().is_empty() {
                command.push_str(&format!(" -v {}", quote_shell(volume)));
            }
        }
        for network in &input.networks {
            if !network.trim().is_empty() {
                command.push_str(&format!(" --network {}", quote_shell(network)));
            }
        }
        command.push_str(&format!(" {}", quote_shell(&input.image)));
        if let Some(command_text) = input
            .command
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            command.push_str(&format!(" sh -lc {}", quote_shell(command_text)));
        }
        let output = client.exec(&command)?;
        if output.exit_code == 0 {
            Ok(output.stdout.trim().to_string())
        } else if is_permission_error(&output) {
            execute_privileged(client, profile, store, &command)
        } else {
            let error = command_error(&output);
            if input
                .command
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
                && output.exit_code == 127
            {
                Err(format!(
                    "The image could not run the requested command through sh (exit status 127). It may be a shell-less/distroless image. Runtime detail: {error}"
                ))
            } else {
                Err(error)
            }
        }
    })
}

pub fn logs(
    store: &Store,
    server_id: &str,
    request: &LogsRequest,
    operation_id: Option<&str>,
) -> Result<String, String> {
    with_client(store, server_id, operation_id, |client, profile| {
        let command = log_command(client, profile, store, request, false)?;
        run_log_command(client, profile, store, &command)
    })
}

pub(crate) fn log_command(
    client: &mut crate::ssh::SshClient,
    profile: &ServerProfile,
    store: &Store,
    request: &LogsRequest,
    follow: bool,
) -> Result<String, String> {
    let lines = if follow {
        request.lines.min(5000)
    } else {
        request.lines.clamp(1, 5000)
    };
    match resolved_log_source(request) {
        "container" | "docker" => {
            let container =
                required_log_value(request.container.as_deref(), "Choose a container first")?;
            let runtime = docker_runtime(client)?;
            let mut command =
                docker_logs_command(&runtime, container, lines, request.since.as_deref())?;
            if follow {
                command = command.replacen(" logs ", " logs --follow ", 1);
                if lines == 0 {
                    command = command.replacen("--tail 1", "--tail 0", 1);
                }
            }
            Ok(command)
        }
        "compose" => {
            let path = required_log_value(
                request.compose_path.as_deref(),
                "Choose a Compose project first",
            )?;
            if path.contains(['\n', '\r', '\0']) {
                return Err("Choose a valid Compose file".to_string());
            }
            let mut args = format!("logs --tail {lines}");
            if follow {
                args.push_str(" --follow");
            }
            if let Some(since) = docker_since_shell_argument(request.since.as_deref())? {
                args.push_str(&format!(" --since {since}"));
            }
            if let Some(service) = request
                .service
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                validate_simple_log_name(service, "Compose service")?;
                args.push_str(&format!(" {}", quote_shell(service)));
            }
            Ok(crate::tier3::compose_command(path, &args))
        }
        "file" => {
            let path = required_log_value(request.file_path.as_deref(), "Choose a log file first")?;
            validate_log_path(path)?;
            let tail_flag = if follow { "-F" } else { "" };
            let tail = format!("tail -n {lines} {tail_flag} -- {}", quote_shell(path));
            if let Some(container) = request
                .container
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let runtime = docker_runtime(client)?;
                let shell = resolve_container_shell_privileged(client, profile, store, |shell| {
                    runtime_shell_probe(&runtime, container, shell)
                })?;
                Ok(format!(
                    "{runtime} exec {} {} -c {}",
                    quote_shell(container),
                    quote_shell(shell),
                    quote_shell(&tail)
                ))
            } else {
                Ok(tail)
            }
        }
        "system" => {
            let capabilities = detect_capabilities(client)?;
            if capabilities.journalctl {
                let mut command = format!("journalctl -n {lines} --no-pager -o short-iso");
                if follow {
                    command.push_str(" --follow");
                }
                if let Some(service) = request
                    .service
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    validate_unit_name(service)?;
                    command.push_str(&format!(" -u {}", quote_shell(service)));
                }
                if let Some(since) = request
                    .since
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    command.push_str(&format!(" --since {}", quote_shell(since)));
                }
                if let Some(query) = request
                    .query
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    command.push_str(&format!(
                        " --grep {}",
                        quote_shell(&journal_grep_pattern(query))
                    ));
                }
                match request.severity.as_deref() {
                    Some("error") => command.push_str(" -p err"),
                    Some("warn") => command.push_str(" -p warning"),
                    Some("all") | None => {}
                    Some(_) => return Err("Unsupported log severity".to_string()),
                }
                Ok(command)
            } else if capabilities.logread {
                if follow {
                    return Err("Live streaming is unavailable for this syslog buffer".to_string());
                }
                Ok(format!("logread -l {lines}"))
            } else {
                Err("No supported system log source is available on this server".to_string())
            }
        }
        _ => Err("Unsupported log source".to_string()),
    }
}

pub(crate) fn log_access_command(
    client: &mut crate::ssh::SshClient,
    profile: &ServerProfile,
    store: &Store,
    request: &LogsRequest,
) -> Result<String, String> {
    match resolved_log_source(request) {
        "system" => Ok("journalctl -n 1 --no-pager >/dev/null".to_string()),
        "container" | "docker" => {
            let container =
                required_log_value(request.container.as_deref(), "Choose a container first")?;
            Ok(format!(
                "{} inspect {} >/dev/null",
                docker_runtime(client)?,
                quote_shell(container)
            ))
        }
        "compose" => {
            let path = required_log_value(
                request.compose_path.as_deref(),
                "Choose a Compose project first",
            )?;
            Ok(format!(
                "{} >/dev/null",
                crate::tier3::compose_command(path, "ps")
            ))
        }
        "file" => {
            let path = required_log_value(request.file_path.as_deref(), "Choose a log file first")?;
            validate_log_path(path)?;
            if let Some(container) = request
                .container
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let runtime = docker_runtime(client)?;
                let shell = resolve_container_shell_privileged(client, profile, store, |shell| {
                    runtime_shell_probe(&runtime, container, shell)
                })?;
                Ok(format!(
                    "{runtime} exec {} {} -c {}",
                    quote_shell(container),
                    quote_shell(shell),
                    quote_shell(&format!(
                        "if [ ! -e {path} ] || [ -r {path} ]; then exit 0; else echo 'Permission denied' >&2; exit 1; fi",
                        path = quote_shell(path)
                    ))
                ))
            } else {
                let path = quote_shell(path);
                Ok(format!(
                    "if [ ! -e {path} ] || [ -r {path} ]; then exit 0; else echo 'Permission denied' >&2; exit 1; fi"
                ))
            }
        }
        _ => Err("Unsupported log source".to_string()),
    }
}

fn resolved_log_source(request: &LogsRequest) -> &str {
    if request
        .file_path
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        "file"
    } else if request
        .compose_path
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        "compose"
    } else if request
        .container
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        "container"
    } else {
        request.source.as_str()
    }
}

fn required_log_value<'a>(value: Option<&'a str>, message: &str) -> Result<&'a str, String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| message.to_string())
}

fn validate_log_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains(['\n', '\r', '\0']) {
        return Err("Enter an absolute log file path".to_string());
    }
    Ok(())
}

fn validate_simple_log_name(value: &str, label: &str) -> Result<(), String> {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        Ok(())
    } else {
        Err(format!("Invalid {label}"))
    }
}

pub fn ports(
    store: &Store,
    server_id: &str,
    offset: usize,
    limit: usize,
    operation_id: Option<&str>,
) -> Result<Page<PortInfo>, String> {
    with_client(store, server_id, operation_id, |client, _| {
        let capabilities = detect_capabilities(client)?;
        let limit = page_limit(limit);
        let end = offset.saturating_add(limit).saturating_add(1);
        let (output, parser) = match capabilities.network_tool.as_deref() {
            Some("ss") => {
                let start = offset.saturating_add(1);
                (
                    client
                        .exec(&format!(
                            "ss -H -tunap 2>/dev/null | sed -n '{start},{end}p'"
                        ))?
                        .stdout,
                    parse_ss_ports as fn(&str) -> Vec<PortInfo>,
                )
            }
            Some("netstat") => {
                let start = offset.saturating_add(3);
                let end = end.saturating_add(2);
                (
                    client
                        .exec(&format!(
                            "netstat -tunap 2>/dev/null | sed -n '{start},{end}p'"
                        ))?
                        .stdout,
                    parse_netstat_ports as fn(&str) -> Vec<PortInfo>,
                )
            }
            Some(tool) => return Err(format!("Unsupported network tool: {tool}")),
            None => {
                return Err(
                    "No supported network socket tool is available on this server".to_string(),
                )
            }
        };
        Ok(page(parser(&output), limit))
    })
}

fn parse_load_averages(value: &str) -> [f64; 3] {
    let fields: Vec<f64> = value
        .split_whitespace()
        .take(3)
        .filter_map(|value| value.parse().ok())
        .collect();
    [
        fields.first().copied().unwrap_or(0.0),
        fields.get(1).copied().unwrap_or(0.0),
        fields.get(2).copied().unwrap_or(0.0),
    ]
}

fn parse_cpu_utilization(before: &str, after: &str) -> f64 {
    let parse_row = |value: &str| {
        value
            .split_whitespace()
            .filter_map(|field| field.parse::<u64>().ok())
            .collect::<Vec<_>>()
    };
    let before = parse_row(before);
    let after = parse_row(after);
    if before.len() < 5 || after.len() < 5 {
        return 0.0;
    }
    let total_a: u64 = before.iter().sum();
    let total_b: u64 = after.iter().sum();
    let idle_a = before.get(3).copied().unwrap_or(0) + before.get(4).copied().unwrap_or(0);
    let idle_b = after.get(3).copied().unwrap_or(0) + after.get(4).copied().unwrap_or(0);
    let total = total_b.saturating_sub(total_a);
    if total == 0 {
        0.0
    } else {
        ((total.saturating_sub(idle_b.saturating_sub(idle_a))) as f64 / total as f64 * 100.0)
            .clamp(0.0, 100.0)
    }
}

fn parse_memory(value: &str) -> MemoryStats {
    let mut total = 0;
    let mut available = 0;
    let mut free = 0;
    let mut buffers = 0;
    let mut cached = 0;
    let mut reclaimable = 0;
    let mut shared = 0;
    for line in value.lines() {
        let mut fields = line.split_whitespace();
        let Some(label) = fields.next() else { continue };
        let amount = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            * 1024;
        match label {
            "MemTotal:" => total = amount,
            "MemAvailable:" => available = amount,
            "MemFree:" => free = amount,
            "Buffers:" => buffers = amount,
            "Cached:" => cached = amount,
            "SReclaimable:" => reclaimable = amount,
            "Shmem:" => shared = amount,
            _ => {}
        }
    }
    if available == 0 {
        available = free
            .saturating_add(buffers)
            .saturating_add(cached)
            .saturating_add(reclaimable)
            .saturating_sub(shared)
            .min(total);
    }
    let used = total.saturating_sub(available);
    MemoryStats {
        used_bytes: used,
        free_bytes: available,
        total_bytes: total,
        percent: if total == 0 {
            0.0
        } else {
            used as f64 / total as f64 * 100.0
        },
    }
}

fn parse_swap(value: &str) -> SwapStats {
    let mut total = 0;
    let mut free = 0;
    for line in value.lines() {
        let mut fields = line.split_whitespace();
        let Some(label) = fields.next() else { continue };
        let amount = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            * 1024;
        match label {
            "SwapTotal:" => total = amount,
            "SwapFree:" => free = amount,
            _ => {}
        }
    }
    let used = total.saturating_sub(free);
    SwapStats {
        used_bytes: used,
        total_bytes: total,
        percent: if total == 0 {
            0.0
        } else {
            used as f64 / total as f64 * 100.0
        },
    }
}

fn parse_disks(value: &str) -> Vec<DiskUsage> {
    value
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let total = fields[1].parse::<u64>().ok()? * 1024;
            let used = fields[2].parse::<u64>().ok()? * 1024;
            let available = fields[3].parse::<u64>().ok()? * 1024;
            let percent = fields[4].trim_end_matches('%').parse().unwrap_or(0.0);
            Some(DiskUsage {
                filesystem: fields[0].to_string(),
                total_bytes: total,
                used_bytes: used,
                available_bytes: available,
                percent,
                mount: fields[5..].join(" "),
            })
        })
        .filter(|disk: &DiskUsage| disk.total_bytes > 0)
        .take(20)
        .collect()
}

fn parse_interfaces(value: &str) -> Vec<NetworkInterface> {
    let mut result: Vec<NetworkInterface> = Vec::new();
    for line in value.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let Some(name) = fields.get(1) else { continue };
        let Some(kind_index) = fields
            .iter()
            .position(|field| *field == "inet" || *field == "inet6")
        else {
            continue;
        };
        let Some(address) = fields.get(kind_index + 1) else {
            continue;
        };
        if let Some(item) = result.iter_mut().find(|item| item.name == *name) {
            item.addresses.push((*address).to_string());
        } else {
            result.push(NetworkInterface {
                name: (*name).to_string(),
                addresses: vec![(*address).to_string()],
            });
        }
    }
    result
}

fn parse_ss_ports(value: &str) -> Vec<PortInfo> {
    value
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                return None;
            }
            let process = fields
                .get(6..)
                .map(|items| items.join(" "))
                .unwrap_or_default();
            let pid = process
                .split("pid=")
                .nth(1)
                .and_then(|value| {
                    value
                        .split(|character: char| !character.is_ascii_digit())
                        .next()
                })
                .and_then(|value| value.parse().ok());
            Some(PortInfo {
                protocol: fields[0].to_string(),
                state: fields[1].to_string(),
                local_address: fields[4.min(fields.len() - 1)].to_string(),
                remote_address: fields[5.min(fields.len() - 1)].to_string(),
                process,
                pid,
            })
        })
        .collect()
}

fn parse_netstat_ports(value: &str) -> Vec<PortInfo> {
    value
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 || (!fields[0].starts_with("tcp") && !fields[0].starts_with("udp"))
            {
                return None;
            }
            let (state, process_start) =
                if fields.get(5).is_some_and(|value| is_socket_state(value)) {
                    (fields[5].to_string(), 6)
                } else {
                    ("—".to_string(), 5)
                };
            let process = fields
                .get(process_start..)
                .map(|items| items.join(" "))
                .unwrap_or_default();
            Some(PortInfo {
                protocol: fields[0].to_string(),
                state,
                local_address: fields[3].to_string(),
                remote_address: fields[4].to_string(),
                pid: parse_netstat_pid(&process),
                process,
            })
        })
        .collect()
}

fn is_socket_state(value: &str) -> bool {
    matches!(
        value,
        "LISTEN"
            | "ESTABLISHED"
            | "SYN_SENT"
            | "SYN_RECV"
            | "FIN_WAIT1"
            | "FIN_WAIT2"
            | "TIME_WAIT"
            | "CLOSE_WAIT"
            | "LAST_ACK"
            | "CLOSING"
            | "CLOSED"
            | "UNKNOWN"
    )
}

fn parse_netstat_pid(process: &str) -> Option<u32> {
    process
        .split_once("pid=")
        .map(|(_, value)| value)
        .or_else(|| process.split('/').next())
        .and_then(|value| {
            value
                .split(|character: char| !character.is_ascii_digit())
                .find(|value| !value.is_empty())
        })
        .and_then(|value| value.parse().ok())
}

fn validate_unit_name(value: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.chars().any(|character| {
            character.is_whitespace() || character == ';' || character == '&' || character == '|'
        })
    {
        return Err("Invalid systemd service name".to_string());
    }
    Ok(())
}

fn docker_runtime(client: &mut crate::ssh::SshClient) -> Result<String, String> {
    if let Some(runtime) = client.container_runtime() {
        return Ok(runtime.to_string());
    }
    let capabilities = detect_capabilities(client)?;
    let mut permission_fallback = None;
    let mut diagnostics = Vec::new();
    for (runtime, available) in [
        ("docker", capabilities.docker),
        ("podman", capabilities.podman),
    ] {
        if !available {
            continue;
        }
        let output = match client.exec_bounded_with_timeout(
            &format!("{runtime} info >/dev/null"),
            MAX_RUNTIME_PROBE_OUTPUT_BYTES,
            RUNTIME_PROBE_TIMEOUT,
        ) {
            Ok(output) => output,
            Err(error) => {
                diagnostics.push(format!("{runtime}: {error}"));
                continue;
            }
        };
        if output.exit_code == 0 {
            let runtime = runtime.to_string();
            client.remember_container_runtime(runtime.clone());
            return Ok(runtime);
        }
        if is_permission_error(&output) {
            permission_fallback.get_or_insert_with(|| runtime.to_string());
        } else {
            diagnostics.push(format!("{runtime}: {}", command_error(&output)));
        }
    }
    if let Some(runtime) = permission_fallback {
        client.remember_container_runtime(runtime.clone());
        return Ok(runtime);
    }
    if diagnostics.is_empty() {
        Err("Docker or Podman is not installed on this server".to_string())
    } else {
        Err(format!(
            "No usable container runtime is available. {}",
            diagnostics.join("; ")
        ))
    }
}

pub(crate) fn resolve_container_shell_privileged<F>(
    client: &mut crate::ssh::SshClient,
    profile: &ServerProfile,
    store: &Store,
    mut probe_command: F,
) -> Result<&'static str, String>
where
    F: FnMut(&str) -> String,
{
    for shell in ["/bin/sh", "/bin/bash", "/bin/ash", "/bin/zsh"] {
        let command = probe_command(shell);
        let output = client.exec(&command)?;
        if output.exit_code == 0 {
            return Ok(shell);
        }
        if is_permission_error(&output) {
            match execute_privileged(client, profile, store, &command) {
                Ok(_) => return Ok(shell),
                Err(error) if error.contains("status 126") || error.contains("status 127") => {}
                Err(error) => return Err(error),
            }
        } else if !matches!(output.exit_code, 126 | 127) {
            return Err(command_error(&output));
        }
    }
    Err(
        "No supported command shell was found in this container. It may use a distroless image."
            .to_string(),
    )
}

#[derive(Clone, Copy, PartialEq)]
enum ContainerRuntimeAccess {
    Direct,
    PasswordlessSudo,
}

fn ensure_container_running(
    client: &mut crate::ssh::SshClient,
    runtime: &str,
    container: &str,
) -> Result<ContainerRuntimeAccess, String> {
    let command = format!(
        "{runtime} inspect --format {} {}",
        quote_shell("{{.State.Running}}"),
        quote_shell(container)
    );
    let output = client.exec_bounded(&command, MAX_RUNTIME_PROBE_OUTPUT_BYTES)?;
    let (running, access) = if output.exit_code == 0 {
        (output.stdout, ContainerRuntimeAccess::Direct)
    } else if is_permission_error(&output) {
        if client.exec("sudo -n true")?.exit_code != 0 {
            return Err(container_terminal_permission_error());
        }
        let privileged = client.exec_bounded(
            &format!("sudo -n sh -c {}", quote_shell(&command)),
            MAX_RUNTIME_PROBE_OUTPUT_BYTES,
        )?;
        if privileged.exit_code != 0 {
            return Err(command_error(&privileged));
        }
        (privileged.stdout, ContainerRuntimeAccess::PasswordlessSudo)
    } else {
        return Err(command_error(&output));
    };
    if running.trim() == "true" {
        Ok(access)
    } else {
        Err("Start the container before opening an exec shell.".to_string())
    }
}

fn resolve_container_terminal_shell(
    client: &mut crate::ssh::SshClient,
    runtime: &str,
    container: &str,
    access: ContainerRuntimeAccess,
) -> Result<&'static str, String> {
    for shell in ["/bin/sh", "/bin/bash", "/bin/ash", "/bin/zsh"] {
        let command = runtime_shell_probe(runtime, container, shell);
        let command = if access == ContainerRuntimeAccess::PasswordlessSudo {
            format!("sudo -n sh -c {}", quote_shell(&command))
        } else {
            command
        };
        let output = client.exec(&command)?;
        if output.exit_code == 0 {
            return Ok(shell);
        }
        if is_permission_error(&output) {
            return Err(container_terminal_permission_error());
        }
        if !matches!(output.exit_code, 126 | 127) {
            return Err(command_error(&output));
        }
    }
    Err(
        "No supported command shell was found in this container. It may use a distroless image."
            .to_string(),
    )
}

fn container_terminal_permission_error() -> String {
    "Container Exec requires direct access to the Docker/Podman socket or passwordless sudo. Add the SSH user to the runtime's group, enable rootless Podman, or use the server terminal with sudo.".to_string()
}

fn runtime_shell_probe(runtime: &str, container: &str, shell: &str) -> String {
    format!(
        "{runtime} exec {} {} -c {}",
        quote_shell(container),
        quote_shell(shell),
        quote_shell("exit")
    )
}

fn journal_grep_pattern(value: &str) -> String {
    let mut pattern = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '.' | '^' | '$' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?'
        ) {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern
}

pub(crate) fn docker_since_argument(since: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = since.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value
        .chars()
        .any(|character| matches!(character, '\0' | '\n' | '\r'))
    {
        return Err("Invalid log time filter".to_string());
    }
    let value = match value {
        "1 hour ago" => "1h".to_string(),
        "today" => "today".to_string(),
        _ => value.to_string(),
    };
    Ok(Some(value))
}

pub(crate) fn docker_since_shell_argument(since: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = docker_since_argument(since)? else {
        return Ok(None);
    };
    if value == "today" {
        return Ok(Some(
            "\"$(date '+%Y-%m-%dT00:00:00%z' | sed 's/\\([+-][0-9][0-9]\\)\\([0-9][0-9]\\)$/\\1:\\2/')\""
                .to_string(),
        ));
    }
    Ok(Some(quote_shell(&value)))
}

fn docker_logs_command(
    runtime: &str,
    container: &str,
    lines: u32,
    since: Option<&str>,
) -> Result<String, String> {
    let mut command = format!("{runtime} logs --tail {}", lines.clamp(1, 5000));
    if let Some(since) = docker_since_shell_argument(since)? {
        command.push_str(&format!(" --since {since}"));
    }
    command.push_str(&format!(" {}", quote_shell(container)));
    Ok(command)
}

fn run_log_command(
    client: &mut crate::ssh::SshClient,
    profile: &ServerProfile,
    store: &Store,
    command: &str,
) -> Result<String, String> {
    let output = client.exec_bounded(command, MAX_LOG_OUTPUT_BYTES)?;
    if output.exit_code == 0 {
        Ok(bounded_output(output.stdout))
    } else if is_permission_error(&output) {
        execute_privileged_bounded(client, profile, store, command, MAX_LOG_OUTPUT_BYTES)
            .map(bounded_output)
    } else {
        Err(command_error(&output))
    }
}

fn docker_collection(
    client: &mut crate::ssh::SshClient,
    profile: &ServerProfile,
    store: &Store,
    runtime: &str,
    section: &str,
    offset: usize,
    limit: usize,
) -> Result<(String, String), String> {
    let offset = offset.to_string();
    let limit = limit.to_string();
    let arguments = [runtime, section, offset.as_str(), limit.as_str()];
    let output = match client.exec_posix_script_bounded(
        DOCKER_COLLECTION_SCRIPT,
        &arguments,
        MAX_DOCKER_PAGE_OUTPUT_BYTES,
    ) {
        Ok(output) => output,
        Err(error) if is_permission_message(&error) => execute_privileged_posix_script_bounded(
            client,
            profile,
            store,
            DOCKER_COLLECTION_SCRIPT,
            &arguments,
            MAX_DOCKER_PAGE_OUTPUT_BYTES,
        )?,
        Err(error) => return Err(error),
    };
    let (items, stats) = parse_docker_collection(&output)?;
    Ok((items.to_string(), stats.to_string()))
}

fn parse_docker_collection(output: &str) -> Result<(&str, &str), String> {
    let items_start = output
        .strip_prefix(DOCKER_ITEMS_MARKER)
        .and_then(|value| value.strip_prefix('\n'))
        .ok_or_else(|| "The container runtime returned an invalid resource response".to_string())?;
    let stats_marker = format!("\n{DOCKER_STATS_MARKER}\n");
    items_start
        .split_once(&stats_marker)
        .ok_or_else(|| "The container runtime returned an incomplete resource response".to_string())
}

fn parse_docker_containers(output: &str) -> Vec<ContainerInfo> {
    output
        .lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            Some(ContainerInfo {
                id: json_text_any(&value, &["ID", "Id"]),
                name: json_text_any(&value, &["Names", "Name"]),
                image: json_text(&value, "Image"),
                state: json_text(&value, "State"),
                status: json_text(&value, "Status"),
                ports: json_text(&value, "Ports"),
                cpu_percent: None,
                memory_usage_bytes: None,
                memory_limit_bytes: None,
                memory_percent: None,
                network_rx_bytes: None,
                network_tx_bytes: None,
                block_read_bytes: None,
                block_write_bytes: None,
            })
        })
        .collect()
}

fn parse_docker_stats(output: &str) -> Vec<ContainerInfo> {
    output
        .lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            let mem = json_text(&value, "MemUsage");
            let net = json_text(&value, "NetIO");
            let block = json_text(&value, "BlockIO");
            let (memory_usage_bytes, memory_limit_bytes) = parse_pair_sizes(&mem);
            let (network_rx_bytes, network_tx_bytes) = parse_pair_sizes(&net);
            let (block_read_bytes, block_write_bytes) = parse_pair_sizes(&block);
            Some(ContainerInfo {
                id: json_text_any(&value, &["ID", "Id"]),
                name: json_text_any(&value, &["Name", "Names"]),
                image: String::new(),
                state: String::new(),
                status: String::new(),
                ports: String::new(),
                cpu_percent: parse_percent(&json_text_any(&value, &["CPUPerc", "CPU"])),
                memory_usage_bytes,
                memory_limit_bytes,
                memory_percent: parse_percent(&json_text(&value, "MemPerc")),
                network_rx_bytes,
                network_tx_bytes,
                block_read_bytes,
                block_write_bytes,
            })
        })
        .collect()
}

fn parse_docker_images(output: &str) -> Vec<DockerImage> {
    output
        .lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            Some(DockerImage {
                id: json_text_any(&value, &["ID", "Id"]),
                repository: json_text(&value, "Repository"),
                tag: json_text(&value, "Tag"),
                size: json_text(&value, "Size"),
                created: json_text_any(&value, &["CreatedSince", "CreatedAt", "Created"]),
            })
        })
        .collect()
}

fn parse_docker_volumes(output: &str) -> Vec<DockerVolume> {
    output
        .lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            Some(DockerVolume {
                name: json_text(&value, "Name"),
                driver: json_text(&value, "Driver"),
                mountpoint: String::new(),
            })
        })
        .collect()
}

fn parse_docker_networks(output: &str) -> Vec<DockerNetwork> {
    output
        .lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            Some(DockerNetwork {
                id: json_text_any(&value, &["ID", "Id"]),
                name: json_text(&value, "Name"),
                driver: json_text(&value, "Driver"),
                scope: json_text(&value, "Scope"),
            })
        })
        .collect()
}

fn json_text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn json_text_any(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

fn parse_percent(value: &str) -> Option<f64> {
    value.trim().trim_end_matches('%').parse().ok()
}

fn parse_pair_sizes(value: &str) -> (Option<u64>, Option<u64>) {
    let values: Vec<Option<u64>> = value.split('/').take(2).map(parse_human_size).collect();
    (
        values.first().copied().flatten(),
        values.get(1).copied().flatten(),
    )
}

fn parse_human_size(value: &str) -> Option<u64> {
    let value = value.trim().replace(' ', "");
    let lower = value.to_ascii_lowercase();
    let suffixes = [
        ("tib", 1024_f64.powi(4)),
        ("tb", 1000_f64.powi(4)),
        ("gib", 1024_f64.powi(3)),
        ("gb", 1000_f64.powi(3)),
        ("mib", 1024_f64.powi(2)),
        ("mb", 1000_f64.powi(2)),
        ("kib", 1024_f64),
        ("kb", 1000_f64),
        ("b", 1_f64),
    ];
    let (number, multiplier) = suffixes
        .iter()
        .find_map(|(suffix, multiplier)| {
            lower
                .strip_suffix(suffix)
                .map(|number| (number, *multiplier))
        })
        .unwrap_or((lower.as_str(), 1_f64));
    number
        .parse::<f64>()
        .ok()
        .map(|number| (number * multiplier) as u64)
}

pub fn list_files(
    store: &Store,
    server_id: &str,
    request: &RemotePathRequest,
    operation_id: Option<&str>,
) -> Result<Page<RemoteFile>, String> {
    let path = remote_path(&request.path);
    with_client(store, server_id, operation_id, |client, _profile| {
        client.check_cancelled()?;
        let sftp = client.sftp()?;
        let mut directory = sftp
            .opendir(&path)
            .map_err(|error| format!("Could not list {}: {error}", path.display()))?;
        let limit = page_limit(request.limit);
        let mut visible_index = 0_usize;
        let mut result = Vec::with_capacity(limit.saturating_add(1));
        loop {
            client.check_cancelled()?;
            let (filename, stat) = match directory.readdir() {
                Ok(entry) => entry,
                // libssh2 reports end-of-directory as LIBSSH2_ERROR_FILE.
                Err(error) if error.code() == ErrorCode::Session(-16) => break,
                Err(error) => return Err(format!("Could not list {}: {error}", path.display())),
            };
            if filename == Path::new(".") || filename == Path::new("..") {
                continue;
            }
            let Some(name) = filename
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
            else {
                continue;
            };
            let hidden = name.starts_with('.');
            if hidden && !request.show_hidden {
                continue;
            }
            if visible_index < request.offset {
                visible_index += 1;
                continue;
            }
            result.push(remote_file(path.join(filename), stat, hidden));
            visible_index += 1;
            if result.len() > limit {
                break;
            }
        }
        Ok(page(result, limit))
    })
}

pub fn log_files(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<Vec<String>, String> {
    with_client(store, server_id, operation_id, |client, _| {
        let sftp = client.sftp()?;
        let mut pending = std::collections::VecDeque::from([(PathBuf::from("/var/log"), 0_u8)]);
        let mut files = Vec::new();
        while let Some((path, depth)) = pending.pop_front() {
            client.check_cancelled()?;
            let Ok(mut directory) = sftp.opendir(&path) else {
                if depth == 0 {
                    return Err("The remote /var/log directory is unavailable".to_string());
                }
                continue;
            };
            loop {
                client.check_cancelled()?;
                let (filename, stat) = match directory.readdir() {
                    Ok(entry) => entry,
                    Err(error) if error.code() == ErrorCode::Session(-16) => break,
                    Err(_) => break,
                };
                if filename == Path::new(".") || filename == Path::new("..") {
                    continue;
                }
                let full_path = path.join(filename);
                if is_directory(stat.perm) {
                    if depth < 4 {
                        pending.push_back((full_path, depth + 1));
                    }
                } else {
                    files.push(full_path.to_string_lossy().to_string());
                    if files.len() >= 500 {
                        pending.clear();
                        break;
                    }
                }
            }
        }
        files.sort();
        Ok(files)
    })
}

pub fn read_file(
    store: &Store,
    server_id: &str,
    path: &str,
    operation_id: Option<&str>,
) -> Result<String, String> {
    let path = remote_path(path);
    with_client(store, server_id, operation_id, |client, _| {
        client.check_cancelled()?;
        let sftp = client.sftp()?;
        let mut file = sftp
            .open(&path)
            .map_err(|error| format!("Could not open {}: {error}", path.display()))?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 128 * 1024];
        loop {
            client.check_cancelled()?;
            let size = file
                .read(&mut buffer)
                .map_err(|error| format!("Could not read {}: {error}", path.display()))?;
            if size == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..size]);
            if bytes.len() > 5 * 1024 * 1024 {
                return Err("This editor is limited to files smaller than 5 MB".to_string());
            }
        }
        if bytes.contains(&0) {
            return Err("That file looks binary and cannot be previewed in the editor".to_string());
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    })
}

pub fn write_file(
    store: &Store,
    server_id: &str,
    path: &str,
    content: &str,
    operation_id: Option<&str>,
) -> Result<(), String> {
    if content.len() > 5 * 1024 * 1024 {
        return Err("This editor is limited to files smaller than 5 MB".to_string());
    }
    let path = remote_path(path);
    with_client(store, server_id, operation_id, |client, _| {
        client.check_cancelled()?;
        let sftp = client.sftp()?;
        let original_permissions = sftp
            .stat(&path)
            .ok()
            .and_then(|stat| stat.perm)
            .map(|permissions| permissions & 0o7777);
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "Choose a file to save".to_string())?;
        let temporary_path = path.with_file_name(format!(
            ".{}.serverbox-{}.tmp",
            name.to_string_lossy(),
            Uuid::new_v4()
        ));
        let write_result = (|| -> Result<(), String> {
            let mut file = sftp.create(&temporary_path).map_err(|error| {
                format!("Could not write {}: {error}", temporary_path.display())
            })?;
            for chunk in content.as_bytes().chunks(128 * 1024) {
                client.check_cancelled()?;
                file.write_all(chunk).map_err(|error| {
                    format!("Could not write {}: {error}", temporary_path.display())
                })?;
            }
            file.flush().map_err(|error| {
                format!(
                    "Could not finish writing {}: {error}",
                    temporary_path.display()
                )
            })?;
            if let Some(permissions) = original_permissions {
                sftp.setstat(
                    &temporary_path,
                    FileStat {
                        size: None,
                        uid: None,
                        gid: None,
                        perm: Some(permissions),
                        atime: None,
                        mtime: None,
                    },
                )
                .map_err(|error| {
                    format!(
                        "Could not preserve permissions for {}: {error}",
                        path.display()
                    )
                })?;
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = sftp.unlink(&temporary_path);
            return Err(error);
        }
        if let Err(error) = client.check_cancelled() {
            let _ = sftp.unlink(&temporary_path);
            return Err(error);
        }
        let rename_flags = RenameFlags::ATOMIC | RenameFlags::NATIVE | RenameFlags::OVERWRITE;
        if let Err(error) = sftp.rename(&temporary_path, &path, Some(rename_flags)) {
            let _ = sftp.unlink(&temporary_path);
            return Err(format!("Could not save {}: {error}", path.display()));
        }
        Ok(())
    })
}

pub fn file_action(
    store: &Store,
    server_id: &str,
    action: &str,
    path: &str,
    target: Option<String>,
    mode: Option<String>,
    operation_id: Option<&str>,
) -> Result<(), String> {
    let path = remote_path(path);
    with_client(store, server_id, operation_id, |client, profile| {
        client.check_cancelled()?;
        let cancellation = client.cancellation_token();
        let sftp = client.sftp()?;
        let result = match action {
            "mkdir" => sftp
                .mkdir(&path, 0o755)
                .map_err(|error| format!("Could not create folder: {error}")),
            "touch" => {
                let _ = sftp
                    .create(&path)
                    .map_err(|error| format!("Could not create file: {error}"))?;
                Ok(())
            }
            "rename" => {
                let target = target
                    .as_deref()
                    .ok_or_else(|| "Choose a new name".to_string())?;
                let destination = path.parent().unwrap_or(Path::new("/")).join(target);
                sftp.rename(&path, &destination, Some(RenameFlags::OVERWRITE))
                    .map_err(|error| format!("Could not rename file: {error}"))
            }
            "delete" => delete_remote(&sftp, &path, cancellation.as_ref()),
            "chmod" => {
                let mode = mode
                    .as_deref()
                    .ok_or_else(|| "Enter a permission mode such as 644".to_string())?;
                let mode = u32::from_str_radix(mode.trim().trim_start_matches('0'), 8)
                    .map_err(|_| "Permission mode must be octal, such as 644 or 755".to_string())?;
                let stat = sftp
                    .stat(&path)
                    .map_err(|error| format!("Could not read file permissions: {error}"))?;
                sftp.setstat(
                    &path,
                    FileStat {
                        perm: Some(mode),
                        ..stat
                    },
                )
                .map_err(|error| format!("Could not change permissions: {error}"))
            }
            "chown" => {
                let owner = target
                    .as_deref()
                    .ok_or_else(|| "Enter an owner as uid:gid".to_string())?;
                let mut fields = owner.split(':');
                let uid = fields
                    .next()
                    .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
                    .ok_or_else(|| "Owner must use numeric uid:gid values".to_string())?;
                let gid = fields
                    .next()
                    .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
                    .ok_or_else(|| "Owner must use numeric uid:gid values".to_string())?;
                if fields.next().is_some() {
                    return Err("Owner must use uid:gid".to_string());
                }
                execute_privileged(
                    client,
                    profile,
                    store,
                    &format!("chown {uid}:{gid} {}", quote_shell(&path.to_string_lossy())),
                )
                .map(|_| ())
            }
            _ => Err("Unsupported file action".to_string()),
        };
        result?;
        ensure_not_cancelled(cancellation.as_ref())
    })
}

pub fn upload_path(
    store: &Store,
    server_id: &str,
    local_path: &str,
    remote_path_value: &str,
    overwrite: bool,
    app: AppHandle,
    operation_id: Option<&str>,
) -> Result<TransferProgress, String> {
    let source = resolve_local_path(local_path);
    if !source.exists() {
        return Err("The local upload source does not exist".to_string());
    }
    let metadata = fs::metadata(&source)
        .map_err(|error| format!("Could not inspect upload source: {error}"))?;
    let transfer_id = Uuid::new_v4().to_string();
    let (total_bytes, total_files) = if metadata.is_dir() {
        WalkDir::new(&source)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .fold((0, 0), |(bytes, files), entry| {
                (
                    bytes + entry.metadata().map(|meta| meta.len()).unwrap_or(0),
                    files + 1,
                )
            })
    } else {
        (metadata.len(), 1)
    };
    let initial = progress(
        &transfer_id,
        "upload",
        local_path,
        0,
        total_bytes,
        0,
        total_files,
        false,
        None,
    );
    emit_progress(&app, &initial);
    let result = with_client(store, server_id, operation_id, |client, _| {
        let cancellation = client.cancellation_token();
        let sftp = client.sftp()?;
        ensure_not_cancelled(cancellation.as_ref())?;
        let remote_root = remote_path(remote_path_value);
        let remote_destination = if metadata.is_dir() {
            remote_root
        } else {
            let name = source
                .file_name()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| "Choose a local file to upload".to_string())?;
            remote_root.join(name)
        };
        if !overwrite {
            let (paths, count) = upload_conflicts(
                &sftp,
                &source,
                &remote_destination,
                metadata.is_dir(),
                cancellation.as_ref(),
            )?;
            if count > 0 {
                let payload = serde_json::json!({ "paths": paths, "count": count });
                return Err(format!("UPLOAD_CONFLICT:{payload}"));
            }
        }
        if metadata.is_dir() {
            upload_directory(
                &sftp,
                &source,
                &remote_destination,
                &app,
                &transfer_id,
                total_bytes,
                total_files,
                overwrite,
                cancellation.as_ref(),
            )
        } else {
            upload_file(
                &sftp,
                &source,
                &remote_destination,
                &app,
                &transfer_id,
                total_bytes,
                total_files,
                0,
                0,
                overwrite,
                cancellation.as_ref(),
            )
        }
    });
    match result {
        Ok((completed_bytes, completed_files)) => {
            let done = progress(
                &transfer_id,
                "upload",
                local_path,
                completed_bytes,
                total_bytes,
                completed_files,
                total_files,
                true,
                None,
            );
            emit_progress(&app, &done);
            Ok(done)
        }
        Err(error) => {
            let failed = progress(
                &transfer_id,
                "upload",
                local_path,
                0,
                total_bytes,
                0,
                total_files,
                true,
                Some(error.clone()),
            );
            emit_progress(&app, &failed);
            Err(error)
        }
    }
}

pub fn download_path(
    store: &Store,
    server_id: &str,
    remote_source: &str,
    local_target: &str,
    app: AppHandle,
    operation_id: Option<&str>,
) -> Result<TransferProgress, String> {
    let remote_source = remote_path(remote_source);
    let local_target = resolve_local_path(local_target);
    let transfer_id = Uuid::new_v4().to_string();
    let file_staging =
        local_target.with_file_name(format!(".serverbox-download-{transfer_id}.part"));
    let directory_staging = local_target.join(format!(".serverbox-download-{transfer_id}"));
    let mut created_directories = Vec::new();
    let mut file_staging_created = false;
    let mut directory_staging_created = false;
    let result = with_client(store, server_id, operation_id, |client, _| {
        let cancellation = client.cancellation_token();
        let sftp = client.sftp()?;
        ensure_not_cancelled(cancellation.as_ref())?;
        let stat = sftp
            .stat(&remote_source)
            .map_err(|error| format!("Could not inspect remote source: {error}"))?;
        let is_dir = is_directory(stat.perm);
        let (total_bytes, total_files) =
            remote_totals(&sftp, &remote_source, is_dir, cancellation.as_ref())?;
        let initial = progress(
            &transfer_id,
            "download",
            &remote_source.to_string_lossy(),
            0,
            total_bytes,
            0,
            total_files,
            false,
            None,
        );
        emit_progress(&app, &initial);
        let result = if is_dir {
            let name = remote_source
                .file_name()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| std::ffi::OsStr::new("root"));
            let destination = local_target.join(name);
            if destination.exists() {
                return Err(format!(
                    "The download destination already exists: {}",
                    destination.display()
                ));
            }
            ensure_local_directory(&local_target, &mut created_directories)?;
            fs::create_dir(&directory_staging)
                .map_err(|error| format!("Could not create download staging directory: {error}"))?;
            directory_staging_created = true;
            let result = download_directory(
                &sftp,
                &remote_source,
                &directory_staging,
                &app,
                &transfer_id,
                total_bytes,
                total_files,
                0,
                0,
                cancellation.as_ref(),
            )?;
            fs::rename(&directory_staging, &destination)
                .map_err(|error| format!("Could not finish download: {error}"))?;
            result
        } else {
            if local_target.exists() {
                return Err(format!(
                    "The download destination already exists: {}",
                    local_target.display()
                ));
            }
            let parent = local_target
                .parent()
                .ok_or_else(|| "The download destination must have a parent folder".to_string())?;
            ensure_local_directory(parent, &mut created_directories)?;
            file_staging_created = true;
            let result = download_file(
                &sftp,
                &remote_source,
                &file_staging,
                &app,
                &transfer_id,
                total_bytes,
                total_files,
                0,
                0,
                cancellation.as_ref(),
            )?;
            fs::rename(&file_staging, &local_target)
                .map_err(|error| format!("Could not finish download: {error}"))?;
            result
        };
        Ok((result.0, result.1, total_bytes, total_files))
    });
    match result {
        Ok((completed_bytes, completed_files, total_bytes, total_files)) => {
            let done = progress(
                &transfer_id,
                "download",
                &remote_source.to_string_lossy(),
                completed_bytes,
                total_bytes,
                completed_files,
                total_files,
                true,
                None,
            );
            emit_progress(&app, &done);
            Ok(done)
        }
        Err(error) => {
            if file_staging_created {
                let _ = fs::remove_file(&file_staging);
            }
            if directory_staging_created {
                let _ = fs::remove_dir_all(&directory_staging);
            }
            cleanup_created_directories(&created_directories);
            let failed = progress(
                &transfer_id,
                "download",
                &remote_source.to_string_lossy(),
                0,
                0,
                0,
                0,
                true,
                Some(error.clone()),
            );
            emit_progress(&app, &failed);
            Err(error)
        }
    }
}

fn ensure_local_directory(path: &Path, created: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match fs::metadata(current) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(format!(
                    "The download parent is not a folder: {}",
                    current.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current.parent().ok_or_else(|| {
                    format!("Could not find a parent folder for {}", path.display())
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "Could not inspect download directory {}: {error}",
                    current.display()
                ));
            }
        }
    }
    for directory in missing.iter().rev() {
        fs::create_dir(directory)
            .map_err(|error| format!("Could not create download directory: {error}"))?;
        created.push(directory.clone());
    }
    Ok(())
}

fn cleanup_created_directories(created: &[PathBuf]) {
    for directory in created.iter().rev() {
        let _ = fs::remove_dir(directory);
    }
}

fn remote_path(value: &str) -> PathBuf {
    let value = value.trim();
    if value.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(value)
    }
}

fn resolve_local_path(value: &str) -> PathBuf {
    let value = value.trim();
    if value == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(value))
    } else if let Some(relative) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        dirs::home_dir()
            .map(|home| home.join(relative))
            .unwrap_or_else(|| PathBuf::from(value))
    } else {
        PathBuf::from(value)
    }
}

fn remote_file(path: PathBuf, stat: FileStat, hidden: bool) -> RemoteFile {
    let kind = match stat.perm.unwrap_or(0) & 0o170000 {
        0o040000 => "directory",
        0o120000 => "symlink",
        _ => "file",
    };
    RemoteFile {
        name: path
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string()),
        path: path.to_string_lossy().to_string(),
        kind: kind.to_string(),
        size_bytes: stat.size.unwrap_or(0),
        modified_at: stat.mtime.map(|value| value as i64),
        permissions: stat.perm.map(permissions_string),
        uid: stat.uid,
        gid: stat.gid,
        hidden,
    }
}

fn is_directory(perm: Option<u32>) -> bool {
    perm.map(|value| value & 0o170000 == 0o040000)
        .unwrap_or(false)
}

fn permissions_string(value: u32) -> String {
    let chars = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    chars
        .iter()
        .map(|(bit, character)| if value & bit != 0 { *character } else { '-' })
        .collect()
}

fn delete_remote(
    sftp: &ssh2::Sftp,
    path: &Path,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(), String> {
    ensure_not_cancelled(cancellation)?;
    let stat = sftp
        .lstat(path)
        .map_err(|error| format!("Could not inspect remote path: {error}"))?;
    if is_directory(stat.perm) {
        for (child, _) in sftp
            .readdir(path)
            .map_err(|error| format!("Could not read remote folder: {error}"))?
        {
            ensure_not_cancelled(cancellation)?;
            delete_remote(sftp, &path.join(child), cancellation)?;
        }
        sftp.rmdir(path)
            .map_err(|error| format!("Could not delete remote folder: {error}"))
    } else {
        sftp.unlink(path)
            .map_err(|error| format!("Could not delete remote file: {error}"))
    }
}

fn upload_directory(
    sftp: &ssh2::Sftp,
    source: &Path,
    remote_root: &Path,
    app: &AppHandle,
    transfer_id: &str,
    total_bytes: u64,
    total_files: u64,
    overwrite: bool,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(u64, u64), String> {
    ensure_not_cancelled(cancellation)?;
    ensure_remote_directory(sftp, remote_root)?;
    let mut completed_bytes = 0;
    let mut completed_files = 0;
    for entry in WalkDir::new(source).into_iter().filter_map(Result::ok) {
        ensure_not_cancelled(cancellation)?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|error| error.to_string())?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let destination = remote_root.join(relative);
        if entry.file_type().is_dir() {
            ensure_remote_directory(sftp, &destination)?;
            continue;
        }
        let (bytes, files) = upload_file(
            sftp,
            entry.path(),
            &destination,
            app,
            transfer_id,
            total_bytes,
            total_files,
            completed_bytes,
            completed_files,
            overwrite,
            cancellation,
        )?;
        completed_bytes = bytes;
        completed_files = files;
    }
    Ok((completed_bytes, completed_files))
}

fn upload_file(
    sftp: &ssh2::Sftp,
    source: &Path,
    destination: &Path,
    app: &AppHandle,
    transfer_id: &str,
    total_bytes: u64,
    total_files: u64,
    mut completed_bytes: u64,
    mut completed_files: u64,
    overwrite: bool,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(u64, u64), String> {
    ensure_not_cancelled(cancellation)?;
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        ensure_remote_directory(sftp, parent)?;
    }
    let mut input = File::open(source)
        .map_err(|error| format!("Could not read {}: {error}", source.display()))?;
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "Choose a remote file destination".to_string())?;
    let temporary_path = destination.with_file_name(format!(
        ".{}.serverbox-upload-{}.part",
        name.to_string_lossy(),
        Uuid::new_v4()
    ));
    let original_permissions = overwrite
        .then(|| sftp.stat(destination).ok().and_then(|stat| stat.perm))
        .flatten()
        .map(|permissions| permissions & 0o7777);
    let write_result = (|| -> Result<(), String> {
        let mut output = sftp.create(&temporary_path).map_err(|error| {
            format!(
                "Could not create upload staging file {}: {error}",
                temporary_path.display()
            )
        })?;
        let mut buffer = [0u8; 128 * 1024];
        loop {
            ensure_not_cancelled(cancellation)?;
            let read = input
                .read(&mut buffer)
                .map_err(|error| format!("Could not read {}: {error}", source.display()))?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read]).map_err(|error| {
                format!("Could not write {}: {error}", temporary_path.display())
            })?;
            completed_bytes += read as u64;
            emit_progress(
                app,
                &progress(
                    transfer_id,
                    "upload",
                    &source.to_string_lossy(),
                    completed_bytes,
                    total_bytes,
                    completed_files,
                    total_files,
                    false,
                    None,
                ),
            );
        }
        output.flush().map_err(|error| {
            format!(
                "Could not finish writing {}: {error}",
                temporary_path.display()
            )
        })?;
        drop(output);
        if let Some(permissions) = original_permissions {
            sftp.setstat(
                &temporary_path,
                FileStat {
                    size: None,
                    uid: None,
                    gid: None,
                    perm: Some(permissions),
                    atime: None,
                    mtime: None,
                },
            )
            .map_err(|error| {
                format!(
                    "Could not preserve permissions for {}: {error}",
                    destination.display()
                )
            })?;
        }
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = sftp.unlink(&temporary_path);
        return Err(error);
    }
    if let Err(error) = ensure_not_cancelled(cancellation) {
        let _ = sftp.unlink(&temporary_path);
        return Err(error);
    }
    let mut rename_flags = RenameFlags::ATOMIC | RenameFlags::NATIVE;
    if overwrite {
        rename_flags |= RenameFlags::OVERWRITE;
    }
    if let Err(error) = sftp.rename(&temporary_path, destination, Some(rename_flags)) {
        let _ = sftp.unlink(&temporary_path);
        return Err(format!(
            "Could not finish uploading {}: {error}",
            destination.display()
        ));
    }
    completed_files += 1;
    Ok((completed_bytes, completed_files))
}

fn upload_conflicts(
    sftp: &ssh2::Sftp,
    source: &Path,
    destination: &Path,
    source_is_directory: bool,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(Vec<String>, usize), String> {
    let mut paths = Vec::new();
    let mut count = 0;
    if source_is_directory {
        for entry in WalkDir::new(source).into_iter().filter_map(Result::ok) {
            ensure_not_cancelled(cancellation)?;
            if !entry.file_type().is_file() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(source)
                .map_err(|error| error.to_string())?;
            record_upload_conflict(sftp, &destination.join(relative), &mut paths, &mut count);
        }
    } else {
        record_upload_conflict(sftp, destination, &mut paths, &mut count);
    }
    Ok((paths, count))
}

fn record_upload_conflict(
    sftp: &ssh2::Sftp,
    destination: &Path,
    paths: &mut Vec<String>,
    count: &mut usize,
) {
    if sftp.stat(destination).is_ok() {
        *count += 1;
        if paths.len() < 5 {
            paths.push(destination.to_string_lossy().to_string());
        }
    }
}

fn ensure_remote_directory(sftp: &ssh2::Sftp, path: &Path) -> Result<(), String> {
    match sftp.mkdir(path, 0o755) {
        Ok(()) => Ok(()),
        Err(mkdir_error) => match sftp.stat(path) {
            Ok(stat) if is_directory(stat.perm) => Ok(()),
            Ok(_) => Err(format!(
                "Could not create remote folder {}: a non-folder entry already exists",
                path.display()
            )),
            Err(_) => Err(format!(
                "Could not create remote folder {}: {mkdir_error}",
                path.display()
            )),
        },
    }
}

fn remote_totals(
    sftp: &ssh2::Sftp,
    path: &Path,
    is_dir: bool,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(u64, u64), String> {
    ensure_not_cancelled(cancellation)?;
    if !is_dir {
        return Ok((
            sftp.stat(path)
                .map_err(|error| error.to_string())?
                .size
                .unwrap_or(0),
            1,
        ));
    }
    let mut total = (0, 0);
    for (child, stat) in sftp.readdir(path).map_err(|error| error.to_string())? {
        ensure_not_cancelled(cancellation)?;
        let child_totals = remote_totals(
            sftp,
            &path.join(child),
            is_directory(stat.perm),
            cancellation,
        )?;
        total.0 += child_totals.0;
        total.1 += child_totals.1;
    }
    Ok(total)
}

fn download_directory(
    sftp: &ssh2::Sftp,
    source: &Path,
    local_root: &Path,
    app: &AppHandle,
    transfer_id: &str,
    total_bytes: u64,
    total_files: u64,
    mut completed_bytes: u64,
    mut completed_files: u64,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(u64, u64), String> {
    ensure_not_cancelled(cancellation)?;
    for (child, stat) in sftp
        .readdir(source)
        .map_err(|error| format!("Could not read remote folder: {error}"))?
    {
        ensure_not_cancelled(cancellation)?;
        let name = child.file_name().unwrap_or_default();
        let local = local_root.join(name);
        let remote = source.join(child);
        if is_directory(stat.perm) {
            fs::create_dir_all(&local)
                .map_err(|error| format!("Could not create {}: {error}", local.display()))?;
            (completed_bytes, completed_files) = download_directory(
                sftp,
                &remote,
                &local,
                app,
                transfer_id,
                total_bytes,
                total_files,
                completed_bytes,
                completed_files,
                cancellation,
            )?;
        } else {
            (completed_bytes, completed_files) = download_file(
                sftp,
                &remote,
                &local,
                app,
                transfer_id,
                total_bytes,
                total_files,
                completed_bytes,
                completed_files,
                cancellation,
            )?;
        }
    }
    Ok((completed_bytes, completed_files))
}

fn download_file(
    sftp: &ssh2::Sftp,
    source: &Path,
    destination: &Path,
    app: &AppHandle,
    transfer_id: &str,
    total_bytes: u64,
    total_files: u64,
    mut completed_bytes: u64,
    mut completed_files: u64,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(u64, u64), String> {
    ensure_not_cancelled(cancellation)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create {}: {error}", parent.display()))?;
    }
    let mut input = sftp
        .open(source)
        .map_err(|error| format!("Could not read {}: {error}", source.display()))?;
    let mut output = File::options()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("Could not create {}: {error}", destination.display()))?;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        ensure_not_cancelled(cancellation)?;
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("Could not read {}: {error}", source.display()))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| format!("Could not write {}: {error}", destination.display()))?;
        completed_bytes += read as u64;
        emit_progress(
            app,
            &progress(
                transfer_id,
                "download",
                &source.to_string_lossy(),
                completed_bytes,
                total_bytes,
                completed_files,
                total_files,
                false,
                None,
            ),
        );
    }
    ensure_not_cancelled(cancellation)?;
    completed_files += 1;
    Ok((completed_bytes, completed_files))
}

fn progress(
    transfer_id: &str,
    direction: &str,
    path: &str,
    completed_bytes: u64,
    total_bytes: u64,
    completed_files: u64,
    total_files: u64,
    done: bool,
    error: Option<String>,
) -> TransferProgress {
    TransferProgress {
        transfer_id: transfer_id.to_string(),
        direction: direction.to_string(),
        path: path.to_string(),
        completed_bytes,
        total_bytes,
        completed_files,
        total_files,
        done,
        error,
    }
}

fn emit_progress(app: &AppHandle, payload: &TransferProgress) {
    let _ = app.emit("transfer-progress", payload);
}
