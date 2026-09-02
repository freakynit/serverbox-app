use crate::models::*;
use crate::providers::{docker_since_shell_argument, resolve_container_shell_privileged};
use crate::ssh::{
    bounded_output, command_error, execute_privileged, execute_privileged_bounded,
    execute_privileged_long, is_permission_error, quote_shell, with_client, LONG_COMMAND_TIMEOUT,
    MAX_LOG_OUTPUT_BYTES,
};
use crate::storage::Store;
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

const SECURITY_SCRIPT: &str = r#"
updates=0
security=0
container_update=0
package_supported=0
last=
lines=

if command -v apt-get >/dev/null 2>&1; then
  package_supported=1
  lines=$(LC_ALL=C apt list --upgradable 2>/dev/null | sed '1d')
  updates=$(printf '%s\n' "$lines" | awk 'NF {n++} END {print n+0}')
  security=$(printf '%s\n' "$lines" | grep -Eic 'security|ubuntu.*-security' || true)
  last=$(stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -c %y /var/lib/apt/lists 2>/dev/null || true)
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  package_supported=1
  if command -v dnf >/dev/null 2>&1; then manager=dnf; else manager=yum; fi
  lines=$(LC_ALL=C "$manager" -q check-update 2>/dev/null || true)
  updates=$(printf '%s\n' "$lines" | awk 'NF >= 3 && $1 !~ /^Last/ {n++} END {print n+0}')
  security=$(LC_ALL=C "$manager" -q updateinfo list security updates 2>/dev/null | awk 'NF >= 3 {n++} END {print n+0}')
  last=$(stat -c %y "/var/cache/$manager" 2>/dev/null || true)
elif command -v zypper >/dev/null 2>&1; then
  package_supported=1
  lines=$(LC_ALL=C zypper --non-interactive list-updates 2>/dev/null || true)
  updates=$(printf '%s\n' "$lines" | awk -F '|' '$1 ~ /^[[:space:]]*v[[:space:]]*$/ {n++} END {print n+0}')
  security=$(LC_ALL=C zypper --non-interactive list-patches --category security 2>/dev/null | awk -F '|' '$1 ~ /^[[:space:]]*needed[[:space:]]*$/ {n++} END {print n+0}')
  last=$(stat -c %y /var/cache/zypp 2>/dev/null || true)
elif command -v pacman >/dev/null 2>&1; then
  package_supported=1
  lines=$(LC_ALL=C pacman -Qu 2>/dev/null || true)
  updates=$(printf '%s\n' "$lines" | awk 'NF {n++} END {print n+0}')
  last=$(stat -c %y /var/lib/pacman/sync 2>/dev/null || true)
elif command -v apk >/dev/null 2>&1; then
  package_supported=1
  lines=$(LC_ALL=C apk version -l '<' 2>/dev/null || true)
  updates=$(printf '%s\n' "$lines" | awk 'NF {n++} END {print n+0}')
  if apk audit --help >/dev/null 2>&1; then security=$(LC_ALL=C apk audit 2>/dev/null | awk 'NF {n++} END {print n+0}'); fi
  last=$(stat -c %y /var/cache/apk 2>/dev/null || true)
fi

printf '%s\n' "$lines" | grep -Eiq '^(docker|containerd|podman)' && container_update=1
reboot=0
if [ -e /var/run/reboot-required ]; then reboot=1
elif command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1 || reboot=1
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$updates" "$security" "$reboot" "$(uname -r 2>/dev/null || printf unknown)" "$last" "$container_update" "$package_supported"
(docker --version 2>/dev/null || podman --version 2>/dev/null || true)
"#;

pub fn compose_projects(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<Vec<ComposeProject>, String> {
    with_client(store, server_id, operation_id, |client, _| {
        // The script keeps its own 120s global deadline and per-project
        // guards, so its idle timeout must comfortably exceed that deadline;
        // otherwise a silent stretch aborts the scan before it can finish.
        let output = client.exec_posix_script_bounded_with_timeout(
            COMPOSE_SCAN_SCRIPT,
            &[],
            COMPOSE_SCAN_OUTPUT_LIMIT,
            COMPOSE_SCAN_IDLE_TIMEOUT,
        )?;
        Ok(parse_compose_scan(&output))
    })
}

pub fn compose_action(
    store: &Store,
    server_id: &str,
    path: &str,
    action: &str,
    service: Option<&str>,
    command: Option<&str>,
    operation_id: Option<&str>,
    lines: Option<u32>,
    since: Option<&str>,
) -> Result<String, String> {
    if path.trim().is_empty() || path.contains('\n') {
        return Err("Choose a valid Compose file".to_string());
    }
    if ![
        "up", "down", "restart", "pull", "rebuild", "logs", "exec", "scale",
    ]
    .contains(&action)
    {
        return Err("Unsupported Compose action".to_string());
    }
    if let Some(service) = service {
        validate_simple_name(service, "service")?;
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let args = match action {
            "up" => "up -d".to_string(),
            "down" => "down".to_string(),
            "restart" => format!("restart {}", service.map(quote_shell).unwrap_or_default()),
            "pull" => "pull".to_string(),
            "rebuild" => "up -d --build".to_string(),
            "logs" => {
                let mut args = format!("logs --tail {}", lines.unwrap_or(300).clamp(1, 5000));
                if let Some(since) = docker_since_shell_argument(since)? {
                    args.push_str(&format!(" --since {since}"));
                }
                args.push_str(&format!(
                    " {}",
                    service.map(quote_shell).unwrap_or_default()
                ));
                args
            }
            "exec" => {
                let service = service.ok_or_else(|| "Choose a Compose service".to_string())?;
                let command = command
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| "Enter a command".to_string())?;
                ensure_compose_service_running(client, profile, store, path, service)?;
                let shell = resolve_container_shell_privileged(client, profile, store, |shell| {
                    compose_command(
                        path,
                        &format!(
                            "exec -T {} {} -c {}",
                            quote_shell(service),
                            quote_shell(shell),
                            quote_shell("exit")
                        ),
                    )
                })?;
                format!(
                    "exec -T {} {} -c {}",
                    quote_shell(service),
                    quote_shell(shell),
                    quote_shell(command)
                )
            }
            "scale" => format!(
                "up -d --scale {}",
                quote_shell(
                    command
                        .filter(|value| value.contains('='))
                        .ok_or_else(|| "Enter scale as service=count".to_string())?
                )
            ),
            _ => unreachable!(),
        };
        let runner = compose_command(path, &args);
        let output = if action == "logs" {
            client.exec_bounded(&runner, MAX_LOG_OUTPUT_BYTES)?
        } else {
            // Rebuilds, pulls, and up/down can stay silent for minutes.
            client.exec_long(&runner)?
        };
        if output.exit_code == 0 {
            if action == "logs" {
                Ok(bounded_output(output.stdout))
            } else {
                Ok(format!("{}{}", output.stdout, output.stderr))
            }
        } else if is_permission_error(&output) {
            if action == "logs" {
                execute_privileged_bounded(client, profile, store, &runner, MAX_LOG_OUTPUT_BYTES)
                    .map(bounded_output)
            } else {
                execute_privileged_long(client, profile, store, &runner)
            }
        } else {
            Err(command_error(&output))
        }
    })
}

fn ensure_compose_service_running(
    client: &mut crate::ssh::SshClient,
    profile: &ServerProfile,
    store: &Store,
    path: &str,
    service: &str,
) -> Result<(), String> {
    let probe = compose_command(path, &format!("ps -q {}", quote_shell(service)));
    let output = client.exec_bounded(&probe, 64 * 1024)?;
    let running = if output.exit_code == 0 {
        output.stdout
    } else if is_permission_error(&output) {
        execute_privileged_bounded(client, profile, store, &probe, 64 * 1024)?
    } else {
        return Err(command_error(&output));
    };
    if running.trim().is_empty() {
        Err(format!(
            "Start {service} before running a command.",
            service = service
        ))
    } else {
        Ok(())
    }
}

pub fn firewall(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<FirewallSnapshot, String> {
    with_client(store, server_id, operation_id, |client, profile| {
        let provider = client.exec_ok("if command -v ufw >/dev/null 2>&1; then echo ufw; elif command -v firewall-cmd >/dev/null 2>&1; then echo firewalld; fi")?.trim().to_string();
        if provider.is_empty() {
            return Ok(FirewallSnapshot {
                provider: None,
                enabled: false,
                rules: vec![],
            });
        }
        let text = if provider == "ufw" {
            execute_privileged(client, profile, store, "LC_ALL=C ufw status numbered")?
        } else {
            client
                .exec("firewall-cmd --state 2>/dev/null; firewall-cmd --list-all 2>/dev/null")?
                .stdout
        };
        let enabled = if provider == "ufw" {
            text.lines()
                .next()
                .is_some_and(|line| line.trim().eq_ignore_ascii_case("Status: active"))
        } else {
            text.lines()
                .next()
                .is_some_and(|line| line.trim() == "running")
        };
        Ok(FirewallSnapshot {
            provider: Some(provider),
            enabled,
            rules: text
                .lines()
                .skip(1)
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect(),
        })
    })
}

pub fn firewall_action(
    store: &Store,
    server_id: &str,
    action: &str,
    port: Option<u32>,
    protocol: Option<&str>,
    source: Option<&str>,
    operation_id: Option<&str>,
) -> Result<(), String> {
    if !["enable", "disable", "allow", "deny"].contains(&action) {
        return Err("Unsupported firewall action".to_string());
    }
    if matches!(action, "allow" | "deny") && !matches!(port, Some(1..=65535)) {
        return Err("Port must be between 1 and 65535".to_string());
    }
    let protocol = protocol.unwrap_or("tcp");
    if !["tcp", "udp"].contains(&protocol) {
        return Err("Protocol must be TCP or UDP".to_string());
    }
    if let Some(source) = source {
        if !source
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ".:/".contains(ch))
        {
            return Err("Source must be an IP address or CIDR".to_string());
        }
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let provider = client.exec_ok("if command -v ufw >/dev/null 2>&1; then echo ufw; elif command -v firewall-cmd >/dev/null 2>&1; then echo firewalld; fi")?.trim().to_string();
        let command = match (provider.as_str(), action) {
            ("ufw", "enable") => "ufw --force enable".to_string(),
            ("ufw", "disable") => "ufw disable".to_string(),
            ("ufw", effect) => source
                .map(|source| {
                    format!(
                        "ufw {effect} from {source} to any port {} proto {protocol}",
                        port.unwrap()
                    )
                })
                .unwrap_or_else(|| format!("ufw {effect} {}/{protocol}", port.unwrap())),
            ("firewalld", "enable") => "systemctl enable --now firewalld".to_string(),
            ("firewalld", "disable") => "systemctl disable --now firewalld".to_string(),
            ("firewalld", effect) => {
                let verb = if effect == "allow" { "add" } else { "remove" };
                if let Some(source) = source {
                    if effect == "allow" {
                        format!("firewall-cmd --permanent --add-rich-rule='rule source address={source} port port={} protocol={protocol} accept' && firewall-cmd --reload", port.unwrap())
                    } else {
                        format!("firewall-cmd --permanent --add-rich-rule='rule source address={source} port port={} protocol={protocol} drop' && firewall-cmd --reload", port.unwrap())
                    }
                } else {
                    format!("firewall-cmd --permanent --{verb}-port={}/{protocol} && firewall-cmd --reload", port.unwrap())
                }
            }
            _ => return Err("Neither UFW nor firewalld is installed".to_string()),
        };
        execute_privileged(client, profile, store, &command).map(|_| ())
    })
}

pub fn authorized_keys(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<Vec<AuthorizedKey>, String> {
    with_client(store, server_id, operation_id, |client, _| {
        let text = client.exec_ok(r#"if ! command -v ssh-keygen >/dev/null 2>&1; then echo 'SSH key inspection requires ssh-keygen, which is not installed on this server' >&2; exit 69; fi; test ! -f ~/.ssh/authorized_keys || while IFS= read -r line; do case "$line" in ''|'#'*) continue;; esac; fingerprint=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'); [ -n "$fingerprint" ] && printf '%s\t%s\n' "$fingerprint" "$line"; done < ~/.ssh/authorized_keys"#)?;
        let mut keys = Vec::new();
        for record in text.lines().take(1_000) {
            let Some((fingerprint, line)) = record.split_once('\t') else {
                continue;
            };
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let key_index = fields.iter().position(|value| {
                value.starts_with("ssh-") || value.starts_with("ecdsa-") || value.starts_with("sk-")
            });
            let Some(index) = key_index else { continue };
            if fields.len() <= index + 1 {
                continue;
            }
            let mut hasher = DefaultHasher::new();
            line.hash(&mut hasher);
            keys.push(AuthorizedKey {
                id: format!("{:016x}", hasher.finish()),
                kind: fields[index].to_string(),
                fingerprint: fingerprint.to_string(),
                comment: fields.get(index + 2..).unwrap_or_default().join(" "),
                key: line.to_string(),
            });
        }
        Ok(keys)
    })
}

pub fn authorized_key_action(
    store: &Store,
    server_id: &str,
    action: &str,
    key: &str,
    operation_id: Option<&str>,
) -> Result<(), String> {
    if !["add", "remove"].contains(&action) || key.contains('\n') || key.len() > 20_000 {
        return Err("Invalid SSH key action".to_string());
    }
    if action == "add" && !(key.contains("ssh-") || key.contains("ecdsa-") || key.contains("sk-")) {
        return Err("Enter a valid OpenSSH public key".to_string());
    }
    with_client(store, server_id, operation_id, |client, _| {
        let command = if action == "add" {
            format!("umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -Fqx -- {} ~/.ssh/authorized_keys || printf '%s\\n' {} >> ~/.ssh/authorized_keys", quote_shell(key), quote_shell(key))
        } else {
            format!("test ! -f ~/.ssh/authorized_keys || {{ tmp=$(mktemp); grep -Fvx -- {} ~/.ssh/authorized_keys > \"$tmp\" || true; cat \"$tmp\" > ~/.ssh/authorized_keys; rm -f \"$tmp\"; }}", quote_shell(key))
        };
        client.exec_ok(&command).map(|_| ())
    })
}

pub fn security(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<SecuritySnapshot, String> {
    with_client(store, server_id, operation_id, |client, _| {
        // Update checks (`dnf check-update`, `apt list --upgradable`) can run
        // long without output; give them the extended idle timeout.
        let output = client.exec_bounded_with_timeout(
            SECURITY_SCRIPT,
            MAX_LOG_OUTPUT_BYTES,
            LONG_COMMAND_TIMEOUT,
        )?;
        if output.exit_code != 0 {
            return Err(command_error(&output));
        }
        let mut lines = output.stdout.lines();
        let fields = lines
            .next()
            .unwrap_or_default()
            .split('\t')
            .collect::<Vec<_>>();
        Ok(SecuritySnapshot {
            updates: fields.first().and_then(|v| v.parse().ok()).unwrap_or(0),
            security_updates: fields.get(1).and_then(|v| v.parse().ok()).unwrap_or(0),
            reboot_required: fields.get(2) == Some(&"1"),
            kernel_version: fields.get(3).unwrap_or(&"unknown").to_string(),
            last_package_update: fields
                .get(4)
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.to_string()),
            container_version: lines
                .next()
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string),
            container_update_available: fields.get(5) == Some(&"1"),
            package_updates_available: fields.get(6) == Some(&"1"),
        })
    })
}

pub fn quick_action(
    store: &Store,
    server_id: &str,
    action: &str,
    operation_id: Option<&str>,
) -> Result<String, String> {
    let command = match action {
        "reboot" => "if command -v shutdown >/dev/null 2>&1; then shutdown -r +1 'Scheduled by Serverbox'; elif command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then systemctl reboot; elif command -v reboot >/dev/null 2>&1; then reboot; else echo 'No supported reboot command is installed' >&2; exit 69; fi",
        "shutdown" => "if command -v shutdown >/dev/null 2>&1; then shutdown -h +1 'Scheduled by Serverbox'; elif command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then systemctl poweroff; elif command -v poweroff >/dev/null 2>&1; then poweroff; else echo 'No supported shutdown command is installed' >&2; exit 69; fi",
        "clear-cache" => "sync; echo 3 > /proc/sys/vm/drop_caches",
        "restart-ssh" => "if ! { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; } && ! command -v rc-service >/dev/null 2>&1 && ! command -v service >/dev/null 2>&1; then echo 'No supported service manager is available to restart SSH' >&2; exit 69; fi; nohup sh -c 'sleep 1; if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service; elif command -v rc-service >/dev/null 2>&1; then rc-service sshd restart 2>/dev/null || rc-service ssh restart; else service ssh restart 2>/dev/null || service sshd restart; fi' >/dev/null 2>&1 &",
        "restart-docker" => "if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then systemctl restart docker.service 2>/dev/null || systemctl restart podman.service; elif command -v rc-service >/dev/null 2>&1; then rc-service docker restart 2>/dev/null || rc-service podman restart; elif command -v service >/dev/null 2>&1; then service docker restart 2>/dev/null || service podman restart; else echo 'No supported service manager is available to restart the container runtime' >&2; exit 69; fi",
        "update-index" => "if command -v apt-get >/dev/null 2>&1; then apt-get update; elif command -v dnf >/dev/null 2>&1; then dnf makecache; elif command -v yum >/dev/null 2>&1; then yum makecache; elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive refresh; elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm; elif command -v apk >/dev/null 2>&1; then apk update; else echo 'No supported package manager is installed (APT, DNF, YUM, Zypper, Pacman, or APK)' >&2; exit 69; fi",
        "install-tools" => "if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y curl git htop jq; elif command -v dnf >/dev/null 2>&1; then dnf install -y curl git htop jq; elif command -v yum >/dev/null 2>&1; then yum install -y curl git htop jq; elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install curl git htop jq; elif command -v pacman >/dev/null 2>&1; then pacman -S --needed --noconfirm curl git htop jq; elif command -v apk >/dev/null 2>&1; then apk add curl git htop jq; else echo 'No supported package manager is installed (APT, DNF, YUM, Zypper, Pacman, or APK)' >&2; exit 69; fi",
        _ => return Err("Unsupported server action".to_string()),
    };
    with_client(store, server_id, operation_id, |client, profile| {
        execute_privileged_long(client, profile, store, command)
    })
}

pub fn run_command(
    store: &Store,
    server_id: &str,
    command: &str,
    operation_id: Option<&str>,
) -> Result<CommandResult, String> {
    if command.trim().is_empty() || command.len() > 20_000 {
        return Err("Enter a command no larger than 20 KB".to_string());
    }
    with_client(store, server_id, operation_id, |client, profile| {
        let output = client.exec(command)?;
        Ok(CommandResult {
            server_id: server_id.to_string(),
            server_name: profile.name.clone(),
            stdout: bounded_output(output.stdout),
            stderr: bounded_output(output.stderr),
            exit_code: output.exit_code,
            error: None,
        })
    })
}

fn validate_simple_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_.-".contains(ch))
    {
        Err(format!("Invalid {label} name"))
    } else {
        Ok(())
    }
}

const COMPOSE_MODE_MARKER: &str = "__SERVERBOX_COMPOSE_MODE__";
const COMPOSE_PROJECT_MARKER: &str = "__SERVERBOX_COMPOSE_PROJECT__";
const COMPOSE_SERVICES_MARKER: &str = "__SERVERBOX_COMPOSE_SERVICES__";
const COMPOSE_CONFIG_MARKER: &str = "__SERVERBOX_COMPOSE_CONFIG__";
const COMPOSE_RUNNING_MARKER: &str = "__SERVERBOX_COMPOSE_RUNNING__";
const COMPOSE_SCAN_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
/// Idle timeout for the Compose scan. The script's own global deadline is
/// 120 seconds, so this must be longer to let the deadline (not the SSH idle
/// timer) end a stalled scan gracefully.
const COMPOSE_SCAN_IDLE_TIMEOUT: Duration = Duration::from_secs(150);

// One self-contained POSIX shell script gathers every Compose project's
// services, resolved config, and running state in a single SSH round trip.
// Each section is framed by unique markers so Rust can split the output;
// per-command `timeout` and a global deadline keep one bad project from
// wedging the scan.
const COMPOSE_SCAN_SCRIPT: &str = r#"runner=''; mode='none'
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then runner='docker compose'; mode='services'; elif command -v docker-compose >/dev/null 2>&1; then runner='docker-compose'; mode='services'; elif command -v podman-compose >/dev/null 2>&1; then runner='podman-compose'; mode='states'; fi
printf '__SERVERBOX_COMPOSE_MODE__\t%s\n' "$mode"
[ -n "$runner" ] || exit 0
guard=''
command -v timeout >/dev/null 2>&1 && guard='timeout 15'
deadline=$(( $(date +%s 2>/dev/null || echo 0) + 120 ))
for root in "$HOME" /opt /srv /var/www; do [ -d "$root" ] && find "$root" -maxdepth 5 -type f \( -iname 'compose.yml' -o -iname 'compose.yaml' -o -iname 'docker-compose.yml' -o -iname 'docker-compose.yaml' -o -iname '*compose*.yml' -o -iname '*compose*.yaml' \) ! -iname '*override*.yml' ! -iname '*override*.yaml' 2>/dev/null; done | awk '!seen[$0]++' | head -100 | while IFS= read -r path; do
  now=$(date +%s 2>/dev/null || echo 0)
  [ "$now" -ge "$deadline" ] && break
  printf '\n__SERVERBOX_COMPOSE_PROJECT__\t%s\n' "$path"
  printf '\n__SERVERBOX_COMPOSE_SERVICES__\n'
  $guard $runner -f "$path" config --services 2>/dev/null || true
  printf '\n__SERVERBOX_COMPOSE_CONFIG__\n'
  $guard $runner -f "$path" config --format json 2>/dev/null || $guard $runner -f "$path" config 2>/dev/null || true
  printf '\n__SERVERBOX_COMPOSE_RUNNING__\n'
  if [ "$mode" = 'states' ]; then $guard $runner -f "$path" ps --format '{{.State}}' 2>/dev/null || true; else $guard $runner -f "$path" ps --services 2>/dev/null || true; fi
done
exit 0"#;

pub(crate) fn compose_command(path: &str, args: &str) -> String {
    let path = quote_shell(path);
    format!(
        "if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then docker compose -f {path} {args}; elif command -v docker-compose >/dev/null 2>&1; then docker-compose -f {path} {args}; elif command -v podman-compose >/dev/null 2>&1; then podman-compose -f {path} {args}; else echo 'Docker Compose is unavailable' >&2; exit 127; fi"
    )
}

fn marker_value<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.strip_prefix(marker)?.strip_prefix('\t')
}

#[derive(Clone, Copy, PartialEq)]
enum ComposeScanSection {
    Services,
    Config,
    Running,
}

fn parse_compose_scan(text: &str) -> Vec<ComposeProject> {
    let mut lines = text.lines();
    let mode = lines
        .next()
        .and_then(|line| marker_value(line, COMPOSE_MODE_MARKER))
        .map(str::trim);
    let services_mode = mode == Some("services");
    let states_mode = mode == Some("states");
    if !services_mode && !states_mode {
        return Vec::new();
    }
    // Each record is (path, [services, config, running]).
    let mut records: Vec<(String, [String; 3])> = Vec::new();
    let mut section: Option<ComposeScanSection> = None;
    for line in lines {
        if let Some(path) = marker_value(line, COMPOSE_PROJECT_MARKER) {
            records.push((path.to_string(), Default::default()));
            section = None;
        } else if line == COMPOSE_SERVICES_MARKER && !records.is_empty() {
            section = Some(ComposeScanSection::Services);
        } else if line == COMPOSE_CONFIG_MARKER && !records.is_empty() {
            section = Some(ComposeScanSection::Config);
        } else if line == COMPOSE_RUNNING_MARKER && !records.is_empty() {
            section = Some(ComposeScanSection::Running);
        } else if let Some((_, sections)) = records.last_mut() {
            let target = match section {
                Some(ComposeScanSection::Services) => &mut sections[0],
                Some(ComposeScanSection::Config) => &mut sections[1],
                Some(ComposeScanSection::Running) => &mut sections[2],
                None => continue,
            };
            target.push_str(line);
            target.push('\n');
        }
    }
    let mut projects = Vec::new();
    for (path, sections) in records {
        let [services_text, config, running_text] = sections;
        let services = services_text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if services.is_empty() {
            continue;
        }
        let (topology, environment) = compose_metadata(&config);
        let running = if services_mode {
            running_text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .count()
        } else {
            running_text
                .lines()
                .map(str::trim)
                .filter(|line| line.eq_ignore_ascii_case("running"))
                .count()
        };
        let name = std::path::Path::new(&path)
            .parent()
            .and_then(|dir| dir.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("compose")
            .to_string();
        projects.push(ComposeProject {
            name,
            path,
            services,
            running,
            topology,
            environment,
        });
    }
    projects
}

fn compose_metadata(text: &str) -> (Vec<String>, Vec<String>) {
    let value =
        serde_json::from_str::<Value>(text).or_else(|_| serde_yaml::from_str::<Value>(text));
    let Ok(value) = value else {
        return (vec![], vec![]);
    };
    let Some(services) = value.get("services").and_then(|value| value.as_object()) else {
        return (vec![], vec![]);
    };
    let mut topology = Vec::new();
    let mut environment = Vec::new();
    for (name, service) in services {
        if let Some(dependencies) = service.get("depends_on") {
            if let Some(items) = dependencies.as_object() {
                topology.extend(
                    items
                        .keys()
                        .map(|dependency| format!("{name} → {dependency}")),
                );
            }
            if let Some(items) = dependencies.as_array() {
                topology.extend(
                    items
                        .iter()
                        .filter_map(|dependency| dependency.as_str())
                        .map(|dependency| format!("{name} → {dependency}")),
                );
            }
        }
        if let Some(values) = service.get("environment") {
            if let Some(items) = values.as_object() {
                environment.extend(items.keys().map(|key| format!("{name}: {key}")));
            }
            if let Some(items) = values.as_array() {
                environment.extend(
                    items
                        .iter()
                        .filter_map(|entry| entry.as_str())
                        .map(|entry| {
                            format!("{name}: {}", entry.split('=').next().unwrap_or(entry))
                        }),
                );
            }
        }
    }
    topology.sort();
    topology.dedup();
    environment.sort();
    environment.dedup();
    (topology, environment)
}
