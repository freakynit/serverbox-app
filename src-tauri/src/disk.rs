use crate::models::{
    DiskExplorerSnapshot, DiskMount, DockerDiskUsage, LargestDirectory, LargestFile,
};
use crate::ssh::{with_client, COMMAND_TIMEOUT};
use crate::storage::Store;
use std::collections::HashMap;
use std::time::Duration;

const DISK_SECTION_MARKER: &str = "__SERVERBOX_DISK_V1__";
/// Disk scans are verbose by nature, but the bounded script keeps the real
/// output far below this; the cap only stops a misbehaving host from growing
/// buffers without end.
const MAX_DISK_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
/// The script's own global deadline is 120 seconds, so this must be longer to
/// let the deadline (not the SSH idle timer) end a stalled scan gracefully.
const DISK_SCAN_IDLE_TIMEOUT: Duration = Duration::from_secs(150);

// One self-contained POSIX shell script gathers mounts, inode pressure,
// largest files, largest directories, and Docker disk usage in a single SSH
// round trip. Sections are framed by unique markers parsed in Rust.
//
// Design constraints:
// - Depth-limited `find` and filesystem-bound `du` keep huge servers bounded;
//   per-command `timeout` plus a global deadline stop one slow subtree from
//   wedging the scan.
// - GNU `find -printf` is used when available; BusyBox falls back to batched
//   `ls -dn` (no modified times).
// - `du` depth flags differ across implementations, so directory depth is
//   limited after the fact in awk — du must walk everything anyway.
const DISK_SCAN_SCRIPT: &str = r#"marker() { printf '\n__SERVERBOX_DISK_V1__%s\n' "$1"; }
guard=''
command -v timeout >/dev/null 2>&1 && guard='timeout 25'
deadline=$(( $(date +%s 2>/dev/null || echo 0) + 120 ))

marker mounts
df -Pk 2>/dev/null || df -kP 2>/dev/null || true

marker inodes
# Inodes are only meaningful on local filesystems; skip virtual/special mounts.
for dev in $(df -Pk 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|overlay|squashfs|proc|sysfs|devpts|mqueue|debugfs|configfs|binfmt_misc|nsfs|cgroup|pstore|bpf|tracefs|securityfs|hugetlbfs|ramfs|autofs|efivarfs|fusectl)/ {print $1}'); do
  df -i -P "$dev" 2>/dev/null | awk -v dev="$dev" 'NR==2 && $1 == dev {m=$6; for(i=7;i<=NF;i++) m=m" " $i; printf "inode\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $5, m}'
done

marker largest_files
if find / -maxdepth 0 -printf '' >/dev/null 2>&1; then
  for root in /var /opt /srv /home /usr/local /root; do
    now=$(date +%s 2>/dev/null || echo 0)
    [ "$deadline" -gt 0 ] && [ "$now" -ge "$deadline" ] && break
    [ -d "$root" ] || continue
    $guard find "$root" -xdev -maxdepth 4 -type f -printf '%s\t%T@\t%p\n' 2>/dev/null || true
  done | sort -rn | head -n 80
else
  # No GNU find: batched ls is slower but portable. Modified times are omitted.
  for root in /var /opt /srv /home /usr/local /root; do
    now=$(date +%s 2>/dev/null || echo 0)
    [ "$deadline" -gt 0 ] && [ "$now" -ge "$deadline" ] && break
    [ -d "$root" ] || continue
    $guard find "$root" -xdev -maxdepth 4 -type f -exec ls -dn {} + 2>/dev/null | awk '{name=""; for(i=9;i<=NF;i++) name=name (name?" ":"")$i; if(name!="") printf "%s\t0\t%s\n", $5, name}' || true
  done | sort -rn | head -n 80
fi

marker largest_dirs
for root in /var /opt /srv /home /usr/local /tmp; do
  now=$(date +%s 2>/dev/null || echo 0)
  [ "$deadline" -gt 0 ] && [ "$now" -ge "$deadline" ] && break
  [ -d "$root" ] || continue
  # Depth is limited here (not via du flags) because every implementation of
  # du walks the whole tree regardless; printing fewer lines keeps it bounded.
  $guard du -xk "$root" 2>/dev/null | awk -v base="$root" '
    {
      i = index($0, "\t")
      if (!i) next
      size = substr($0, 1, i - 1) + 0
      path = substr($0, i + 1)
      if (substr(path, 1, length(base)) != base) next
      rest = substr(path, length(base) + 1)
      n = 0
      for (j = 1; j <= length(rest); j++) if (substr(rest, j, 1) == "/") n++
      if (n <= 3 && size >= 10240) print size "\t" path
    }' || true
done | sort -rn | head -n 80

marker docker_usage
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  $guard docker system df --format '{{.Type}}\t{{.TotalCount}}\t{{.Active}}\t{{.Size}}\t{{.Reclaimable}}' 2>/dev/null || true
fi
exit 0"#;

// Depth below /var/log is limited after the fact for the same reason as the
// main scan: every du implementation walks the whole tree anyway.
const VARLOG_SCRIPT: &str = r#"guard=''
command -v timeout >/dev/null 2>&1 && guard='timeout 20'
$guard du -xk /var/log 2>/dev/null | awk '
  {
    i = index($0, "\t")
    if (!i) next
    size = substr($0, 1, i - 1) + 0
    path = substr($0, i + 1)
    n = -1
    for (j = 2; j <= length(path); j++) if (substr(path, j, 1) == "/") n++
    if (path == "/var/log" || (n >= 0 && n <= 2)) print size "\t" path
  }' | sort -rn | head -n 40
exit 0"#;

pub fn disk_snapshot(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<DiskExplorerSnapshot, String> {
    with_client(store, server_id, operation_id, |client, _| {
        client.check_cancelled()?;
        let output = client.exec_posix_script_bounded_with_timeout(
            DISK_SCAN_SCRIPT,
            &[],
            MAX_DISK_OUTPUT_BYTES,
            DISK_SCAN_IDLE_TIMEOUT,
        )?;
        Ok(parse_disk_scan(&output))
    })
}

pub fn varlog_usage(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
) -> Result<Vec<LargestDirectory>, String> {
    with_client(store, server_id, operation_id, |client, _| {
        client.check_cancelled()?;
        let output = client.exec_posix_script_bounded_with_timeout(
            VARLOG_SCRIPT,
            &[],
            128 * 1024,
            COMMAND_TIMEOUT,
        )?;
        Ok(parse_size_lines(&output)
            .into_iter()
            .map(|(path, size)| LargestDirectory {
                depth: path_depth(&path),
                path,
                size_bytes: size,
            })
            .collect())
    })
}

fn parse_disk_scan(text: &str) -> DiskExplorerSnapshot {
    let sections = parse_marker_sections(text);
    let mut snapshot = DiskExplorerSnapshot {
        mounts: parse_mounts(section(&sections, "mounts"), section(&sections, "inodes")),
        largest_files: parse_largest_files(section(&sections, "largest_files")),
        largest_dirs: parse_size_lines(section(&sections, "largest_dirs"))
            .into_iter()
            .map(|(path, size_bytes)| LargestDirectory {
                depth: path_depth(&path),
                path,
                size_bytes,
            })
            .collect(),
        docker_usage: parse_docker_usage(section(&sections, "docker_usage")),
    };
    snapshot.largest_dirs.truncate(60);
    snapshot.largest_files.truncate(60);
    snapshot.mounts.truncate(24);
    snapshot
}

fn parse_marker_sections(output: &str) -> HashMap<String, String> {
    let mut sections = HashMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        if let Some(name) = line.strip_prefix(DISK_SECTION_MARKER) {
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

fn parse_mounts(df_text: &str, inode_text: &str) -> Vec<DiskMount> {
    let mut mounts: Vec<DiskMount> = df_text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let total = fields[1].parse::<u64>().ok()? * 1024;
            if total == 0 {
                return None;
            }
            Some(DiskMount {
                filesystem: fields[0].to_string(),
                mount: fields[5..].join(" "),
                total_bytes: total,
                used_bytes: fields[2].parse::<u64>().ok()? * 1024,
                available_bytes: fields[3].parse::<u64>().ok()? * 1024,
                percent: fields[4].trim_end_matches('%').parse().unwrap_or(0.0),
                ..DiskMount::default()
            })
        })
        .collect();
    // Merge per-device inode figures onto matching (filesystem, mount) rows.
    for line in inode_text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 6 || fields[0] != "inode" {
            continue;
        }
        let filesystem = fields[1];
        let inode_total = fields[2].parse::<u64>().ok();
        let inode_used = fields[3].parse::<u64>().ok();
        let inode_percent = fields[4].trim_end_matches('%').parse::<f64>().ok();
        let mount = fields[5..].join(" ");
        if let Some(entry) = mounts
            .iter_mut()
            .find(|entry| entry.filesystem == filesystem && entry.mount == mount)
        {
            entry.inode_total = inode_total;
            entry.inode_used = inode_used;
            entry.inode_percent = inode_percent;
        }
    }
    // Most useful first: fullest local filesystems lead the overview.
    mounts.sort_by(|left, right| right.percent.total_cmp(&left.percent));
    mounts
}

fn parse_largest_files(text: &str) -> Vec<LargestFile> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, '\t');
            let size_bytes = fields.next()?.parse::<u64>().ok()?;
            let modified_raw = fields.next()?.trim();
            // GNU find %T@ carries fractional seconds; a plain integer parse
            // fails on that, so take the part before the decimal point.
            let modified_at = modified_raw
                .split('.')
                .next()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0);
            let path = fields.next()?.trim().to_string();
            if path.is_empty() {
                return None;
            }
            Some(LargestFile {
                path,
                size_bytes,
                modified_at,
            })
        })
        .collect()
}

fn parse_size_lines(text: &str) -> Vec<(String, u64)> {
    let mut entries: Vec<(String, u64)> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(2, '\t');
            let size_bytes = fields.next()?.parse::<u64>().ok()?;
            let path = fields.next()?.trim().to_string();
            if path.is_empty() {
                return None;
            }
            Some((path, size_bytes * 1024))
        })
        .collect();
    entries.dedup_by(|a, b| a.0 == b.0);
    entries
}

fn path_depth(path: &str) -> u32 {
    path.split('/').filter(|part| !part.is_empty()).count() as u32
}

fn parse_docker_usage(text: &str) -> Option<DockerDiskUsage> {
    let mut usage = DockerDiskUsage::default();
    let mut found = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 5 {
            continue;
        }
        let size = parse_docker_size(fields[3]);
        let reclaimable = parse_docker_size(fields[4]);
        match fields[0] {
            "Images" => usage.images_bytes = size,
            "Containers" => usage.containers_bytes = size,
            "Local Volumes" => usage.volumes_bytes = size,
            "Build Cache" => usage.build_cache_bytes = size,
            _ => usage.other_bytes += size,
        }
        usage.reclaimable_bytes += reclaimable;
        found = true;
    }
    if !found {
        return None;
    }
    usage.total_bytes = usage.images_bytes
        + usage.containers_bytes
        + usage.volumes_bytes
        + usage.build_cache_bytes
        + usage.other_bytes;
    usage.reclaimable_bytes = usage.reclaimable_bytes.min(usage.total_bytes);
    Some(usage)
}

/// Parses Docker's human size strings ("897B", "12.34kB", "1.5GB", and
/// reclaimable values that carry a percentage suffix like "208.4MB (45%)").
/// Docker's units.HumanSize uses decimal (1000-based) multipliers; a space
/// before the unit is tolerated just in case.
fn parse_docker_size(value: &str) -> u64 {
    let value = value.trim();
    let split = value
        .char_indices()
        .find(|(_, character)| !character.is_ascii_digit() && *character != '.')
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let number: f64 = number.parse().unwrap_or(0.0);
    // Only the alphabetic unit prefix matters; anything after it (for example
    // "MB (8%)") is decoration.
    let multiplier = match unit
        .trim_start()
        .chars()
        .take_while(|character| character.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_lowercase()
        .as_str()
    {
        "" => 1.0,
        "b" => 1.0,
        "k" | "kb" => 1e3,
        "m" | "mb" => 1e6,
        "g" | "gb" => 1e9,
        "t" | "tb" => 1e12,
        "p" | "pb" => 1e15,
        "e" | "eb" => 1e18,
        // Fallback for unexpected binary-style suffixes.
        "ki" | "kib" => 1024.0,
        "mi" | "mib" => 1024.0 * 1024.0,
        "gi" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "ti" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (number * multiplier).round() as u64
}
