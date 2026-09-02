#!/usr/bin/env bash
#
# =============================================================================
# Alpine SSH Test Servers — spin up temporary Docker-based Alpine servers
# for testing serverbox's multi-server features.
#
# What it does:
#   - Creates 3 Alpine containers with OpenSSH server installed
#   - Password authentication (keys NOT set up)
#   - Non-standard SSH ports on the host (2221/2222/2223 → 22 in container)
#   - Optionally verifies connectivity with a real SSH password login
#
# -----------------------------------------------------------------------------
# USAGE
#   ./scripts/alpine-ssh-test-servers.sh up       # start all 3 servers (+ verify)
#   ./scripts/alpine-ssh-test-servers.sh down     # stop and remove all 3
#   ./scripts/alpine-ssh-test-servers.sh stop     # stop only (keeps containers)
#   ./scripts/alpine-ssh-test-servers.sh start    # start previously stopped ones
#   ./scripts/alpine-ssh-test-servers.sh status   # show container + port status
#   ./scripts/alpine-ssh-test-servers.sh test     # SSH into each server, run a cmd
#   ./scripts/alpine-ssh-test-servers.sh logs N   # show sshd logs for server N (1|2|3)
#   ./scripts/alpine-ssh-test-servers.sh help     # this help
#
# -----------------------------------------------------------------------------
# CONNECTION DETAILS (all servers identical)
#   Host:      localhost
#   Ports:     2221, 2222, 2223   (never port 22)
#   User:      root
#   Password:  serverbox123
#
#   Connect manually:
#     ssh -p 2221 root@localhost
#     ssh -p 2222 root@localhost
#     ssh -p 2223 root@localhost
#
#   Connect with a password flag (requires sshpass, `brew install sshpass`):
#     sshpass -p 'serverbox123' ssh -p 2221 root@localhost
#
#   For serverbox: add each server as host "localhost", user "root",
#   password "serverbox123", port 2221 / 2222 / 2223.
#
# -----------------------------------------------------------------------------
# STOPPING / REMOVING
#   Stop (keep for later `start`):
#     ./scripts/alpine-ssh-test-servers.sh stop
#     # or: docker stop sbx-alpine-1 sbx-alpine-2 sbx-alpine-3
#
#   Remove (stop + delete — they hold no persistent state):
#     ./scripts/alpine-ssh-test-servers.sh down
#     # or: docker rm -f sbx-alpine-1 sbx-alpine-2 sbx-alpine-3
#
#   Clean stale known_hosts entries after a recreate (if host keys change):
#     ssh-keygen -R "[localhost]:2221"
#     ssh-keygen -R "[localhost]:2222"
#     ssh-keygen -R "[localhost]:2223"
#
# -----------------------------------------------------------------------------
# NOTES / TROUBLESHOOTING
#   - Containers are disposable: state (files, installed pkgs) is lost on
#     `down`. Nothing is persisted to volumes.
#   - There is NO init system: if a container is stopped by the host,
#     `start` will bring it back up (it re-runs the full setup command).
#     If a container EXITS on its own, just run `up` again.
#   - `up` always recreates fresh (safe to re-run at any time).
#   - Password auth only: sshd is configured with
#       PasswordAuthentication yes
#       PermitRootLogin yes
#     Host keys are generated at boot (ssh-keygen -A), so keys rotate on
#     every `up` — clear known_hosts entries if SSH warns about a changed
#     host key.
#   - Requires: docker (running), and for the automatic `test` step:
#     sshpass (`brew install sshpass`).
#
# =============================================================================

set -euo pipefail

PASSWORD="serverbox123"
IMAGES=("alpine:latest" "alpine:latest" "alpine:latest")
PORTS=(2221 2222 2223)

name() { echo "sbx-alpine-$1"; }

# The container entrypoint: install sshd, set root password, enable password
# auth + root login, generate host keys, run sshd in the foreground.
setup_cmd() {
  cat <<EOF
apk add --no-cache openssh-server &&
echo 'root:${PASSWORD}' | chpasswd &&
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config &&
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config &&
ssh-keygen -A &&
/usr/sbin/sshd -D -e
EOF
}

up_one() {
  local i="$1"
  docker rm -f "$(name "$i")" >/dev/null 2>&1 || true
  docker run -d --name "$(name "$i")" -p "${PORTS[$((i-1))]}:22" \
    "${IMAGES[$((i-1))]}" /bin/sh -c "$(setup_cmd)" >/dev/null
  echo "  [ok] $(name "$i")  →  localhost:${PORTS[$((i-1))]}"
}

cmd_up() {
  command -v docker >/dev/null || { echo "ERROR: docker not found" >&2; exit 1; }
  docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not running" >&2; exit 1; }

  echo "Creating 3 Alpine SSH servers..."
  for i in 1 2 3; do up_one "$i"; done

  echo "Waiting for sshd to come up..."
  sleep 8

  if command -v sshpass >/dev/null; then
    cmd_test
  else
    echo
    echo "Containers are up. (sshpass not installed — skipping auto-verify."
    echo " Install with 'brew install sshpass' or connect manually, see header.)"
  fi
}

cmd_down() {
  docker rm -f sbx-alpine-1 sbx-alpine-2 sbx-alpine-3 2>/dev/null \
    && echo "Removed sbx-alpine-1/2/3" \
    || echo "Nothing to remove."
}

cmd_stop() { docker stop sbx-alpine-1 sbx-alpine-2 sbx-alpine-3 2>/dev/null || echo "Nothing to stop."; }
cmd_start() { docker start sbx-alpine-1 sbx-alpine-2 sbx-alpine-3 2>/dev/null || echo "Nothing to start."; }

cmd_status() {
  docker ps -a --filter "name=sbx-alpine" \
    --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
}

cmd_test() {
  local port user
  for i in 1 2 3; do
    port="${PORTS[$((i-1))]}"
    echo "=== ssh localhost:${port} ==="
    if command -v sshpass >/dev/null; then
      sshpass -p "${PASSWORD}" ssh \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -p "$port" root@localhost \
        'echo "connected: user=$(whoami) host=$(hostname)"' 2>&1 | grep -v '^Warning:' || true
    else
      # Fallback: prompt for password interactively
      ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -p "$port" root@localhost \
        'echo "connected: user=$(whoami) host=$(hostname)"' 2>&1 | grep -v '^Warning:' || true
    fi
    echo
  done
}

cmd_logs() {
  local n="${1:-}"
  [[ "$n" =~ ^[123]$ ]] || { echo "Usage: $0 logs [1|2|3]" >&2; exit 1; }
  docker logs --tail 50 "$(name "$n")"
}

cmd="${1:-help}"
case "$cmd" in
  up)     cmd_up ;;
  down)   cmd_down ;;
  stop)   cmd_stop ;;
  start)  cmd_start ;;
  status) cmd_status ;;
  test)   cmd_test ;;
  logs)   shift; cmd_logs "${1:-}" ;;
  help|-h|--help) sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) echo "Unknown command: $cmd (see '$0 help')" >&2; exit 1 ;;
esac
