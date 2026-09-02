I've read through the entire codebase — all Rust backend modules (`ssh.rs`, `providers.rs`, `credentials.rs`, `storage.rs`, `terminal.rs`, `tunnels.rs`, `log_stream.rs`, `tier3.rs`, `lib.rs`, `models.rs`), the frontend (`main.ts`, `app/*`), config, CI, and docs. Overall this is a well-organized codebase with genuinely good instincts (parameterized SQL, consistent shell quoting via `quote_shell`, atomic vault writes with `0o600`, staging+rename for transfers, capability detection instead of Debian assumptions). The issues below are ordered by severity.

---

## 1. High severity

### 1.1 The Compose scan is aborted by the shared idle timeout whenever its output stalls
`tier3.rs` gives the Compose scan a **global 120s deadline** (`deadline=$(( $(date +%s) + 120 ))`) and per-project `timeout 15` guards, and allows a **16 MB** output limit (`COMPOSE_SCAN_OUTPUT_LIMIT`). But `compose_projects()` runs it via `exec_posix_script_bounded` → `exec_with_input_limited_timeout` with the default `COMMAND_TIMEOUT = 35s` **idle timeout** (`ssh.rs`). When `timeout(1)` exists on the remote host, each guarded step finishes within 15s and the section markers printed between commands keep resetting the idle timer, so the 120s deadline works as designed in the common case. The failure mode is any stretch of **output silence >35s**: a missing `timeout` binary (the `$guard` variable stays empty), a hung `docker compose config` that ignores SIGTERM, or an NFS-stalled `find`. In those environments the entire scan aborts with "Remote command timed out after 35 seconds" and the 120s deadline never gets a chance to fire. Either pass a longer explicit idle timeout for this call, or emit periodic keepalive bytes from the script.

The same 35s idle ceiling affects other legitimately long operations: `compose_action` "rebuild" (`up -d --build`), `apt-get upgrade`, `dnf check-update` in the security script — all invoked through plain `client.exec()` with no output-bound or extended timeout. A silent 40-second build will fail spuriously.

### 1.2 Saving *any* profile tears down *everything* globally
In `lib.rs`:
```rust
fn save_server(...) {
    let saved = state.store.save_server(&draft)?;
    tunnels::stop_all();          // ALL tunnels, every server
    log_stream::close_all(...);   // ALL live logs
    ssh::disconnect_all();        // ALL cached SSH connections
```
Editing a note, renaming a server, or toggling a favorite on server A stops tunnels and closes live log streams for servers B, C, D. Same in `delete_server`. This should be scoped: compare old vs. new profile, and only tear down connections whose `profile_key` actually changed (you already have `profile_key()` in `ssh.rs` for exactly this). `disconnect_all()` itself is even weaker than needed — it uses `try_lock()`, so any in-flight operation keeps its connection alive while the map entry is removed, producing reconnect churn anyway.

### 1.3 Unbounded remote output accumulation
`append_output()` caps only when a limit is passed, but many call sites use plain `client.exec()` / `exec_ok()` with no cap: `packages()` (`dpkg-query -W` over the entire package database, plus `apt-cache search`), `accounts()` (`getent passwd/group/shadow`), `cron_jobs`, `authorized_keys`, `SECURITY_SCRIPT` (holds all upgradable lines in a shell variable *and* prints them), `docker_pull`, `run_command` (bounded only after the fact via `bounded_output`). A compromised or misbehaving host (or just `/var/log`-sized output) can grow the Vec indefinitely and OOM the desktop app. Since you already have the bounded read loop, make the limit mandatory (or default-on) rather than opt-in.

### 1.4 Stringly-typed control channel over IPC is spoofable by server output
Control flow is encoded in error strings parsed by the frontend: `"MASTER_PASSWORD_REQUIRED:"`, `"HOST_KEY_MISMATCH:{json}"`. But `command_error()` returns **remote-controlled stderr/stdout verbatim**, which flows into those same strings. A malicious/compromised server can emit `HOST_KEY_MISMATCH:{...}` on stderr of any failing command and trigger the frontend's host-key replacement dialog (impact limited because `replace_host_key` verifies the fingerprint against the real presented key, but it's still an injection into a security UX flow). Use a structured error type serialized as JSON over Tauri IPC (`{ kind: "hostKeyMismatch", ... }`) instead of prefix-scraping prose.

### 1.5 Tunnel listeners have zero authentication, including SOCKS5
`tunnels.rs` binds whatever `bind_host` the profile specifies. Choose `0.0.0.0` and any machine on your LAN can use your desktop as an open pivot into the remote network (local/remote forwarding) or as an **unauthenticated open SOCKS5 proxy** (`socks_target` answers `0x00` = no-auth required, always). Note that the frontend already warns on non-loopback binds (`main.ts` shows a confirmation dialog before saving a bind host outside `127.0.0.1`/`::1`/`localhost`), so a warning-only mitigation exists — but the SOCKS proxy itself remains fully unauthenticated once started. Consider restricting to `127.0.0.1` unless explicitly overridden, and requiring the (already available) master-password-derived key for SOCKS auth.

### 1.6 Host-key trust model: silent TOFU into the user's shared `~/.ssh/known_hosts`
On `CheckResult::NotFound`, Serverbox **silently writes the new key** to the user's real `~/.ssh/known_hosts` — no fingerprint confirmation prompt (the README only promises review for *changed* keys). For a tool whose headline security feature is host-key verification, first-contact should show the fingerprint and ask. Additionally:
- You read the entire known_hosts file into libssh2 and rewrite the whole file on every add/replace — a concurrent `ssh-keygen`/OpenSSH modification in that window is lost.
- `replace_host_key()` calls `disconnect_all()` (all servers!) and, while walking the bastion chain looking for the mismatched hop, skips candidates whose host/port don't match but calls `verify_host_key()` on host/port-*matching* candidates whose presented fingerprint differs from the expected one. If such a candidate's old entry has meanwhile disappeared from known_hosts, `verify_host_key()`'s `NotFound` branch silently **adds a new entry** as a side effect of the replacement flow.

### 1.7 Sudo password handling: stdin-multiplexing and non-zeroized plaintext
In `execute_privileged_posix_script_bounded()` and `execute_privileged_with_input()`:
```rust
let mut input = format!("{password}\n").into_bytes();
input.extend_from_slice(script.as_bytes());
```
Password and payload share one stdin write. If the stored sudo password is stale, `sudo -S` consumes subsequent stdin (your script text) as additional password attempts before giving up — behavior then depends on how much was buffered; you partially compensate by sniffing "Sorry, try again." It works in the happy path but is fragile. Also, `CredentialDocument` holds passwords/key-passphrases/sudo passwords as plain `String`s that are cloned freely (`state.document.clone()` on every update) and never zeroized — only the derived key gets `Zeroizing`. For an app that advertises an encrypted vault, use `Zeroizing<String>`/`SecretBox` throughout the document.

---

## 2. Medium severity (correctness / reliability)

- **`mark_connected()` semantics broken** (`ssh.rs::with_client`): *every* successful operation — each dashboard refresh, page load, poll — updates `last_connected_at`. The sidebar "last connected" actually shows "last successful SSH command." Track real connect events only.
- **Over-aggressive connection invalidation**: any non-cancelled error result calls `invalidate_cached()` — including pure command timeouts and remote command errors — dropping perfectly healthy sessions and forcing full re-handshake (+ possible second 12s connect attempt from the `for attempt in 0..2` retry loop, which also blindly retries auth failures after 220 ms).
- **`cached_client` connect race**: check-then-insert under separately acquired locks; two concurrent first requests to the same server can both construct `SshClient`s, leaking one live session (never disconnected).
- **Cron job identity is line-index based**: `cron_line_id()` falls back to `user:line:{index}`. If the remote crontab changes between `crontab -l` and your `crontab -` write (another session, another tool), `replace_cron_line()`/`cron_action()` deletes or disables the *wrong line*. There is no read-back verification either.
- **Bastion relay hijack window**: `jump_stream()` binds an ephemeral localhost port and spawns a relay thread; any local process that connects to that port in the window before your own `TcpStream::connect` wins gets the authenticated tunnel to the target. Low probability, local-only, but a deterministic fix exists (use `socketpair`-style fd passing, or connect first from the same thread with a pre-negotiated token).
- **Magic libssh2 numbers**: `ErrorCode::Session(-37)` (EAGAIN) and `-9` appear as raw ints in `terminal.rs`/`tunnels.rs`/`log_stream.rs`. These are internal libssh2 errno values that have shifted between versions; define named constants or match on `io::ErrorKind::WouldBlock` consistently.
- **`log_stream` start does multiple extra round trips** (access probe, `id -u`, `sudo -n true`, sudo validation) sequentially before opening the follow channel — several seconds of added latency on high-RTT links; could be collapsed into one probe script like the overview collector does.
- **Uploads silently ignore `mkdir` failures** (`let _ = sftp.mkdir(...)`) in `upload_directory`/`upload_file`; a permission failure surfaces later as confusing per-file create errors, and empty dirs may simply not exist remotely.
- **Unit parsing fragility**: `parse_human_size` treats decimal SI units ("MB", "GB") as binary (1024ⁿ) — stats display will drift from `docker stats` reality. Cosmetic but systematic.

---

## 3. Architecture & maintainability

- **`providers.rs` is 3,451 lines** covering ten domains (dashboard, processes, services, SFTP, Docker, cron, APT, accounts, logs, networking). Your own architecture rule says "add a provider function and a typed command" — the file proves the rule doesn't scale. Split by domain (the way `tier3.rs` already is).
- **`main.ts` is ~3,000 lines of module-level mutable state + full `root.innerHTML` re-render** on every state change. It works today (delegated listeners, careful `escapeHtml`, explicit focus restoration hacks at lines 1415–1423), but every new view multiplies the risk of (a) an unescaped interpolation becoming XSS, and (b) focus/scroll glitches. Consider extracting per-view modules with their own state slices, as you did for `app/command-client.ts`.
- **No schema migration story**: `schema_version` table is created and never used again; the only migration is a hand-rolled `PRAGMA table_info(servers)` column check. The moment you ship v2, this becomes the riskiest file in the project.
- **No tests anywhere.** AGENTS.md says not to add them unprompted, so I'm flagging risk rather than telling you to violate your own rules — but note that the most bug-prone logic here is *pure and trivially testable*: `parse_capabilities_probe`, `parse_overview_sections`, `parse_docker_collection`, `parse_user_crontab`/`cron_line_id` (see §2 cron race), `parse_compose_scan`, `parse_ss/netstat_ports`, `posix_script_command`, `quote_shell`. These parsers encode assumptions about remote output formats that you cannot verify without tests or constant manual QA across distros.
- **`ssh2` crate (libssh2 bindings)** is lightly maintained and its error/nonblocking ergonomics are clearly fighting you (see the comment in `set_nonblocking`, the EAGAIN magic numbers, the relay polling loops). Not urgent, but `russh` or shelling out to the system `ssh` would remove a class of subtle transport bugs. At minimum pin and monitor it.
- **Version triple-bookkeeping**: `0.1.0` lives in `package.json`, `Cargo.toml`, and `tauri.conf.json`. One release drift and your updater/bundle metadata disagrees.
- **Docs drift**: PROJECT.md states "`src-tauri/gen/` … checked in for schema validation," but `.gitignore` contains `src-tauri/gen` and nothing under it is tracked. Also `.DS_Store` files exist in the working tree (repo root and `src-tauri/.DS_Store`) — gitignored, but worth cleaning.

---

## 4. Release pipeline

- **Deprecated runners still in use**: the workflow builds on `macos-14` and `ubuntu-22.04-arm` — the exact images your own README flags for deprecation — and the `create-release`/`publish-release` jobs also run on plain `ubuntu-22.04`, which GitHub is retiring on the same schedule. Fix them now rather than waiting for a failed release run.
- ~~Suspicious action versions~~: verified — `actions/checkout@v7` and `actions/setup-node@v7` are real, current tags (latest releases `v7.0.1` / `v7.0.0`). No action needed.
- **Signing posture**: ad-hoc macOS signing (documented) means Gatekeeper friction; Windows binaries are completely unsigned → SmartScreen "unknown publisher" for every user. Fine for early development, but decide before public release whether you'll do real code signing, since it changes the download/support experience materially.

---

## 5. Smaller but worth noting

- **Fake sparklines** (`format.ts`): `sparkline()` generates a deterministic sine wave from the current value. In a monitoring product, rendering a plausible-looking "history" chart for what is a single instantaneous sample is misleading — either drop it or label it decorative.
- **Vault has no idle lock**: once unlocked, credentials stay decryptable in memory for the app's lifetime. Consider an inactivity re-lock.
- **`navigator.platform`** is deprecated; you already fall back to userAgent, but `getUserAgentData`/Tauri's `os` plugin is cleaner.
- **CSP includes `style-src 'unsafe-inline'`** — acceptable given the inline-meter widths, but tighten if feasible.
- **SSH config import** ignores `Match`, `Include`, `ProxyJump`, and `IdentityFile` tilde expansion inside quotes; users with non-trivial configs will get silently incomplete imports.
- **No SSH-agent support** — notable gap for a key-first SSH tool; agent auth would also eliminate storing passphrases at all for many users.
- `cancel_operation()` calls `prune_pending_cancellations()` twice back-to-back (harmless, redundant).
- `APP_VERSION = 1` (models.rs) reads like the app version but is a snapshot-schema version — rename to avoid confusion.

---

## Summary

| Area | Verdict |
|---|---|
| Crypto/vault design | Sound (Argon2id + AES-GCM, atomic 0600 writes), but plaintext secrets aren't zeroized |
| Shell-injection safety | Strong — consistent `quote_shell`, allowlisted identifiers, parameterized SQL |
| Host-key security | Good mismatch handling; weak TOFU-on-new-host and shared-known_hosts mutation |
| Reliability | 35s idle timeout undermines long operations (Compose scan worst case); global teardown on profile save; unbounded outputs |
| Frontend | Functional and carefully escaped, but a 3k-line monolith with full re-render architecture |
| Tests | None, despite the highest-risk logic being pure parsing |
| CI/docs | Mostly excellent; deprecated runners, gen/ doc contradiction |

If I were prioritizing fixes: (1) scope the save/delete teardown per-server, (2) give the Compose scan and long actions their own timeouts, (3) make output bounds default-on, (4) replace string-prefix IPC errors with structured ones, and (5) put unit tests around the remote-output parsers before adding more distro-specific behavior.
