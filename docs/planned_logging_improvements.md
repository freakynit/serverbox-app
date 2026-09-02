Current logs implementation:

- **Backend** (`providers.rs::logs`, `log_stream.rs`): one typed contract covers journal, `logread`, container, Compose, and raw-file logs. One-shot output is capped at 1 MB; journal, container, Compose, and file follow use PTY-free SSH streams, while `logread` falls back to polling.
- **Frontend** (`main.ts`): one reusable viewer provides consistent source controls, time and line limits, client-side search/severity, live status, pause/resume, line counts, copy, and clear behavior in both the Logs and Container workspaces.

Suggested upgrades, roughly in value-per-effort order:

### 1. Real tail-follow instead of polling — implemented
The big one. Your follow today re-runs the whole command. Instead:
- **journalctl**: run `journalctl -f` over a dedicated PTY-free command channel. Stream lines to the UI like the terminal does. Stop on un-follow with channel close.
- **Raw files** (see #2): `tail -F file` over the same streaming channel.
- Stream Docker and Compose through their native follow commands; keep polling only as the fallback for `logread`, which cannot follow reliably.
- Show a live "N lines received" counter and pause/resume instead of just a toggle.

### 2. Raw log file source (your own backlog item) — implemented
Add a third source: file browser for `/var/log` (and container paths via `docker exec cat`/`tail`). Capability-gate by checking the dir exists. This unlocks app-specific logs (nginx, mysql, app) that journal may not have. Reuse the SFTP directory-listing provider logic.

### 3. Smarter parsing & structured filtering
- Parse journal lines into fields (timestamp, PID, unit, severity, message) when possible; render as a **table with highlight mode** in addition to raw.
- Replace the fixed severity regex with per-line classification from parsed fields (journalctl `-o short-iso` gives you PRIORITY).
- Add filters: unit, PID, host (for multi-node journals), and **multiple search terms** (AND/OR, case toggle).
- **Regex mode** and **inverted match** (hide noisy lines, e.g. access-log spam).
- A quick-action "match as filter" from the search box.

### 4. Time range upgrade
- Replace the fixed since-options with a proper preset list (15m, 1h, 6h, 24h, 7d, custom local date). You already resolve "today" remotely — do all presets remotely to respect server timezone.
- **Time-based follow window**: while following, keep a sliding window of the last N minutes so a long session doesn't unbounded-memory in the webview.
- Journal has `--since`/`--until`; docker has `--since` epoch; files need awk on timestamp — degrade gracefully per source.

### 5. Multi-log fan-out ("log groups")
Big power feature for a multi-server app:
- Select multiple sources (e.g., 3 services, or the same service across 3 servers) and view them in one pane with a **server/unit gutter column** and a dim/unrelated-lines toggle.
- Use a bounded, parallel executor with a 100-host limit.
- This turns it from a log viewer into a correlation tool — the single most "powerful" feature on this list.

### 6. Export & share
- **Download to local file** through Serverbox's app-native path prompt with the applied filters — copy is enough for 1000 lines, not for 5000.
- Save a "log recipe" (source, service, query, filters, time range) as local SQLite metadata like your saved commands, so an on-call workflow is one click.
- Optional: "copy as markdown" or "copy last N lines" variants.

### 7. Log-aware performance
- Render logs in **chunks** (e.g., append 500 lines per rAF) instead of escaping+inserting the whole blob on every follow tick; virtualize if you allow >5000 lines or add local buffering.
- Consider raising the 1 MB cap for follow mode only (streaming chunks never hit it) and keep it for one-shot loads.
- Pause follow automatically on tab/visibility blur; resume on return.

### 8. Smaller wins
- **Error-count summary bar**: "312 lines · 14 errors · 6 warnings" above the pane, click to jump to first error.
- Line wrapping toggle + monospace font-size control.
- `journalctl --output=short-full` (shows truncated args back) toggle.
- Per-service **log state hints** from the systemd view (failed units flash in the service list) — you already have journal in the service details modal; a "view full logs for this unit" jump button ties the two views together.
- "Copy as plain text" already exists; add "download as .log".
- Follow indicator: subtle animation + line count, and a "catching up / live" state distinction when switching from tail → follow.

### What I'd deliberately keep out
- No log shipping/agent-based indexing — that breaks the agentless model.
- No editing log files from here (risky, low value).
- No full log storage on the desktop — keep it read-only streaming; the recipe feature gives persistence without data retention.

If I had to pick a top-3 roadmap: **streaming follow (#1) → file source (#2) → multi-source fan-out (#5)**. Those three, plus recipe save (#6), would make it a genuinely powerful tool while staying inside your existing SSH boundary and capability-gating patterns.
