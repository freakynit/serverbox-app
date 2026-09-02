# Serverbox Stacks — Compose Studio

## 1. Vision

Serverbox is a desktop control panel for Linux servers over SSH. Today it can
*discover* and *manage* existing Docker/Podman resources and Docker Compose
projects, but creating a multi-service deployment still means hand-writing a
Compose file, tracking down the right image, and wiring networks, volumes,
environment, and security settings by hand.

**Stacks** closes that loop. It turns Serverbox from a *viewer/manager* of what
already runs into a tool that can also *author* a deployment from scratch: a
guided, deterministic wizard that asks the user what they want to run (the
docker image name/path comes from them), how the pieces connect, and what
their security boundaries are — then generates a Docker Compose file, validates
it, and deploys it on the selected host.

There is deliberately **no natural-language "describe and it builds it" mode.**
The wizard is fully structured and deterministic: every input maps to a concrete
Compose field, the generated file is always visible before deploy, and nothing
runs on a host until the user has reviewed and confirmed it. This keeps the
feature offline-capable, side-effect-free to preview, and free of
hallucination/secret-leakage risk.

The output of the wizard is a **Docker Compose file** — the same artifact
Serverbox already manages — so a freshly authored stack immediately benefits
from the existing Compose lifecycle UI (logs, exec, rebuild, pull, scale,
topology) with no new post-deploy tooling.

---

## 2. Scope and boundaries

### In scope (v1)

- A single-host wizard that authoring a multi-service Compose stack.
- Image selection from a user-supplied image reference (`nginx:1.27`) or a
  local build path (`build:` with a `Dockerfile`/context on the host).
- Service wiring: networks, published ports, DNS aliases, dependencies.
- Storage: named volumes, bind mounts, read-only mounts, tmpfs.
- Environment: key/value pairs, `.env` files, and secret-flagged values.
- Security boundaries: non-root user/uid-gid, read-only rootfs, capability
  dropping, `no-new-privileges`, resource limits, and network isolation.
- Compose generation, dry-run validation, guarded deploy (`up`), and teardown (`down`).
- Round-tripping: re-open any deployed stack in the wizard by parsing the hosted file.

### Out of scope (v1)

- **Cross-host orchestration.** Compose is single-host by design. If "how they
  connect" ever means services on *different* servers, that is a separate
  product (Swarm/Nomad/K8s) and out of scope here. Stacks v1 targets one server
  per stack.
- **Docker Swarm secrets.** `docker compose` (non-Swarm) has no native
  `secrets:` block. Secrets are handled through an encrypted `.env` sidecar
  instead (see §7).
- **Natural-language generation.** Explicitly deferred; the wizard is structured.
- **Stack templates / reuse library** (deferred to a later tier).
- **Historical diff/rollback of configs** (deferred; ties into backlog #34).

---

## 3. Feasibility

Architecturally this is a strong fit. The engine is roughly 80% present; the
net-new work is the authoring pipeline and UI.

### Already built and reusable

| Requirement | Existing code | Notes |
|---|---|---|
| SSH + privilege escalation | `src-tauri/src/ssh.rs` (sudo/root fallback) | Connect, reconnect, cancellation, typed results |
| Capability detection | `providers.rs`, `ServerCapabilities` | Knows `docker`, `podman`, `sudo`, `root`, distro, arch |
| Compose discovery + topology | `tier3.rs` `compose_projects`, `parse_compose_scan` | Bounded scan, services/topology/running/env-names |
| Compose lifecycle actions | `tier3.rs` `compose_action` | `up/down/restart/pull/rebuild/exec/scale` |
| Docker/Podman resources | `providers.rs` | Containers, images, volumes, networks (read-only today) |
| Guarded mutation + validation gate | `tier3.rs` firewall manager | The template for "confirm before you mutate" |
| Secret masking | house rule across Compose UI | Env *names* shown, values never rendered |

### Net-new work

1. A typed **StackSpec** intent model (Rust + mirrored TypeScript) — §5.
2. **StackSpec → Compose YAML** generator, and a **Compose → StackSpec** parser
   for round-tripping — §6.
3. **Wizard UI** as a new "Stacks" workspace — §9.
4. The **secrets sidecar** (`stack.env`, encrypted at rest) — §7.
5. **Dry-run validation** wiring (`docker compose config`) before deploy — §8.

The scariest decisions are scope, not technology: single-host vs cross-host and
the secrets model (both pinned down in §2).

---

## 4. Is Docker Compose the right representation?

**Yes — as the deployment artifact and on-host source of truth.** Compose is
declarative, human-diffable, versionable, already parsed by `tier3.rs`, and
already managed by the existing Compose UI. A stack authored in the wizard
drops straight into that pipeline.

It is **not sufficient as the *only* representation**, for two reasons:

1. **Secrets.** Non-Swarm Compose cannot express file-based secrets. We use an
   encrypted `.env` sidecar alongside the compose file.
2. **Authoring ergonomics.** The wizard should edit a clean domain model, not
   YAML text. The compose file is *generated from* the model and *parsed back
   into* it, so the UI and the file never drift.

The resulting three-layer model:

```
StackSpec (typed intent model — what the wizard edits)
     │  generate  ⇄  parse   (round-trip, no drift)
     ▼
docker-compose.yml  (on-host source of truth — deployed, diffed, managed)
     +  stack.env    (encrypted secrets sidecar — values never rendered)
```

Compose's one genuine ceiling — cross-host orchestration — is accepted as out
of scope (§2). For single-host stacks it is the right foundation.

---

## 5. The intent model: `StackSpec`

The wizard edits a typed model, *not* Compose text. This struct lives in Rust
(`src-tauri/src/models.rs`) and is mirrored in `src/types.ts`. It is the single
intermediate representation between the UI and the generated file.

> Field names below use Rust `snake_case`; the TS mirror uses `camelCase`
> (matching the existing `#[serde(rename_all = "camelCase")]` convention).

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackSpec {
    pub name: String,                  // project name (compose project / dir name)
    pub server_id: String,             // target host
    pub deploy_path: String,           // remote dir e.g. /opt/stacks/myapp
    pub services: Vec<StackService>,
    pub networks: Vec<StackNetwork>,
    pub volumes: Vec<StackVolume>,
    pub secrets: Vec<StackSecret>,     // resolved to stack.env at deploy time
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackService {
    pub name: String,
    pub image: StackImage,             // image reference OR local build
    pub command: Option<String>,
    pub replicas: Option<u32>,         // deploy.replicas (docker compose v2)
    pub restart: RestartPolicy,        // no | always | unless-stopped | on-failure[:n]
    pub ports: Vec<PortMapping>,       // "8080:80", "127.0.0.1:5432:5432"
    pub networks: Vec<String>,         // network names this service joins
    pub aliases: Vec<String>,          // network aliases
    pub depends_on: Vec<String>,       // "service_started" condition by default
    pub environment: Vec<EnvEntry>,
    pub env_file: Vec<String>,         // paths to .env files on host
    pub volumes: Vec<MountRef>,
    pub healthcheck: Option<HealthCheck>,
    pub security: ServiceSecurity,
    pub resource_limits: ResourceLimits,
}

pub enum StackImage {
    Reference(String),                 // "nginx:1.27", "ghcr.io/org/app:latest"
    Build { context: String, dockerfile: Option<String> },
}

pub struct EnvEntry {
    pub key: String,
    pub value: Option<String>,         // None => user must supply at deploy (secret prompt)
    pub secret: bool,                  // true => write to stack.env, reference ${KEY}
}

pub struct MountRef {
    pub target: String,                // container path
    pub source: Option<String>,        // volume name or host path (bind)
    pub read_only: bool,
    pub tmpfs: bool,
}

pub struct ServiceSecurity {
    pub user: Option<String>,          // "1000:1000" or "appuser"
    pub read_only_rootfs: bool,
    pub cap_drop: Vec<String>,         // e.g. ["ALL"]
    pub cap_add: Vec<String>,
    pub no_new_privileges: bool,
    pub network_isolation: NetworkIsolation, // how this service reaches others
}
```

`NetworkIsolation` is the heart of the "security boundaries" step and is
expressed as reachability *intent* the generator translates into concrete
Compose primitives (separate internal networks, no default network, etc.).

---

## 6. Generation and round-trip

### Generate (`StackSpec` → Compose)

Deterministic, table-driven. Each `StackService` maps to a `services.<name>`
block; networks/volumes/ports/env/security map to their Compose keys. The
generator is pure Rust (no shell), so it can be unit-tested and produces
stable, diffable output (map keys ordered, 2-space indent).

Notable translations:

- **Security boundaries** become `user`, `read_only: true`, `cap_drop`,
  `security_opt: [no-new-privileges:true]`, and explicit `networks:` membership
  with *no* `default` network for isolated services.
- **Secrets** are *not* inlined — the generator emits `${KEY}` environment
  references and collects the values into `stack.env` (§7).
- **`depends_on`** defaults to `condition: service_started` (simple health-aware
  start ordering without the `service_healthy` foot-gun).
- **Resource limits** become `deploy.resources.limits` / `reservations`.

### Parse (Compose → `StackSpec`)

Reuses the existing `parse_compose_scan` output and `docker compose config
--format json` as the canonical resolved view. Parsing back into `StackSpec`
enables round-trip editing: the wizard opens any existing compose file and the
user continues editing values, never raw YAML. Unrecognized keys are preserved
as an opaque "advanced" block so nothing is silently dropped.

---

## 7. Secrets

Non-Swarm Compose has no `secrets:` primitive, so secrets live in an encrypted
sidecar `stack.env` next to the compose file:

- Secret-flagged `EnvEntry` values are written to `stack.env` as `KEY=value`.
- The compose file references them as `${KEY}`; values are **never** written
  into `docker-compose.yml`.
- `stack.env` is wrapped with **age** (or a GPG passphrase key if age is
  unavailable) with the encryption key not stored in plaintext. In v1, a
  simplest safe option is encrypted at rest with the same vault primitives used
  by `credentials.rs`, plus `.gitignore`-style protection against accidental
  commit on the host.
- The UI masks secret values everywhere, matching the existing "Compose env
  names shown, values not rendered" rule.
- `None`-valued secret entries are *prompted at deploy time* and never persist
  locally beyond the deployment operation.

This keeps the compose file the single source of structural truth while
secrets remain out of it.

---

## 8. Validation and deploy

No host mutation without a passing validation gate — the same pattern as the
firewall manager.

1. **Preview.** The wizard shows the generated compose file live (see §9).
2. **Dry-run.** `docker compose -f <path> config` runs before any deploy; a
   non-zero exit or parse error blocks deploy and surfaces the exact error.
3. **Confirm.** An explicit confirmation dialog summarizes what will be
   created and warns about the SSH port (the "keep the SSH port out of the
   blast radius" messaging).
4. **Deploy.** `compose_action`-style `up -d` (reuse `compose_command` from
   `tier3.rs` for runner detection: `docker compose`, `docker-compose`, or
   `podman-compose`).
5. **Handoff.** On success, the stack appears in the existing Compose workspace
   where logs/exec/rebuild/pull/scale already work.

`down`/teardown is likewise guarded, with a visible warning that it removes
containers but leaves named volumes by default (or `down -v` behind a second
confirm when destructive).

---

## 9. UI flow

A new **"Stacks"** workspace, consistent with the existing Container/Compose
workspace and the house visual style.

```
Stacks workspace (per server tab)
├── Stack list           — authored + discovered stacks, running state, "New Stack"
│
├── New Stack wizard (non-linear, live preview always visible)
│    Step 1  Services      — add service: image ref (name:tag) or build path,
│                            command, replicas, restart policy, healthcheck
│    Step 2  Networking    — internal networks, which services share a net,
│                            published ports, DNS aliases
│    Step 3  Storage       — named/bind volumes, mount path, read-only, tmpfs
│    Step 4  Environment   — key/values, .env file, flag value as secret
│    Step 5  Security      — non-root user/uid, read-only rootfs, cap-drop,
│                            no-new-privileges, network isolation, resource limits
│    Step 6  Deploy        — project name, remote path, target server
│
│    [ Panel: live compose preview — generated YAML, secrets already masked ]
│
├── Review & validate     — full compose render, `compose config` dry-run,
│                           pass/fail + errors, diff vs last-known-good
└── Deploy                — guarded `up` → hand off to existing Compose lifecycle UI
```

### Principles

- **Live compose preview.** The generated YAML is visible at all times while
  editing, so there are no surprises and users learn Compose as they go.
- **Round-trip editing.** After deploy, re-open the wizard by parsing the
  hosted file; users may edit the file directly or in the UI without drift.
- **Security as a first-class, named step.** "Who can reach whom" is explicit,
  not buried in an advanced accordion. This is the differentiator vs raw Compose.
- **No mutation without validation + confirmation** (§8).
- **Secrets masked everywhere** (§7).

---

## 10. Implementation plan (phased)

Because the project is in active development with no back-compat burden, ship
incrementally and reuse existing providers rather than building parallel
abstractions.

### Phase 1 — Model + generator (pure Rust, no UI)

- Add `StackSpec` and companion structs to `models.rs` + `types.ts`.
- Implement `generate_compose(&StackSpec) -> String` and
  `parse_compose(&str) -> StackSpec`.
- Unit-test generation round-trip (`generate` → `parse` → `generate` is stable).

### Phase 2 — Validation + deploy wiring

- Add typed commands: `stack_preview`, `stack_validate` (`compose config`),
  `stack_deploy` (`up`), `stack_down`.
- Reuse `compose_command`/`quote_shell` from `tier3.rs` for runner detection.
- Enforce the validation gate before any deploy.

### Phase 3 — Secrets sidecar

- Implement `stack.env` write/read/mask; wire secret values through the deploy
  command over SSH stdin (never the command line), matching the existing
  Linux-password-reset pattern.

### Phase 4 — Stacks workspace UI

- New workspace: stack list, six-step wizard, live preview panel, review/deploy.
- Round-trip open of existing compose files.

### Phase 5 — Hardening & polish

- Diff against last-known-good; `down -v` danger gating; secret rotation;
  stack templates/reuse (deferred features).

---

## 11. Open questions to resolve before building

1. **Secret encryption primitive.** Age, GPG, or reuse `credentials.rs` vault
   primitives for the on-host `stack.env`? (Recommend: align with existing
   vault approach first; revisit for multi-user host sharing.)
2. **Build support depth.** How far to support `build:` (context + Dockerfile)
   vs. insisting on published image references in v1?
3. **Override files.** Does the wizard emit a single `docker-compose.yml`, or
   `compose.yml` + `compose.override.yml` (env/ports in override) from day one?
   The existing scan deliberately excludes `*override*` files today.
4. **Cross-server "connected" stacks.** Confirmed out of scope, but worth a
   written decision so it's not re-derived later.
5. **Idempotency/redeploy semantics.** Is deploy always `up -d --force-recreate`,
   or a plain `up -d` that prefers minimal churn? Affects diff UX.
