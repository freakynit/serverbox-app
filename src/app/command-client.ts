import { invoke } from "@tauri-apps/api/core";
import type { ActiveOperation, HostKeyMismatch, HostKeyUnknown } from "./types";

export class OperationCancelledError extends Error {
  constructor() {
    super("Operation cancelled");
    this.name = "OperationCancelledError";
  }
}

export const remoteOperationLabels: Record<string, string> = {
  connect_server: "Connecting securely to your server…",
  get_dashboard: "Updating the overview…",
  get_processes: "Reading the process list…",
  signal_process: "Applying the process action…",
  get_services: "Reading system services…",
  get_service_details: "Inspecting the service…",
  service_action: "Applying the service action…",
  get_docker: "Checking the container runtime…",
  docker_action: "Applying the Docker action…",
  container_exec: "Preparing the container shell…",
  docker_logs: "Fetching container logs…",
  docker_inspect: "Inspecting the Docker resource…",
  docker_pull: "Pulling the image on the server…",
  docker_create: "Creating the container…",
  get_logs: "Fetching the latest logs…",
  get_log_files: "Discovering log files…",
  get_ports: "Reading network connections…",
  list_remote_files: "Browsing the remote folder…",
  read_remote_file: "Opening the remote file…",
  write_remote_file: "Saving the remote file…",
  remote_file_action: "Updating the remote files…",
  upload_path: "Uploading to the server…",
  download_path: "Downloading from the server…",
  start_terminal: "Opening an interactive shell…",
  get_cron_jobs: "Reading cron schedules…",
  save_cron_job: "Saving the cron job…",
  cron_action: "Updating the cron job…",
  get_packages: "Reading APT packages…",
  get_package_details: "Reading package details…",
  package_action: "Running the package operation…",
  get_accounts: "Reading users and groups…",
  create_user: "Creating the Linux user…",
  account_action: "Updating the account…",
  reset_user_password: "Resetting the password…",
  get_compose_projects: "Loading Compose projects…",
  compose_action: "Running the Compose operation…",
  get_firewall: "Reading firewall rules…",
  firewall_action: "Updating the firewall…",
  get_authorized_keys: "Reading authorized SSH keys…",
  authorized_key_action: "Updating authorized SSH keys…",
  get_security_snapshot: "Checking updates and security status…",
  run_quick_action: "Running the server action…",
  run_saved_command: "Running the saved command…",
  start_tunnel: "Starting the SSH tunnel…",
};

/** Structured error payloads produced by the backend's `AppError`. */
interface StructuredError {
  kind?: string;
  message?: string;
  host?: unknown;
  port?: unknown;
  keyType?: unknown;
  oldFingerprints?: unknown;
  newFingerprint?: unknown;
  fingerprint?: unknown;
}

function asStructured(error: unknown): StructuredError | null {
  return error !== null && typeof error === "object" ? (error as StructuredError) : null;
}

export function errorText(error: unknown): string {
  const structured = asStructured(error);
  if (structured && typeof structured.message === "string") return structured.message;
  if (structured && typeof structured.kind === "string") {
    return `Serverbox received an invalid ${structured.kind} error response.`;
  }
  return String(error instanceof Error ? error.message : error ?? "Something went wrong");
}

function operationServerId(args?: Record<string, unknown>): string | undefined {
  if (typeof args?.serverId === "string") return args.serverId;
  const request = args?.request;
  return request && typeof request === "object" && typeof (request as { serverId?: unknown }).serverId === "string"
    ? (request as { serverId: string }).serverId
    : undefined;
}

function isCredentialError(error: unknown): boolean {
  const kind = asStructured(error)?.kind;
  return kind === "masterPasswordRequired" || kind === "masterPasswordSetupRequired";
}

function hostKeyMismatch(error: unknown): HostKeyMismatch | null {
  const structured = asStructured(error);
  if (structured?.kind !== "hostKeyMismatch") return null;
  if (typeof structured.host !== "string" || typeof structured.port !== "number" || typeof structured.keyType !== "string" || typeof structured.newFingerprint !== "string") return null;
  return {
    host: structured.host,
    port: structured.port,
    keyType: structured.keyType,
    newFingerprint: structured.newFingerprint,
    oldFingerprints: Array.isArray(structured.oldFingerprints)
      ? structured.oldFingerprints.filter((item): item is string => typeof item === "string")
      : [],
  };
}

function hostKeyUnknown(error: unknown): HostKeyUnknown | null {
  const structured = asStructured(error);
  if (structured?.kind !== "hostKeyUnknown") return null;
  if (typeof structured.host !== "string" || typeof structured.port !== "number" || typeof structured.keyType !== "string" || typeof structured.fingerprint !== "string") return null;
  return {
    host: structured.host,
    port: structured.port,
    keyType: structured.keyType,
    fingerprint: structured.fingerprint,
  };
}

type Recovery =
  | { type: "credentials" }
  | { type: "mismatch"; mismatch: HostKeyMismatch }
  | { type: "unknown"; unknown: HostKeyUnknown }
  | null;

function recoveryFor(error: unknown, retryWithMasterPassword: boolean, retryWithHostKey: boolean): Recovery {
  if (retryWithMasterPassword && isCredentialError(error)) return { type: "credentials" };
  if (retryWithHostKey) {
    const mismatch = hostKeyMismatch(error);
    if (mismatch) return { type: "mismatch", mismatch };
    const unknown = hostKeyUnknown(error);
    if (unknown) return { type: "unknown", unknown };
  }
  return null;
}

export interface CommandClientOptions {
  getActiveOperation: () => ActiveOperation | null;
  setActiveOperation: (operation: ActiveOperation | null) => void;
  onRemoteOperationSuccess: (serverId: string) => void;
  render: () => void;
  unlockForCredentialError: (error: unknown) => Promise<void>;
  requestHostKeyDecision: (mismatch: HostKeyMismatch) => Promise<boolean>;
  requestHostKeyTrust: (unknown: HostKeyUnknown) => Promise<boolean>;
}

export function createCommandClient(options: CommandClientOptions) {
  const cancelCurrentOperation = (expectedOperationId?: string): void => {
    const operation = options.getActiveOperation();
    if (!operation || (expectedOperationId && operation.id !== expectedOperationId)) return;
    operation.cancelled = true;
    options.setActiveOperation(null);
    void invoke("cancel_operation", { operationId: operation.id }).catch(() => undefined);
    options.render();
  };

  const recoverAndRetry = async <T>(
    command: string,
    args: Record<string, unknown> | undefined,
    error: unknown,
    retryWithMasterPassword: boolean,
    retryWithHostKey: boolean,
    beforeRetry: () => void,
  ): Promise<T> => {
    const recovery = recoveryFor(error, retryWithMasterPassword, retryWithHostKey);
    if (!recovery) throw error;
    beforeRetry();
    if (recovery.type === "credentials") {
      await options.unlockForCredentialError(error);
      return invokeCommand<T>(command, args, false, retryWithHostKey);
    }
    const serverId = operationServerId(args);
    if (!serverId) throw error;
    if (recovery.type === "mismatch") {
      if (await options.requestHostKeyDecision(recovery.mismatch)) {
        await invoke("replace_host_key", { serverId, expectedHost: recovery.mismatch.host, expectedPort: recovery.mismatch.port, expectedFingerprint: recovery.mismatch.newFingerprint });
        return invokeCommand<T>(command, args, retryWithMasterPassword, false);
      }
    } else {
      if (await options.requestHostKeyTrust(recovery.unknown)) {
        await invoke("accept_host_key", { serverId, expectedHost: recovery.unknown.host, expectedPort: recovery.unknown.port, expectedFingerprint: recovery.unknown.fingerprint });
        return invokeCommand<T>(command, args, retryWithMasterPassword, false);
      }
    }
    throw new OperationCancelledError();
  };

  const invokeCommand = async <T>(command: string, args?: Record<string, unknown>, retryWithMasterPassword = true, retryWithHostKey = true): Promise<T> => {
    const label = remoteOperationLabels[command];
    if (!label) {
      try {
        return await invoke<T>(command, args);
      } catch (error) {
        return recoverAndRetry<T>(command, args, error, retryWithMasterPassword, retryWithHostKey, () => undefined);
      }
    }

    cancelCurrentOperation();
    const operation: ActiveOperation = { id: crypto.randomUUID(), label, serverId: operationServerId(args), cancelled: false };
    options.setActiveOperation(operation);
    options.render();
    try {
      const result = await invoke<T>(command, { ...(args ?? {}), operationId: operation.id });
      if (operation.cancelled || options.getActiveOperation()?.id !== operation.id) throw new OperationCancelledError();
      if (operation.serverId) options.onRemoteOperationSuccess(operation.serverId);
      return result;
    } catch (error) {
      if (operation.cancelled || options.getActiveOperation()?.id !== operation.id) throw new OperationCancelledError();
      return recoverAndRetry<T>(command, args, error, retryWithMasterPassword, retryWithHostKey, () => {
        if (options.getActiveOperation()?.id === operation.id) {
          options.setActiveOperation(null);
          options.render();
        }
      });
    } finally {
      if (options.getActiveOperation()?.id === operation.id) {
        options.setActiveOperation(null);
        options.render();
      }
    }
  };

  return { cancelCurrentOperation, invokeCommand };
}
