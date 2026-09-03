import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SerializeAddon } from "@xterm/addon-serialize";
import "@xterm/xterm/css/xterm.css";
import { icon } from "./icons";
import { createCommandClient, errorText, OperationCancelledError } from "./app/command-client";
import { closeCustomSelects, enhanceSelects, syncCustomSelect } from "./app/select-controls";
import { createWorkspaceTabDragController } from "./app/workspace-tab-drag";
import { renderEmptyWorkspaceView, renderErrorView, renderInlineErrorView, renderLoadingView, renderTitlebarView, renderUnsupportedView, renderWelcomeView } from "./app/static-views";
import { escapeHtml, formatBytes, formatDate, formatDuration, meter, normalizeLogOutput, sparkline } from "./app/format";
import type { ActiveOperation, AdministrationTab, ContainerPlatformTab, DashboardCardName, DashboardState, DiskTab, DockerSection, HostKeyMismatch, HostKeyUnknown, LogSource, LogTarget, LogViewerState, MasterPasswordPromptMode, ModalKind, ServerToolTab, View, WorkspaceTab } from "./app/types";
import type {
  AppStateSnapshot,
  AccountSnapshot,
  ContainerInfo,
  ContainerExec,
  CronJob,
  CredentialStatus,
  DashboardCard,
  DiskExplorerSnapshot,
  DockerPage,
  DockerSnapshot,
  LargestDirectory,
  Page,
  PackageInfo,
  PackagePage,
  ProcessInfo,
  RemoteFile,
  ServerCapabilities,
  ServerConnection,
  ServerProfile,
  ServerSaveResult,
  ServiceDetails,
  ServiceInfo,
  SshConfigEntry,
  TerminalEvent,
  LogStreamStarted,
  TerminalStarted,
  TerminalTab,
  TransferProgress,
  ComposeProject,
  FirewallSnapshot,
  AuthorizedKey,
  SecuritySnapshot,
  SavedCommand,
  TunnelConfig,
  TunnelStatus,
  CommandResult,
} from "./types";
import "./styles.css";

const root = document.querySelector<HTMLDivElement>("#app")!;
const appWindow = getCurrentWindow();
const appWebview = getCurrentWebview();
const platform = /mac/i.test(navigator.platform || navigator.userAgent) ? "macos" : /win/i.test(navigator.platform || navigator.userAgent) ? "windows" : "linux";

const INTERFACE_SCALE_LEVELS = [0.8, 1, 1.2, 1.4, 1.6, 1.8, 2] as const;
const DEFAULT_INTERFACE_SCALE = 1;
const storedInterfaceScale = Number(localStorage.getItem("serverbox-interface-scale"));
let interfaceScale = INTERFACE_SCALE_LEVELS.includes(storedInterfaceScale as typeof INTERFACE_SCALE_LEVELS[number])
  ? storedInterfaceScale
  : DEFAULT_INTERFACE_SCALE;

let snapshot: AppStateSnapshot = { version: 1, servers: [], sshKeys: [], sshConfigEntries: [] };
let activeServerId: string | null = null;
let activeWorkspaceTabId: string | null = null;
let openServerTabs: WorkspaceTab[] = [];
const serverTabViews = new Map<string, View>();
const connectedServerIds = new Set<string>();
let sidebarCopyPlacement: { sourceId: string; copyId: string } | null = null;
let activeView: View = "dashboard";
let serverQuery = "";
let darkMode = localStorage.getItem("serverbox-theme") === "dark";
let loading = true;
let errorMessage = "";
let modal: ModalKind = null;
let editingServer: ServerProfile | null = null;
let renamingWorkspaceTabId: string | null = null;
let credentialStatus: CredentialStatus = { configured: false, unlocked: false };
let masterPasswordPrompt: { mode: MasterPasswordPromptMode; error: string } | null = null;
let masterPasswordWaiter: Promise<string | null> | null = null;
let finishMasterPasswordWaiter: ((value: string | null) => void) | null = null;
let textInputPrompt: { title: string; label: string; defaultValue: string; placeholder?: string; allowEmpty?: boolean; multiline?: boolean; choices?: string[] } | null = null;
let finishTextInputWaiter: ((value: string | null) => void) | null = null;
let appDialogPrompt: { title: string; message: string; kind: "info" | "warning"; confirmLabel: string; cancelLabel?: string } | null = null;
let finishAppDialogWaiter: ((value: boolean) => void) | null = null;
let appToast: { message: string; kind: "success" | "info" } | null = null;
let appToastTimer: number | undefined;
let hostKeyPrompt: { mismatch?: HostKeyMismatch; unknown?: HostKeyUnknown; error: string } | null = null;
let hostKeyWaiter: Promise<boolean> | null = null;
let finishHostKeyWaiter: ((trust: boolean) => void) | null = null;
let credentialSettingsError = "";
let credentialSettingsNotice = "";
let connection: ServerConnection | null = null;
let dashboard: DashboardState | null = null;
const dashboardSnapshots = new Map<string, DashboardState>();
let processes: ProcessInfo[] = [];
let services: ServiceInfo[] = [];
let serviceDetails: ServiceDetails | null = null;
let diskSnapshot: DiskExplorerSnapshot | null = null;
let diskTab: DiskTab = "mounts";
let diskVarLog: LargestDirectory[] | null = null;
let diskVarLogLoading = false;
let docker: DockerSnapshot | null = null;
let containerPlatformTab: ContainerPlatformTab = "runtime";
let dockerTab: DockerSection = "containers";
let dockerLoaded: Record<DockerSection, boolean> = { containers: false, images: false, volumes: false, networks: false };
let dockerHasMore: Record<DockerSection, boolean> = { containers: false, images: false, volumes: false, networks: false };
let composeScaleProject: ComposeProject | null = null;
let containerLogViewer: LogViewerState | null = null;
let shouldScrollToContainerLogs = false;
let inspectText = "";
let logsViewer: LogViewerState = createLogViewer({ source: "system", label: "System logs" }, 100);
let discoveredLogFiles: string[] = [];
let ports: import("./types").PortInfo[] = [];
let cronJobs: CronJob[] = [];
let editingCron: CronJob | null = null;
let packagePage: PackagePage | null = null;
let packageQuery = "";
let packageUpgradesOnly = false;
let packageDetailsText = "";
let accounts: AccountSnapshot | null = null;
let accountTab: "users" | "groups" = "users";
let administrationTab: AdministrationTab = "firewall";
let composeProjects: ComposeProject[] = [];
let composeProjectsServerId: string | null = null;
let firewallSnapshot: FirewallSnapshot | null = null;
let authorizedKeys: AuthorizedKey[] = [];
let securitySnapshot: SecuritySnapshot | null = null;
let savedCommands: SavedCommand[] = [];
let editingCommand: SavedCommand | null = null;
let tunnels: TunnelConfig[] = [];
let tunnelStatuses: TunnelStatus[] = [];
let editingTunnel: TunnelConfig | null = null;
let commandResults: CommandResult[] = [];
let shouldScrollToCommandResults = false;
let passwordUser = "";
let processesHasMore = false;
let servicesHasMore = false;
let filesHaveMore = false;
let portsHaveMore = false;
let remotePath = "/";
let remoteFiles: RemoteFile[] = [];
let showHidden = false;
let remoteFileSearch = "";
let editorPath = "";
let editorContent = "";
let editorDirty = false;
let transfer: TransferProgress | null = null;
let transferDismissTimer: number | undefined;
let refreshTimer: number | undefined;
let terminalTabs: TerminalTab[] = [];
let activeTerminalTabId: string | null = null;
const activeTerminalTabByWorkspace = new Map<string, string>();
let terminal: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let serializeAddon: SerializeAddon | null = null;
let terminalMountTabId: string | null = null;
let terminalUnlisteners: UnlistenFn[] = [];
const terminalInputChains = new Map<string, Promise<void>>();
let navigationVersion = 0;
let viewTransition: { serverId: string; view: View; version: number } | null = null;
let renderedLocation = "";
const viewScrollPositions = new Map<string, number>();
const sidebarScrollPositions = { servers: 0, navigation: 0 };

const PROCESS_PAGE_SIZE = 100;
const SERVICE_PAGE_SIZE = 100;
const FILE_PAGE_SIZE = 100;
const PORT_PAGE_SIZE = 150;
const DOCKER_PAGE_SIZE = 60;
const DASHBOARD_OVERVIEW_TIMEOUT_MS = 20_000;
const LOG_LINE_OPTIONS = [100, 250, 300, 500, 1000] as const;

let activeOperation: ActiveOperation | null = null;

function renderLogLineOptions(selected: number): string {
  return LOG_LINE_OPTIONS.map((value) => `<option value="${value}" ${selected === value ? "selected" : ""}>${value}</option>`).join("");
}

function renderLogSinceOptions(selected: string): string {
  return `<option value="" ${!selected ? "selected" : ""}>Any time</option><option value="1 hour ago" ${selected === "1 hour ago" ? "selected" : ""}>Last hour</option><option value="today" ${selected === "today" ? "selected" : ""}>Today</option>`;
}

const activeServer = (): ServerProfile | undefined => snapshot.servers.find((server) => server.id === activeServerId);
const activeWorkspaceTab = (): WorkspaceTab | undefined => openServerTabs.find((tab) => tab.id === activeWorkspaceTabId);
const activeCapabilities = (): ServerCapabilities | null => dashboard?.profile?.capabilities ?? null;
const hasInteractiveSession = (serverId = activeServerId): boolean => Boolean(serverId) && terminalTabs.some((tab) => tab.serverId === serverId && Boolean(tab.sessionId) && !tab.closed);
const activeTerminalTabs = (): TerminalTab[] => terminalTabs.filter((tab) => tab.workspaceTabId === activeWorkspaceTabId);
const activeServerIsConnected = (): boolean => Boolean(activeServerId && (connectedServerIds.has(activeServerId) || hasInteractiveSession(activeServerId)));

function errorKind(error: unknown): string | null {
  const structured = error !== null && typeof error === "object" ? (error as { kind?: unknown }) : null;
  return structured && typeof structured.kind === "string" ? structured.kind : null;
}

function requestHostKeyDecision(mismatch: HostKeyMismatch): Promise<boolean> {
  if (hostKeyWaiter) return hostKeyWaiter;
  hostKeyPrompt = { mismatch, error: "" };
  modal = "host-key";
  errorMessage = "";
  hostKeyWaiter = new Promise<boolean>((resolve) => { finishHostKeyWaiter = resolve; });
  render();
  return hostKeyWaiter;
}

function requestHostKeyTrust(unknown: HostKeyUnknown): Promise<boolean> {
  if (hostKeyWaiter) return hostKeyWaiter;
  hostKeyPrompt = { unknown, error: "" };
  modal = "host-key";
  errorMessage = "";
  hostKeyWaiter = new Promise<boolean>((resolve) => { finishHostKeyWaiter = resolve; });
  render();
  return hostKeyWaiter;
}

function finishHostKeyPrompt(trust: boolean): void {
  const finish = finishHostKeyWaiter;
  finishHostKeyWaiter = null;
  hostKeyWaiter = null;
  hostKeyPrompt = null;
  modal = null;
  render();
  finish?.(trust);
}

function credentialPromptMode(error: unknown): MasterPasswordPromptMode {
  return errorKind(error) === "masterPasswordSetupRequired" ? "setup" : "unlock";
}

function requestMasterPassword(mode: MasterPasswordPromptMode, error = ""): Promise<string | null> {
  if (masterPasswordWaiter) return masterPasswordWaiter;
  masterPasswordPrompt = { mode, error };
  modal = "master-password";
  errorMessage = "";
  masterPasswordWaiter = new Promise<string | null>((resolve) => { finishMasterPasswordWaiter = resolve; });
  render();
  window.setTimeout(() => root.querySelector<HTMLInputElement>('form[data-form="master-password"] input')?.focus(), 0);
  return masterPasswordWaiter;
}

function finishMasterPasswordPrompt(value: string | null): void {
  const finish = finishMasterPasswordWaiter;
  finishMasterPasswordWaiter = null;
  masterPasswordWaiter = null;
  masterPasswordPrompt = null;
  modal = null;
  render();
  finish?.(value);
}

async function unlockForCredentialError(error: unknown): Promise<void> {
  const mode = credentialPromptMode(error);
  let promptError = "";
  while (true) {
    const password = await requestMasterPassword(mode, promptError);
    if (password === null) throw new OperationCancelledError();
    try {
      credentialStatus = await invoke<CredentialStatus>("unlock_credentials", { masterPassword: password });
      return;
    } catch (unlockError) {
      if (errorKind(unlockError) === "masterPasswordInvalid") {
        promptError = "That master password did not unlock the local credential vault. Try again.";
        continue;
      }
      throw unlockError;
    }
  }
}

const { cancelCurrentOperation, invokeCommand } = createCommandClient({
  getActiveOperation: () => activeOperation,
  setActiveOperation: (operation) => { activeOperation = operation; },
  onRemoteOperationSuccess: (serverId) => { connectedServerIds.add(serverId); },
  render,
  unlockForCredentialError,
  requestHostKeyDecision,
  requestHostKeyTrust,
});

function setError(error: unknown): void {
  if (error instanceof OperationCancelledError || errorText(error).toLowerCase().includes("operation cancelled")) return;
  errorMessage = errorText(error);
  render();
}

function clearRefreshTimer(): void {
  if (refreshTimer !== undefined) window.clearInterval(refreshTimer);
  refreshTimer = undefined;
}

function resetPaginationState(): void {
  processesHasMore = false;
  servicesHasMore = false;
  filesHaveMore = false;
  portsHaveMore = false;
  dockerLoaded = { containers: false, images: false, volumes: false, networks: false };
  dockerHasMore = { containers: false, images: false, volumes: false, networks: false };
}

function clearContainerLogs(): void {
  if (containerLogViewer?.streamId) void invoke("close_log_stream", { sessionId: containerLogViewer.streamId }).catch(() => undefined);
  containerLogViewer = null;
  shouldScrollToContainerLogs = false;
}

function createLogViewer(target: LogTarget, lines: number): LogViewerState {
  return { target, text: "", lines, since: "", query: "", severity: "all", following: false, status: "idle" };
}

function viewRequestIsCurrent(serverId: string, view: View, version: number): boolean {
  return activeServerId === serverId && activeView === view && navigationVersion === version;
}

function viewTransitionIsCurrent(): boolean {
  return Boolean(viewTransition && viewRequestIsCurrent(viewTransition.serverId, viewTransition.view, viewTransition.version));
}

function shortId(value: string): string { return value.slice(0, 12); }

function scrollPanelIntoView(selector: string): boolean {
  const content = root.querySelector<HTMLElement>(".content-area");
  const panel = root.querySelector<HTMLElement>(selector);
  if (!content || !panel) return false;
  const contentRect = content.getBoundingClientRect();
  const panelRect = panel.getBoundingClientRect();
  const targetTop = content.scrollTop + panelRect.top - contentRect.top - 18;
  content.scrollTo({
    top: Math.max(0, targetTop),
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
  });
  return true;
}

function scrollContainerLogsIntoView(): boolean { return scrollPanelIntoView(".container-log-panel"); }

function scrollCommandResultsIntoView(): boolean { return scrollPanelIntoView("[data-command-results]"); }

function setCommandResults(results: CommandResult[], focus = true): void {
  commandResults = results;
  shouldScrollToCommandResults = focus && results.length > 0;
}

function clearCommandResults(): void {
  commandResults = [];
  shouldScrollToCommandResults = false;
}

function render(): void {
  captureMountedTerminal();
  const previousContent = root.querySelector<HTMLElement>(".content-area");
  const previousServerList = root.querySelector<HTMLElement>(".server-list");
  const previousNavigation = root.querySelector<HTMLElement>(".nav-section");
  if (previousContent && renderedLocation) viewScrollPositions.set(renderedLocation, previousContent.scrollTop);
  if (previousServerList) sidebarScrollPositions.servers = previousServerList.scrollTop;
  if (previousNavigation) sidebarScrollPositions.navigation = previousNavigation.scrollTop;
  const nextLocation = activeWorkspaceTabId ? `${activeWorkspaceTabId}:${activeView}` : "welcome";
  root.dataset.theme = darkMode ? "dark" : "light";
  root.innerHTML = `${renderTitlebar()}${loading ? renderLoading() : renderShell()}`;
  const nextContent = root.querySelector<HTMLElement>(".content-area");
  const nextServerList = root.querySelector<HTMLElement>(".server-list");
  const nextNavigation = root.querySelector<HTMLElement>(".nav-section");
  if (nextContent) nextContent.scrollTop = viewScrollPositions.get(nextLocation) ?? 0;
  if (nextServerList) nextServerList.scrollTop = sidebarScrollPositions.servers;
  if (nextNavigation) nextNavigation.scrollTop = sidebarScrollPositions.navigation;
  if (shouldScrollToContainerLogs && nextContent) {
    window.setTimeout(() => {
      if (scrollContainerLogsIntoView()) shouldScrollToContainerLogs = false;
    }, 0);
  }
  if (shouldScrollToCommandResults && nextContent) {
    window.setTimeout(() => {
      if (scrollCommandResultsIntoView()) shouldScrollToCommandResults = false;
    }, 0);
  }
  enhanceSelects(root);
  renderedLocation = nextLocation;
  if (activeView === "terminal" && !modal) window.setTimeout(() => mountTerminal(), 0);
}

function renderTitlebar(): string {
  return renderTitlebarView({ platform, server: activeServer() });
}

function renderLoading(): string {
  return renderLoadingView();
}

function renderShell(): string {
  return `<div class="app-shell">
    ${renderServerRail()}
    ${renderSidebar()}
    <main class="main-area">
      ${renderTabBar()}
      <section class="content-area">${activeServerId ? renderConnectedContent() : snapshot.servers.length ? renderEmptyWorkspace() : renderWelcome()}</section>
    </main>
  </div>${renderOperationBanner()}${modal ? renderModal() : ""}${appDialogPrompt ? renderAppDialog() : ""}${transfer && !transfer.done ? renderTransferToast() : ""}${appToast ? renderAppToast() : ""}`;
}

function renderOperationBanner(): string {
  if (!activeOperation) return "";
  const server = activeOperation.serverId ? snapshot.servers.find((item) => item.id === activeOperation?.serverId) : activeServer();
  return `<div class="operation-banner" role="status" aria-live="polite"><span class="operation-spinner"></span><div class="operation-copy"><strong>${escapeHtml(activeOperation.label)}</strong><span>${escapeHtml(server?.host ? `SSH can take a moment on ${server.host}. Your workspace is still available.` : "Your workspace is still available while this finishes.")}</span></div><button class="operation-cancel" data-action="cancel-operation">Cancel</button></div>`;
}

function filteredServers(): ServerProfile[] {
  const query = serverQuery.trim().toLowerCase();
  const servers = snapshot.servers.filter((server) => `${server.name} ${server.host} ${server.groupName ?? ""} ${server.tags.join(" ")} ${server.notes}`.toLowerCase().includes(query)).sort((left, right) => {
    if (left.favorite !== right.favorite) return left.favorite ? -1 : 1;
    const recent = (right.lastConnectedAt ?? "").localeCompare(left.lastConnectedAt ?? "");
    return recent || left.name.localeCompare(right.name);
  });
  if (sidebarCopyPlacement) {
    const sourceIndex = servers.findIndex((server) => server.id === sidebarCopyPlacement?.sourceId);
    const copyIndex = servers.findIndex((server) => server.id === sidebarCopyPlacement?.copyId);
    if (sourceIndex >= 0 && copyIndex >= 0 && groupKey(servers[sourceIndex].groupName) === groupKey(servers[copyIndex].groupName)) {
      const [copy] = servers.splice(copyIndex, 1);
      servers.splice(copyIndex < sourceIndex ? sourceIndex : sourceIndex + 1, 0, copy);
    }
  }
  return servers;
}

function normalizedGroupName(groupName?: string): string {
  return groupName?.normalize("NFKC").replace(/[\u200B-\u200D\uFEFF]/gu, "").trim().replace(/\s+/gu, " ") ?? "";
}

function groupKey(groupName?: string): string {
  return (normalizedGroupName(groupName) || "Ungrouped").toLocaleLowerCase();
}

function renderServerGroups(servers: ServerProfile[]): string {
  const grouped = new Map<string, { label: string; servers: ServerProfile[] }>();
  for (const server of servers) {
    const label = normalizedGroupName(server.groupName) || "Ungrouped";
    const key = groupKey(label);
    const group = grouped.get(key) ?? { label, servers: [] };
    group.servers.push(server);
    grouped.set(key, group);
  }
  return [...grouped.values()].map(({ label, servers: items }) => `<div class="server-group"><div class="server-group-label"><span class="group-label-full">${escapeHtml(label)}</span><span class="group-label-short" aria-hidden="true">${escapeHtml(shortGroupLabel(label))}</span></div>${items.map(renderServerItem).join("")}</div>`).join("");
}

function shortGroupLabel(group: string): string {
  return group.length <= 4 ? group : `${group.slice(0, 4)}...`;
}

function renderServerRail(): string {
  const servers = filteredServers();
  const query = serverQuery.trim().toLowerCase();
  return `<aside class="server-rail" aria-label="Servers">
    <div class="server-rail-flyout">
      <div class="rail-brand"><span class="brand-mark">${icon("logo")}</span><span class="rail-brand-name">Serverbox</span></div>
      <div class="sidebar-section server-section">
        <div class="section-label-row"><span class="section-label">Servers</span></div>
        <label class="sidebar-search"><span>${icon("search")}</span><input data-field="server-search" value="${escapeHtml(serverQuery)}" placeholder="Search servers…" aria-label="Search servers and notes"/><kbd>⌘ K</kbd></label>
        <div class="server-list">
          ${servers.length ? renderServerGroups(servers) : `<div class="server-empty">${query ? "No matching servers" : "No servers saved yet"}</div>`}
        </div>
      </div>
      <div class="server-rail-foot">
        <button class="icon-button" data-action="add-server" aria-label="Add server" title="Add server">${icon("plus")}</button>
        <span class="rail-foot-label">New server</span>
      </div>
    </div>
  </aside>`;
}

function renderSidebar(): string {
  const nav = [
    ["dashboard", "Overview", "dashboard"],
    ["terminal", "Terminal", "terminal"],
    ["processes", "Processes", "processes"],
    ["services", "Systemd services", "services"],
    ["files", "Files", "files"],
    ["disk", "Disk usage", "disk"],
    ["docker", "Container platform", "docker"],
    ["logs", "Logs", "logs"],
    ["network", "Network sockets", "network"],
    ["cron", "Cron jobs", "cron"],
    ["packages", "Packages", "packages"],
    ["accounts", "Users & groups", "users"],
    ["commands", "Saved commands", "terminalSmall"],
    ["tunnels", "SSH tunnels", "network"],
    ["administration", "Administration", "settings"],
  ] as const;
  const unsupported = (view: View): boolean => {
    const cap = activeCapabilities();
    if (!cap) return false;
    if (view === "docker") return !cap.docker && !cap.podman;
    if (view === "services") return !cap.systemd;
    if (view === "cron") return !cap.cron;
    if (view === "packages") return cap.packageManager !== "apt-get";
    if (view === "network") return !cap.networkTool;
    return false;
  };
  return `<aside class="sidebar">
    <div class="sidebar-section nav-section"><div class="section-label">Workspace</div>${nav.map(([view, label, iconName]) => `<button class="nav-item ${activeView === view ? "active" : ""}" data-view="${view}" ${!activeServerIsConnected() || unsupported(view) ? "disabled" : ""}>${icon(iconName)}<span>${label}</span>${unsupported(view) ? `<small>off</small>` : ""}</button>`).join("")}</div>
    <div class="sidebar-bottom">
      <button class="utility-link" data-action="credential-settings">${icon("settings")} Settings</button>
      <button class="icon-button sidebar-theme-toggle" data-action="theme" aria-label="${darkMode ? "Switch to light appearance" : "Switch to dark appearance"}" title="${darkMode ? "Switch to light appearance" : "Switch to dark appearance"}">${icon(darkMode ? "sun" : "moon")}</button>
    </div>
  </aside>`;
}

function renderServerItem(server: ServerProfile): string {
  const initials = server.name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
  const connected = connectedServerIds.has(server.id) || hasInteractiveSession(server.id);
  const tooltip = `${server.name}\n${server.host}`;
  return `<div class="server-item ${server.id === activeServerId ? "active" : ""}" data-server-id="${escapeHtml(server.id)}" role="button" tabindex="0" aria-label="Open ${escapeHtml(server.name)} at ${escapeHtml(server.host)}" title="${escapeHtml(tooltip)}">
    <span class="server-avatar">${escapeHtml(initials)}</span><span class="server-item-copy"><strong>${server.favorite ? `${icon("star")} ` : ""}${escapeHtml(server.name)}</strong><small>${escapeHtml(server.username)}@${escapeHtml(server.host)}</small></span><span class="server-item-actions"><button class="server-action" data-server-action="new-tab" data-server-id="${escapeHtml(server.id)}" aria-label="Open another ${escapeHtml(server.name)} workspace" title="Open another workspace">${icon("plus")}</button><button class="server-action" data-server-action="duplicate" data-server-id="${escapeHtml(server.id)}" aria-label="Duplicate ${escapeHtml(server.name)}" title="Duplicate server">${icon("copy")}</button><button class="server-action" data-server-action="edit" data-server-id="${escapeHtml(server.id)}" aria-label="Edit ${escapeHtml(server.name)}" title="Edit connection">${icon("edit")}</button><button class="server-action server-action-delete" data-server-action="delete" data-server-id="${escapeHtml(server.id)}" aria-label="Delete ${escapeHtml(server.name)}" title="Delete server">${icon("trash")}</button></span><span class="connection-dot ${connected ? "online" : ""}"></span>
  </div>`;
}

function renderTabBar(): string {
  const tabs = openServerTabs.map((tab) => ({ tab, server: snapshot.servers.find((server) => server.id === tab.serverId) })).filter((item): item is { tab: WorkspaceTab; server: ServerProfile } => Boolean(item.server));
  const tabContent = tabs.length ? tabs.map(({ tab, server }) => {
    const selected = tab.id === activeWorkspaceTabId;
    const connected = connectedServerIds.has(server.id) || hasInteractiveSession(server.id);
    const label = tab.label || server.name;
    return `<button class="workspace-tab ${selected ? "active" : ""}" data-workspace-tab="${escapeHtml(tab.id)}" role="tab" aria-selected="${selected}"><span class="workspace-tab-status ${connected ? "online" : ""}"></span><span class="workspace-tab-copy">${escapeHtml(label)}</span><span class="workspace-tab-action" data-workspace-tab-action data-workspace-rename="${escapeHtml(tab.id)}" title="Rename tab" aria-label="Rename ${escapeHtml(label)} tab">${icon("edit")}</span><span class="workspace-tab-action workspace-tab-close" data-workspace-tab-action data-workspace-close="${escapeHtml(tab.id)}" title="Close tab" aria-label="Close ${escapeHtml(label)} tab">${icon("close")}</span></button>`;
  }).join("") : `<div class="workspace-tab-placeholder">No server selected</div>`;
  return `<div class="workspace-tabbar"><div class="workspace-tabs" role="tablist" aria-label="Open server workspaces">${tabContent}</div>${activeServerId && activeServerIsConnected() ? `<button class="button button-quiet workspace-disconnect" data-action="disconnect">Disconnect</button>` : ""}</div>`;
}

function renderWelcome(): string {
  return renderWelcomeView();
}

function renderEmptyWorkspace(): string {
  return renderEmptyWorkspaceView();
}

function renderConnectedContent(): string {
  const server = activeServer();
  if (!server) return renderWelcome();
  const titles: Record<View, [string, string]> = {
    dashboard: ["Overview", "A clear read on how this machine is doing."],
    terminal: ["Terminal", "A real interactive shell, one keystroke away."],
    processes: ["Processes", "See what is using the machine right now."],
    services: ["Systemd services", "Keep systemd units healthy and moving."],
    files: ["Files", "Browse, edit, and move files over SFTP."],
    disk: ["Disk usage", "Find what is consuming space before it becomes an outage."],
    docker: ["Container platform", "Runtime resources and Compose applications in one place."],
    logs: ["System logs", "The recent story behind what is happening."],
    network: ["Network sockets", "Listening ports and active connections."],
    cron: ["Cron jobs", "Scheduled commands for this server."],
    packages: ["Packages", "Installed software and pending APT upgrades."],
    accounts: ["Users & groups", "Linux identities, access, and membership."],
    administration: ["Administration", "Firewall, SSH access, security posture, and maintenance."],
    commands: ["Saved commands", "Reusable commands for this server or your whole workspace."],
    tunnels: ["SSH tunnels", "Local, remote, and SOCKS5 forwarding managed by Serverbox."],
  };
  const [title, subtitle] = titles[activeView];
  const snapshotNotice = activeView === "dashboard"
    ? `<span class="overview-snapshot-note">${icon("info")} Snapshot metrics · not live</span>`
    : "";
  return `<div class="page-head"><div><div class="eyebrow">${escapeHtml(server.name)} <span class="eyebrow-separator">/</span> ${title}</div><h1>${title}</h1><p>${subtitle}</p></div><div class="page-actions">${snapshotNotice}<button class="button button-quiet" data-action="refresh">${icon("refresh")} Refresh</button></div></div>${renderView()}`;
}

function renderView(): string {
  if (viewTransitionIsCurrent()) return renderViewLoading();
  if (activeView === "dashboard" && !activeOperation && !dashboard && !activeServerIsConnected()) return `${errorMessage ? renderInlineError() : ""}${renderConnectPrompt()}`;
  if (errorMessage && activeView !== "dashboard") return `${renderError()}${renderViewBody()}`;
  return `${errorMessage ? renderInlineError() : ""}${renderViewBody()}`;
}

function renderConnectPrompt(): string {
  const server = activeServer();
  if (!server) return renderWelcome();
  const bastion = snapshot.servers.find((candidate) => candidate.id === server.jumpHostId);
  const route = bastion
    ? ` The connection routes through ${escapeHtml(profileRouteLabel(bastion))}.`
    : "";
  return `<div class="connect-prompt"><div class="connect-prompt-art">${icon("shield")}</div><div class="eyebrow">Connection is idle</div><h2>Ready when you are.</h2><p>Nothing has contacted ${escapeHtml(server.host)} yet. Serverbox will read this connection's saved secret only when you choose to connect.${route}</p><button class="button button-primary" data-action="connect">${icon("play")} Connect to ${escapeHtml(server.name)}</button></div>`;
}

function renderViewBody(): string {
  switch (activeView) {
    case "dashboard": return renderDashboard();
    case "terminal": return renderTerminal();
    case "processes": return renderProcesses();
    case "services": return renderServices();
    case "files": return renderFiles();
    case "disk": return renderDisk();
    case "docker": return renderDocker();
    case "logs": return renderLogs();
    case "network": return renderNetwork();
    case "cron": return renderCron();
    case "packages": return renderPackages();
    case "accounts": return renderAccounts();
    case "administration": return renderAdministration();
    case "commands": return renderCommands();
    case "tunnels": return renderTunnels();
  }
}

function renderViewLoading(): string {
  const server = activeServer();
  const firstConnection = !activeServerIsConnected();
  const title = activeOperation?.label ?? (firstConnection ? "Establishing a secure connection…" : "Loading this view…");
  const detail = firstConnection
    ? `Connecting to ${server?.host ?? "the server"} and reading its overview. SSH can take a moment on the first connection.`
    : `Reading fresh information from ${server?.host ?? "the server"}. You can switch views or cancel at any time.`;
  return `<div class="view-loading" role="status" aria-live="polite" aria-busy="true"><div class="view-loading-card"><div class="view-loading-mark"><div class="spinner"></div>${icon("logo")}</div><div><strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p></div></div><div class="view-loading-skeleton" aria-hidden="true"><span></span><span></span><span></span><span></span></div></div>`;
}

function renderError(): string {
  return renderErrorView(errorMessage);
}

function renderInlineError(): string {
  return renderInlineErrorView(errorMessage);
}

function renderDashboard(): string {
  if (!dashboard) return renderViewLoading();
  const { profile, cpu, memory, storage, uptime, network } = dashboard;
  const primaryDisk = storage?.disks[0];
  const cap = profile?.capabilities;
  return `<div class="dashboard-grid">
    ${cpu ? `<div class="stat-card stat-card-large"><div class="stat-card-head"><span class="stat-icon coral">${icon("cpu")}</span><span>CPU load</span><span>SNAPSHOT</span></div><div class="stat-value">${cpu.cpuPercent.toFixed(1)}<small>%</small></div><div class="stat-meta">${cpu.cpuCores} cores · ${escapeHtml(cpu.cpuModel)}</div>${sparkline(cpu.cpuPercent, "coral")}</div>` : renderDashboardPlaceholder("div", "stat-card stat-card-large", "CPU load", "cpu")}
    ${memory ? `<div class="stat-card stat-card-large"><div class="stat-card-head"><span class="stat-icon sage">${icon("memory")}</span><span>Memory</span><span>${memory.memory.percent.toFixed(0)}%</span></div><div class="stat-value">${formatBytes(memory.memory.usedBytes)}<small> used</small></div><div class="stat-meta">${formatBytes(memory.memory.freeBytes)} available of ${formatBytes(memory.memory.totalBytes)}</div>${meter(memory.memory.percent, "sage")}</div>` : renderDashboardPlaceholder("div", "stat-card stat-card-large", "Memory", "memory")}
    ${storage ? `<div class="stat-card stat-card-large"><div class="stat-card-head"><span class="stat-icon amber">${icon("disk")}</span><span>System disk</span><span>${primaryDisk ? `${primaryDisk.percent.toFixed(0)}%` : "—"}</span></div><div class="stat-value">${primaryDisk ? formatBytes(primaryDisk.usedBytes) : "—"}<small> used</small></div><div class="stat-meta">${primaryDisk ? `${formatBytes(primaryDisk.availableBytes)} free on ${escapeHtml(primaryDisk.mount)}` : "No disk data"}</div>${meter(primaryDisk?.percent ?? 0, "amber")}</div>` : renderDashboardPlaceholder("div", "stat-card stat-card-large", "System disk", "storage")}
    ${uptime ? `<div class="stat-card stat-card-large"><div class="stat-card-head"><span class="stat-icon blue">${icon("clock")}</span><span>Uptime</span><span>STEADY</span></div><div class="stat-value">${formatDuration(uptime.uptimeSeconds)}</div><div class="stat-meta">Load ${uptime.loadAverages.map((value) => value.toFixed(2)).join(" · ")}</div>${sparkline(uptime.loadAverages[0] * 20, "blue")}</div>` : renderDashboardPlaceholder("div", "stat-card stat-card-large", "Uptime", "uptime")}

    ${profile ? `<section class="panel overview-panel"><div class="panel-head"><div><div class="panel-kicker">Machine profile</div><h2>${escapeHtml(profile.hostname)}</h2><p>${escapeHtml(profile.os)}</p></div><span class="status-badge status-good"><i></i>Reachable</span></div><div class="machine-details"><div><span>Kernel</span><strong>${escapeHtml(profile.kernel)}</strong></div><div><span>Architecture</span><strong>${escapeHtml(profile.architecture)}</strong></div><div><span>Last refresh</span><strong>${formatDate(profile.connectedAt)}</strong></div></div><div class="capability-row">${capabilityBadge("systemd", cap?.systemd ?? false)}${capabilityBadge("Containers", Boolean(cap?.docker || cap?.podman))}${capabilityBadge("sudo", Boolean(cap?.sudo || cap?.root))}${capabilityBadge("cron", cap?.cron ?? false)}${capabilityBadge(cap?.packageManager ?? "packages", Boolean(cap?.packageManager))}${capabilityBadge(cap?.networkTool ?? "network", Boolean(cap?.networkTool))}${capabilityBadge("journalctl", cap?.journalctl ?? false)}${capabilityBadge("logread", cap?.logread ?? false)}</div></section>` : renderDashboardPlaceholder("section", "panel overview-panel", "Machine profile", "profile")}
    ${uptime ? `<section class="panel load-panel"><div class="panel-head compact"><div><div class="panel-kicker">Load averages</div><h2>How busy is it?</h2></div><span class="panel-note">1 · 5 · 15 min</span></div><div class="load-bars">${uptime.loadAverages.map((value, index) => `<div class="load-row"><span>${["01", "05", "15"][index]}</span>${meter(Math.min(100, value / Math.max(1, cpu?.cpuCores ?? 1) * 100), index === 0 ? "coral" : index === 1 ? "sage" : "blue")}<strong>${value.toFixed(2)}</strong></div>`).join("")}</div>${memory ? `<div class="swap-note"><span>${icon("memory")} Swap</span><strong>${formatBytes(memory.swap.usedBytes)} / ${formatBytes(memory.swap.totalBytes)}</strong>${meter(memory.swap.percent, "amber")}</div>` : `<div class="swap-note dashboard-inline-loading"><span>${icon("memory")} Swap</span><span>Waiting for memory…</span></div>`}</section>` : renderDashboardPlaceholder("section", "panel load-panel", "Load averages", "uptime")}
    ${storage ? `<section class="panel disk-panel"><div class="panel-head compact"><div><div class="panel-kicker">Storage</div><h2>Mounted disks</h2></div><span class="panel-note">${storage.disks.length} mount${storage.disks.length === 1 ? "" : "s"}</span></div>${storage.disks.length ? `<div class="disk-list">${storage.disks.slice(0, 5).map((disk) => `<div class="disk-row"><div class="disk-row-name"><span>${icon("folder")}</span><strong>${escapeHtml(disk.mount)}</strong><small>${escapeHtml(disk.filesystem)}</small></div><div class="disk-row-meter">${meter(disk.percent, disk.percent > 85 ? "coral" : "amber")}<small>${formatBytes(disk.usedBytes)} of ${formatBytes(disk.totalBytes)}</small></div><strong class="disk-percent">${disk.percent.toFixed(0)}%</strong></div>`).join("")}</div>` : `<div class="empty-mini">Disk usage could not be read.</div>`}</section>` : renderDashboardPlaceholder("section", "panel disk-panel", "Mounted disks", "storage")}
    ${network ? `<section class="panel network-panel"><div class="panel-head compact"><div><div class="panel-kicker">Network</div><h2>Interfaces</h2></div><button class="text-button" data-view="network">View ports ${icon("chevron")}</button></div>${network.interfaces.length ? `<div class="interface-list">${network.interfaces.slice(0, 5).map((item) => `<div class="interface-row"><span class="interface-dot"></span><strong>${escapeHtml(item.name)}</strong><span>${item.addresses.map(escapeHtml).join(" · ")}</span></div>`).join("")}</div>` : `<div class="empty-mini">No global network addresses reported.</div>`}</section>` : renderDashboardPlaceholder("section", "panel network-panel", "Network interfaces", "network")}
  </div>`;
}

function renderDashboardPlaceholder(tag: "div" | "section", className: string, label: string, card: DashboardCardName): string {
  const error = dashboard?.errors[card];
  const state = error
    ? `<div class="dashboard-card-error"><span>${icon("info")}</span><div><strong>${escapeHtml(label)} is unavailable</strong><small>${escapeHtml(error)}</small></div></div>`
    : `<div class="dashboard-card-skeleton" role="status" aria-live="polite"><span class="dashboard-card-shimmer"></span><div><strong>${dashboard?.loading ? `Loading ${label}…` : `${label} unavailable`}</strong><small>${dashboard?.loading ? "Collecting the overview in one secure request." : "No data was reported by this server."}</small></div></div>`;
  return `<${tag} class="${className} dashboard-card-loading">${state}</${tag}>`;
}

function renderCollectionFooter(hasMore: boolean, loaded: number, noun: string): string {
  if (!hasMore) return loaded ? `<div class="collection-footer"><span>All ${loaded} ${noun} loaded</span></div>` : "";
  return `<div class="collection-footer"><span>${loaded} ${noun} loaded</span><button class="button button-quiet small-button" data-action="load-more" ${activeOperation ? "disabled" : ""}>${activeOperation ? "Loading…" : `Load more ${noun}`}</button></div>`;
}

function capabilityBadge(label: string, enabled: boolean): string {
  return `<span class="capability ${enabled ? "enabled" : "disabled"}"><i></i>${label}</span>`;
}

function renderTerminal(): string {
  const current = terminalTabs.find((tab) => tab.id === activeTerminalTabId);
  const tabs = activeTerminalTabs();
  return `<section class="terminal-workspace"><div class="terminal-toolbar"><div class="terminal-tabs">${tabs.map((tab) => `<button class="terminal-tab ${tab.id === activeTerminalTabId ? "active" : ""}" data-terminal-tab="${tab.id}"><span class="terminal-tab-dot ${tab.closed ? "closed" : ""}"></span>${escapeHtml(tab.title)}${tabs.length > 1 ? `<span class="terminal-tab-close" data-terminal-close="${tab.id}">${icon("close")}</span>` : ""}</button>`).join("")}</div><button class="button button-quiet small-button" data-action="new-terminal">${icon("plus")} New session</button></div>${current ? `<div class="terminal-meta"><span>${icon("terminalSmall")} ${escapeHtml(activeServer()?.username ?? "user")}@${escapeHtml(activeServer()?.host ?? "server")}</span><span>${current.connecting ? "Opening session…" : current.closed ? `${current.command ? "Container" : "SSH"} session closed` : current.command ? "Container exec · xterm" : "Interactive SSH · xterm"}</span>${current.closed ? `<button class="text-button" data-action="reconnect-terminal">${icon("restart")} Reconnect</button>` : ""}<button class="text-button" data-action="clear-terminal">Clear ${icon("close")}</button></div><div class="terminal-surface" data-terminal-surface="${current.id}"></div>` : `<div class="terminal-empty"><div class="terminal-empty-art">${icon("terminal")}</div><h2>A shell for whatever comes next.</h2><p>Every server deserves a good terminal fallback. Open one when you need to go off-road.</p><button class="button button-primary" data-action="new-terminal">${icon("terminalSmall")} Open terminal</button></div>`}</section>`;
}

function renderProcesses(): string {
  const rows = processes;
  return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">Live process table</div><h2>${rows.length} processes loaded</h2><p>Refreshes every 5 seconds · sorted by CPU</p></div><div class="table-head-actions"><span class="status-badge status-live"><i></i>Auto refresh</span><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div></div><div class="table-scroll"><table><thead><tr><th>PID</th><th>Process / user</th><th>CPU</th><th>Memory</th><th>RSS</th><th>Runtime</th><th></th></tr></thead><tbody>${rows.length ? rows.map(renderProcessRow).join("") : `<tr><td colspan="7"><div class="empty-table">No processes were returned.</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(processesHasMore, rows.length, "processes")}</section>`;
}

function renderProcessRow(process: ProcessInfo): string {
  return `<tr><td><span class="mono muted-text">${process.pid}</span></td><td><div class="process-name"><strong title="${escapeHtml(process.command)}">${escapeHtml(process.command)}</strong><small>${escapeHtml(process.user)}</small></div></td><td><span class="metric-number ${process.cpuPercent > 70 ? "hot" : ""}">${process.cpuPercent.toFixed(1)}%</span></td><td><span class="metric-number">${process.memoryPercent.toFixed(1)}%</span></td><td class="muted-text">${formatBytes(process.rssBytes)}</td><td class="muted-text">${formatDuration(process.runtimeSeconds)}</td><td><div class="row-actions"><button class="row-action" data-process-action="term" data-pid="${process.pid}" title="Send SIGTERM">${icon("stop")}</button><button class="row-action danger" data-process-action="kill" data-pid="${process.pid}" title="Force kill">${icon("close")}</button></div></td></tr>`;
}

function renderServices(): string {
  const cap = activeCapabilities();
  if (cap && !cap.systemd) return renderUnsupported("systemd is not available on this server", "This machine did not report systemd. Systemd services are hidden until a compatible init system is detected.");
  return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">systemd service manager</div><h2>${services.length} units loaded</h2><p>Start, stop, reload, and inspect recent journal entries.</p></div><div class="table-head-actions"><span class="status-badge status-good"><i></i>systemd</span><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div></div><div class="service-filter"><span>${icon("search")}</span><input data-field="service-search" placeholder="Filter loaded services…"/><span class="service-count">${services.filter((service) => service.activeState === "active").length} active</span></div><div class="table-scroll"><table><thead><tr><th>Unit</th><th>State</th><th>Description</th><th>Enabled</th><th></th></tr></thead><tbody>${services.length ? services.map(renderServiceRow).join("") : `<tr><td colspan="5"><div class="empty-table">No services returned.</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(servicesHasMore, services.length, "services")}</section>`;
}

function renderServiceRow(service: ServiceInfo): string {
  const good = service.activeState === "active";
  return `<tr data-service-row="${escapeHtml(service.name)}"><td><div class="unit-name"><span class="service-dot ${good ? "active" : service.activeState === "failed" ? "failed" : "idle"}"></span><strong>${escapeHtml(service.name)}</strong></div></td><td><span class="state-label ${good ? "good" : service.activeState === "failed" ? "bad" : "muted"}">${escapeHtml(service.activeState)} · ${escapeHtml(service.subState)}</span></td><td class="description-cell">${escapeHtml(service.description || "—")}</td><td class="muted-text">${service.enabled === undefined ? "—" : service.enabled ? "Enabled" : "Disabled"}</td><td><div class="row-actions service-actions">${good ? `<button class="row-action" data-service-action="stop" data-service="${escapeHtml(service.name)}" title="Stop">${icon("stop")}</button>` : `<button class="row-action" data-service-action="start" data-service="${escapeHtml(service.name)}" title="Start">${icon("play")}</button>`}<button class="row-action" data-service-action="restart" data-service="${escapeHtml(service.name)}" title="Restart">${icon("restart")}</button><button class="row-action" data-service-action="reload" data-service="${escapeHtml(service.name)}" title="Reload">${icon("refresh")}</button><button class="row-action" data-service-details="${escapeHtml(service.name)}" title="Details">${icon("chevron")}</button></div></td></tr>`;
}

function renderFiles(): string {
  const filtered = remoteFiles.filter((file) => file.name.toLowerCase().includes(remoteFileSearch.toLowerCase()));
  const parts = remotePath.split("/").filter(Boolean);
  let accumulated = "";
  const crumbs = [`<button data-file-path="/">root</button>`, ...parts.map((part) => { accumulated += `/${part}`; return `<span>/</span><button data-file-path="${escapeHtml(accumulated)}">${escapeHtml(part)}</button>`; })].join("");
  return `<section class="files-workspace"><div class="files-toolbar"><div class="breadcrumbs">${crumbs}</div><div class="files-toolbar-actions"><label class="toggle-control"><input type="checkbox" data-field="show-hidden" ${showHidden ? "checked" : ""}/><span></span>Hidden</label><button class="button button-quiet" data-action="new-folder">${icon("folder")} New folder</button><button class="button button-quiet" data-action="upload-file">${icon("upload")} File</button><button class="button button-quiet" data-action="upload-folder">${icon("folder")} Folder</button></div></div><div class="file-drop-zone" data-file-drop>${icon("upload")} Drop files or folders here to upload</div><div class="panel table-panel file-table-panel"><div class="file-table-search"><span>${icon("search")}</span><input data-field="file-search" value="${escapeHtml(remoteFileSearch)}" placeholder="Search loaded files…"/><span class="file-location">${escapeHtml(remotePath)}</span><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div><div class="table-scroll"><table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Permissions</th><th>Owner</th><th></th></tr></thead><tbody>${remotePath !== "/" ? `<tr class="parent-row"><td colspan="6"><button class="file-name-button" data-file-path="${escapeHtml(parentPath(remotePath))}">${icon("back")} ..</button></td></tr>` : ""}${filtered.length ? filtered.map(renderFileRow).join("") : `<tr><td colspan="6"><div class="empty-table">${remoteFiles.length ? "No matching files." : "This folder is empty or could not be read."}</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(filesHaveMore, remoteFiles.length, "files")}</div></section>`;
}

function renderFileRow(file: RemoteFile): string {
  const isDir = file.kind === "directory";
  return `<tr><td><button class="file-name-button" data-file-${isDir ? "path" : "edit"}="${escapeHtml(file.path)}">${icon(isDir ? "folder" : "file")}<strong>${escapeHtml(file.name)}</strong>${file.kind === "symlink" ? `<small>symlink</small>` : ""}</button></td><td class="muted-text">${isDir ? "—" : formatBytes(file.sizeBytes)}</td><td class="muted-text">${formatDate(file.modifiedAt)}</td><td><span class="mono muted-text">${escapeHtml(file.permissions ?? "—")}</span></td><td class="muted-text">${file.uid ?? "—"}:${file.gid ?? "—"}</td><td><div class="row-actions"><button class="row-action" data-file-download="${escapeHtml(file.path)}" title="Download">${icon("download")}</button><button class="row-action" data-file-edit="${escapeHtml(file.path)}" title="Edit">${icon("edit")}</button><button class="row-action" data-file-chmod="${escapeHtml(file.path)}" title="Change permissions">${icon("settings")}</button><button class="row-action" data-file-chown="${escapeHtml(file.path)}" title="Change owner">${icon("shield")}</button><button class="row-action danger" data-file-delete="${escapeHtml(file.path)}" title="Delete">${icon("trash")}</button></div></td></tr>`;
}

function parentPath(path: string): string { const value = path.replace(/\/$/, ""); const parent = value.slice(0, value.lastIndexOf("/")); return parent || "/"; }

function diskMeterTone(percent: number): "coral" | "amber" | "sage" {
  if (percent >= 90) return "coral";
  if (percent >= 80) return "amber";
  return "sage";
}

function renderDisk(): string {
  if (!diskSnapshot) return renderViewLoading();
  const { mounts, largestFiles, largestDirs, dockerUsage } = diskSnapshot;
  if (diskTab === "docker" && !dockerUsage) diskTab = "mounts";
  const tabs = [
    ["mounts", "Mounts", `${mounts.length}`],
    ["files", "Largest files", largestFiles.length ? `${largestFiles.length}` : "·"],
    ["dirs", "Largest directories", largestDirs.length ? `${largestDirs.length}` : "·"],
    ...(dockerUsage ? [["docker", "Docker disk", ""] as [DiskTab, string, string]] : []),
    ["varlog", "/var/log", ""],
  ] as Array<[DiskTab, string, string]>;
  return `<section class="docker-workspace"><div class="subnav-tabs workspace-tabs container-platform-tabs">${tabs.map(([tab, label, count]) => `<button class="subnav-tab ${diskTab === tab ? "active" : ""}" data-disk-tab="${tab}">${label}${count ? ` <span>${count}</span>` : ""}</button>`).join("")}</div>${renderDiskTab()}</section>`;
}

function renderDiskTab(): string {
  if (!diskSnapshot) return "";
  switch (diskTab) {
    case "mounts": return renderDiskMounts();
    case "files": return renderDiskLargestFiles();
    case "dirs": return renderDiskLargestDirs();
    case "docker": return diskSnapshot.dockerUsage ? renderDockerDiskPanel(diskSnapshot.dockerUsage) : "";
    case "varlog": return renderDiskVarLog();
  }
}

function renderDiskMounts(): string {
  const { mounts } = diskSnapshot!;
  const inodeCell = (mount: (typeof mounts)[number]): string => {
    if (mount.inodeTotal === undefined || mount.inodeUsed === undefined) return `<td class="muted-text">—</td>`;
    const percent = mount.inodePercent ?? (mount.inodeTotal ? mount.inodeUsed / mount.inodeTotal * 100 : 0);
    return `<td><div class="disk-inode-cell"><span class="metric-number ${percent >= 90 ? "hot" : ""}">${percent.toFixed(0)}%</span><small class="muted-text">${formatNumber(mount.inodeUsed)} / ${formatNumber(mount.inodeTotal)}</small></div></td>`;
  };
  return `<section class="panel table-panel"><div class="panel-head compact"><div><div class="panel-kicker">Mount overview</div><h2>${mounts.length} mounted filesystem${mounts.length === 1 ? "" : "s"}</h2><p>Sorted by how full each mount is. Inodes appear when the filesystem reports them.</p></div><span class="panel-note">snapshot</span></div>
    ${mounts.length ? `<div class="table-scroll"><table><thead><tr><th>Mount</th><th>Filesystem</th><th>Usage</th><th>Used</th><th>Available</th><th>Inodes</th></tr></thead><tbody>${mounts.map((mount) => `<tr>
      <td><div class="process-name wrap-anywhere"><strong title="${escapeHtml(mount.mount)}">${escapeHtml(mount.mount)}</strong><small>${diskMountKind(mount)}</small></div></td>
      <td class="mono muted-text"><span class="file-path-text">${escapeHtml(mount.filesystem)}</span></td>
      <td class="disk-usage-cell"><div class="disk-usage-inner">${meter(mount.percent, diskMeterTone(mount.percent))}<strong class="disk-percent ${mount.percent >= 90 ? "hot-text" : ""}">${mount.percent.toFixed(0)}%</strong></div></td>
      <td class="muted-text">${formatBytes(mount.usedBytes)} <small>of ${formatBytes(mount.totalBytes)}</small></td>
      <td class="muted-text">${formatBytes(mount.availableBytes)}</td>
      ${inodeCell(mount)}
    </tr>`).join("")}</tbody></table></div>` : `<div class="empty-table">Disk usage could not be read on this server.</div>`}
  </section>`;
}

function renderDiskLargestFiles(): string {
  const { largestFiles } = diskSnapshot!;
  return `<section class="panel table-panel"><div class="panel-head compact"><div><div class="panel-kicker">Largest files</div><h2>${largestFiles.length ? `${largestFiles.length} largest files found` : "No large files reported"}</h2><p>Bounded scan of common high-consumption roots (/var, /opt, /srv, /home, /usr/local), four levels deep. Permission-restricted paths may be missed.</p></div></div>
    ${largestFiles.length ? `<div class="table-scroll"><table><thead><tr><th>Path</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>${largestFiles.map((file) => `<tr>
      <td class="file-path-cell"><span class="mono file-path-text" title="${escapeHtml(file.path)}">${escapeHtml(file.path)}</span></td>
      <td><strong>${formatBytes(file.sizeBytes)}</strong></td>
      <td class="muted-text">${file.modifiedAt ? formatDate(file.modifiedAt) : "—"}</td>
      <td><div class="row-actions"><button class="row-action" data-disk-open-path="${escapeHtml(file.path)}" title="Open folder in Files">${icon("folder")}</button></div></td>
    </tr>`).join("")}</tbody></table></div>` : `<div class="empty-table">No matching files were found in the scanned roots.</div>`}
  </section>`;
}

function renderDiskLargestDirs(): string {
  const { largestDirs } = diskSnapshot!;
  return `<section class="panel table-panel"><div class="panel-head compact"><div><div class="panel-kicker">Largest directories</div><h2>${largestDirs.length ? `${largestDirs.length} largest directories found` : "No large directories reported"}</h2><p>Disk usage per directory tree, staying on one filesystem and three levels deep.</p></div></div>
    ${largestDirs.length ? `<div class="table-scroll"><table><thead><tr><th>Path</th><th>Size</th><th>Depth</th><th></th></tr></thead><tbody>${largestDirs.map((dir) => `<tr>
      <td class="file-path-cell"><span class="mono file-path-text" title="${escapeHtml(dir.path)}">${escapeHtml(dir.path)}</span></td>
      <td><strong>${formatBytes(dir.sizeBytes)}</strong></td>
      <td class="muted-text">${dir.depth}</td>
      <td><div class="row-actions"><button class="row-action" data-disk-open-path="${escapeHtml(dir.path)}" title="Open folder in Files">${icon("folder")}</button></div></td>
    </tr>`).join("")}</tbody></table></div>` : `<div class="empty-table">No directories over 10 MB were found in the scanned roots.</div>`}
  </section>`;
}

function renderDiskVarLog(): string {
  return `<section class="panel"><div class="panel-head compact"><div><div class="panel-kicker">Log directory</div><h2>/var/log breakdown</h2><p>On-demand view for the classic “why is /var full?” question.</p></div><button class="icon-button" data-disk-varlog title="Reload /var/log usage">${icon("refresh")}</button></div>
    ${diskVarLogLoading ? `<div class="collection-loading" role="status"><div class="spinner"></div><span>Measuring /var/log…</span></div>` : diskVarLog?.length ? `<div class="varlog-list">${diskVarLog.map((entry) => `<div class="disk-row"><div class="disk-row-name"><span>${icon("folder")}</span><strong title="${escapeHtml(entry.path)}">${escapeHtml(entry.path)}</strong></div><div class="disk-row-meter">${meter(Math.min(100, entry.sizeBytes / Math.max(1, diskVarLog![0].sizeBytes) * 100), "blue")}</div><strong class="disk-percent">${formatBytes(entry.sizeBytes)}</strong></div>`).join("")}</div>` : `<div class="disk-docker-body"><div class="empty-mini">/var/log could not be read or is empty.</div></div>`}
  </section>`;
}

function diskMountKind(mount: import("./types").DiskMount): string {
  const fs = mount.filesystem.toLowerCase();
  if (fs.startsWith("nfs") || fs.includes(":/") || fs.startsWith("cifs") || fs.startsWith("smb")) return "network mount";
  if (fs.startsWith("tmpfs") || fs.startsWith("devtmpfs") || fs.startsWith("overlay") || fs.startsWith("squashfs")) return "virtual";
  return "local";
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(Math.round(value));
}

function renderDockerDiskPanel(usage: NonNullable<DiskExplorerSnapshot["dockerUsage"]>): string {
  const rows = [
    ["Images", usage.imagesBytes],
    ["Containers", usage.containersBytes],
    ["Volumes", usage.volumesBytes],
    ["Build cache", usage.buildCacheBytes],
    ...(usage.otherBytes > 0 ? [["Other", usage.otherBytes] as [string, number]] : []),
  ] as Array<[string, number]>;
  return `<section class="panel"><div class="panel-head compact"><div><div class="panel-kicker">Container runtime</div><h2>Docker disk usage</h2><p>Reported by docker system df. Reclaimable is what a prune would free.</p></div><button class="button button-quiet small-button" data-disk-open-path="/var/lib/docker" title="Open Docker data root in Files">${icon("folder")} /var/lib/docker</button></div>
    <div class="disk-docker-body">
      <div class="disk-stat-cards">${rows.map(([label, bytes]) => `<div class="network-stat"><span class="stat-icon amber">${icon("docker")}</span><div><strong>${formatBytes(bytes)}</strong><span>${label}</span></div></div>`).join("")}</div>
      <div class="machine-details"><div><span>Total</span><strong>${formatBytes(usage.totalBytes)}</strong></div><div><span>Reclaimable</span><strong>${formatBytes(usage.reclaimableBytes)}</strong></div></div>
    </div>
  </section>`;
}

async function selectDiskTab(tab: DiskTab): Promise<void> {
  diskTab = tab;
  errorMessage = "";
  render();
  if (tab === "varlog") await ensureDiskVarLog(false);
}

/// Loads /var/log usage on demand. `force` re-measures even when cached
/// (the tab's reload button); plain tab switches reuse the cached result.
async function ensureDiskVarLog(force: boolean): Promise<void> {
  const serverId = activeServerId;
  if (!serverId || (diskVarLog && !force) || diskVarLogLoading) return;
  diskVarLogLoading = true;
  if (!diskVarLog || force) render();
  try {
    const entries = await invokeCommand<LargestDirectory[]>("get_disk_varlog", { serverId });
    if (activeServerId !== serverId) return;
    diskVarLog = entries;
  } catch (error) {
    setError(error);
  } finally {
    diskVarLogLoading = false;
    if (activeServerId === serverId && activeView === "disk") render();
  }
}

async function openDiskPathInFiles(path: string): Promise<void> {
  remotePath = parentPath(path);
  remoteFileSearch = "";
  remoteFiles = [];
  filesHaveMore = false;
  errorMessage = "";
  await setView("files");
}

function renderDocker(): string {
  const cap = activeCapabilities();
  if (cap && !cap.docker && !cap.podman) return renderUnsupported("No container runtime is available", "The SSH endpoint is not a Docker or Podman host. Install Docker or Podman on that server and reconnect; Serverbox will detect it automatically.");
  return `<section class="docker-workspace"><div class="subnav-tabs workspace-tabs container-platform-tabs"><button class="subnav-tab ${containerPlatformTab === "runtime" ? "active" : ""}" data-container-platform-tab="runtime">Runtime resources</button><button class="subnav-tab ${containerPlatformTab === "compose" ? "active" : ""}" data-container-platform-tab="compose">Compose projects</button></div>${containerPlatformTab === "compose" ? renderComposeProjects() : renderRuntimeResources()}${containerLogBelongsToActiveTab() ? renderContainerLogs() : ""}</section>`;
}

function renderRuntimeResources(): string {
  if (!docker) return renderViewLoading();
  const currentDocker = docker;
  return `<div class="docker-summary"><div class="docker-runtime"><span class="docker-mark">${icon("docker")}</span><div><div class="panel-kicker">Container runtime</div><h2>${escapeHtml(currentDocker.runtime)}</h2><p>Each resource type loads independently in manageable pages.</p></div></div><div class="docker-summary-stats">${(["containers", "images", "volumes", "networks"] as const).map((section) => `<div><strong>${dockerLoaded[section] ? currentDocker[section].length : "—"}${dockerHasMore[section] ? "+" : ""}</strong><span>${section} loaded</span></div>`).join("")}</div></div><div class="subnav-tabs">${(["containers", "images", "volumes", "networks"] as const).map((tab) => `<button class="subnav-tab ${dockerTab === tab ? "active" : ""}" data-docker-tab="${tab}">${tab[0].toUpperCase() + tab.slice(1)} <span>${dockerLoaded[tab] ? `${currentDocker[tab].length}${dockerHasMore[tab] ? "+" : ""}` : "·"}</span></button>`).join("")}<span class="subnav-spacer"></span><button class="button button-quiet" data-action="docker-pull">${icon("download")} Pull image</button><button class="button button-primary" data-action="docker-create">${icon("plus")} Create container</button></div>${!dockerLoaded[dockerTab] ? `<div class="collection-loading" role="status"><div class="spinner"></div><span>Loading ${dockerTab}…</span></div>` : dockerTab === "containers" ? renderContainers() : dockerTab === "images" ? renderImages() : dockerTab === "volumes" ? renderVolumes() : renderNetworks()}`;
}

function renderComposeProjects(): string {
  return `<section class="panel"><div class="panel-head"><div><div class="panel-kicker">Docker Compose</div><h2>${composeProjects.length} Compose ${composeProjects.length === 1 ? "project" : "projects"} found</h2><p>Scans common deployment locations for Compose configuration files.</p></div><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div><div class="tier3-grid">${composeProjects.length ? composeProjects.map((project) => {
    const actions = ["up", "down", "restart", "pull", "rebuild", "logs", "exec", "scale"];
    return `<article class="tier3-card"><div class="tier3-card-head"><span class="stat-icon blue">${icon("docker")}</span><span class="status-badge ${project.running ? "status-good" : ""}"><i></i>${project.running} running</span></div><h3>${escapeHtml(project.name)}</h3><code>${escapeHtml(project.path)}</code><p>${project.services.length ? project.services.map((service) => `<span class="tag-chip">${escapeHtml(service)}</span>`).join(" ") : "No services returned"}</p>${project.topology.length ? `<div class="compose-meta"><strong>Topology</strong><span>${project.topology.map(escapeHtml).join(" · ")}</span></div>` : ""}${project.environment.length ? `<details class="compose-environment"><summary>Environment keys (${project.environment.length})</summary><span>${project.environment.map(escapeHtml).join(" · ")}</span></details>` : ""}<div class="tier3-card-actions">${actions.map((action) => {
      const execUnavailable = action === "exec" && project.running === 0;
      return `<button class="button button-quiet small-button" data-compose-action="${action}" data-compose-path="${escapeHtml(project.path)}" ${execUnavailable ? "disabled title=\"Start a Compose service before running a command\"" : ""}>${action}</button>`;
    }).join("")}</div></article>`;
  }).join("") : `<div class="empty-state compact-empty"><h2>No Compose projects found</h2><p>Projects under the remote home, /opt, /srv, and /var/www appear here.</p></div>`}</div>${renderCommandResults()}</section>`;
}

function renderContainerLogs(): string {
  if (!containerLogViewer) return "";
  const project = containerLogViewer.target.source === "compose"
    ? composeProjects.find((item) => item.path === containerLogViewer?.target.composePath)
    : undefined;
  const targetField = project?.services.length
    ? `<label class="field compact-field"><span>Service</span><select data-field="log-service" data-log-scope="container"><option value="" ${!containerLogViewer.target.service ? "selected" : ""}>All services</option>${project.services.map((service) => `<option value="${escapeHtml(service)}" ${containerLogViewer?.target.service === service ? "selected" : ""}>${escapeHtml(service)}</option>`).join("")}</select></label>`
    : "";
  return renderLogViewer(containerLogViewer, "container", "", targetField, true);
}

function renderContainers(): string {
  return `<section class="panel table-panel"><div class="panel-head compact"><div><div class="panel-kicker">All containers</div><h2>${docker?.containers.length ?? 0} containers loaded</h2></div><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div><div class="container-grid">${docker?.containers.length ? docker.containers.map(renderContainerCard).join("") : `<div class="empty-state compact-empty"><div class="empty-art">${icon("docker")}</div><h2>No containers yet</h2><p>Create the first one from an image.</p></div>`}</div>${renderCollectionFooter(dockerHasMore.containers, docker?.containers.length ?? 0, "containers")}</section>`;
}

function renderContainerCard(container: ContainerInfo): string {
  const state = container.state.trim().toLowerCase();
  const paused = state === "paused";
  const running = state === "running" || paused;
  const canExec = state === "running";
  const execState = canExec ? "" : "disabled title=\"Start the container before opening an exec shell\"";
  return `<article class="container-card"><div class="container-card-head"><span class="container-status ${running ? "running" : "stopped"}"><i></i>${escapeHtml(container.state || "unknown")}</span><button class="icon-button small" data-docker-inspect="${escapeHtml(container.id)}" data-docker-kind="container">${icon("more")}</button></div><h3>${escapeHtml(container.name || shortId(container.id))}</h3><p class="container-image">${escapeHtml(container.image)}</p><div class="container-metrics"><div><span>CPU</span><strong>${container.cpuPercent?.toFixed(1) ?? "—"}%</strong>${meter(container.cpuPercent ?? 0, "coral")}</div><div><span>Memory</span><strong>${container.memoryPercent?.toFixed(1) ?? "—"}%</strong>${meter(container.memoryPercent ?? 0, "sage")}</div></div>${container.ports ? `<div class="container-ports">${icon("network")} ${escapeHtml(container.ports)}</div>` : ""}<div class="container-card-foot"><span>${escapeHtml(container.status || "No status")}</span><div class="row-actions">${running ? `<button class="row-action" data-docker-action="restart" data-docker-target="${escapeHtml(container.id)}" title="Restart">${icon("restart")}</button><button class="row-action" data-docker-action="stop" data-docker-target="${escapeHtml(container.id)}" title="Stop">${icon("stop")}</button><button class="row-action" data-docker-action="${paused ? "unpause" : "pause"}" data-docker-target="${escapeHtml(container.id)}" title="${paused ? "Unpause" : "Pause"}">${icon("pause")}</button>` : `<button class="row-action" data-docker-action="start" data-docker-target="${escapeHtml(container.id)}" title="Start">${icon("play")}</button>`}<button class="row-action" data-docker-logs="${escapeHtml(container.id)}" title="View logs">${icon("logs")}</button><button class="row-action" data-docker-exec="${escapeHtml(container.id)}" ${execState}>${icon("terminalSmall")}</button><button class="row-action danger" data-docker-action="rm" data-docker-target="${escapeHtml(container.id)}" title="Remove">${icon("trash")}</button></div></div></article>`;
}

function renderImages(): string {
  return `<section class="panel table-panel"><div class="panel-head compact"><div><div class="panel-kicker">Image cache</div><h2>${docker?.images.length ?? 0} images loaded</h2></div><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div><div class="table-scroll"><table><thead><tr><th>Repository</th><th>Tag</th><th>Image ID</th><th>Size</th><th>Created</th><th></th></tr></thead><tbody>${docker?.images.length ? docker.images.map((image) => `<tr><td><strong>${escapeHtml(image.repository)}</strong></td><td><span class="tag-chip">${escapeHtml(image.tag)}</span></td><td class="mono muted-text">${escapeHtml(image.id)}</td><td class="muted-text">${escapeHtml(image.size)}</td><td class="muted-text">${escapeHtml(image.created)}</td><td><div class="row-actions"><button class="row-action" data-docker-inspect="${escapeHtml(image.id)}" data-docker-kind="image">${icon("info")}</button><button class="row-action danger" data-docker-action="rmi" data-docker-target="${escapeHtml(image.id)}">${icon("trash")}</button></div></td></tr>`).join("") : `<tr><td colspan="6"><div class="empty-table">No images returned.</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(dockerHasMore.images, docker?.images.length ?? 0, "images")}</section>`;
}

function renderVolumes(): string {
  return `<section class="panel table-panel"><div class="panel-head compact"><div><div class="panel-kicker">Persistent data</div><h2>${docker?.volumes.length ?? 0} volumes loaded</h2></div><div class="table-head-actions"><button class="button button-quiet small-button" data-action="docker-create-volume">${icon("plus")} Volume</button><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div></div><div class="table-scroll"><table><thead><tr><th>Name</th><th>Driver</th><th>Mountpoint</th><th></th></tr></thead><tbody>${docker?.volumes.length ? docker.volumes.map((volume) => `<tr><td><strong>${escapeHtml(volume.name)}</strong></td><td><span class="tag-chip">${escapeHtml(volume.driver)}</span></td><td class="mono muted-text">${escapeHtml(volume.mountpoint || "—")}</td><td><div class="row-actions"><button class="row-action" data-docker-inspect="${escapeHtml(volume.name)}" data-docker-kind="volume">${icon("info")}</button><button class="row-action danger" data-docker-action="volume-rm" data-docker-target="${escapeHtml(volume.name)}">${icon("trash")}</button></div></td></tr>`).join("") : `<tr><td colspan="4"><div class="empty-table">No volumes returned.</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(dockerHasMore.volumes, docker?.volumes.length ?? 0, "volumes")}</section>`;
}

function renderNetworks(): string {
  return `<section class="panel table-panel"><div class="panel-head compact"><div><div class="panel-kicker">Container networking</div><h2>${docker?.networks.length ?? 0} networks loaded</h2></div><div class="table-head-actions"><button class="button button-quiet small-button" data-action="docker-create-network">${icon("plus")} Network</button><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div></div><div class="table-scroll"><table><thead><tr><th>Name</th><th>Driver</th><th>Scope</th><th>ID</th><th></th></tr></thead><tbody>${docker?.networks.length ? docker.networks.map((network) => `<tr><td><strong>${escapeHtml(network.name)}</strong></td><td><span class="tag-chip">${escapeHtml(network.driver)}</span></td><td class="muted-text">${escapeHtml(network.scope)}</td><td class="mono muted-text">${escapeHtml(network.id)}</td><td><div class="row-actions"><button class="row-action" data-docker-inspect="${escapeHtml(network.name)}" data-docker-kind="network">${icon("info")}</button><button class="row-action danger" data-docker-action="network-rm" data-docker-target="${escapeHtml(network.name)}">${icon("trash")}</button></div></td></tr>`).join("") : `<tr><td colspan="5"><div class="empty-table">No networks returned.</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(dockerHasMore.networks, docker?.networks.length ?? 0, "networks")}</section>`;
}

function renderLogs(): string {
  const cap = activeCapabilities();
  const systemLogLabel = cap?.journalctl ? "System journal" : cap?.logread ? "Syslog buffer" : "System logs";
  const source = logsViewer.target.source;
  const sourceControl = `<div class="logs-control-group"><span class="control-label">Source</span><div class="segmented-control"><button class="${source === "system" ? "active" : ""}" data-logs-source="system">${icon("services")} ${systemLogLabel}</button><button class="${source === "container" ? "active" : ""}" data-logs-source="container" ${cap && !cap.docker && !cap.podman ? "disabled" : ""}>${icon("docker")} Container</button><button class="${source === "file" ? "active" : ""}" data-logs-source="file">${icon("folder")} File</button></div></div>`;
  let sourceFields = "";
  if (source === "system") {
    sourceFields = `<label class="field compact-field"><span>Service (optional)</span><input data-field="log-service" data-log-scope="workspace" value="${escapeHtml(logsViewer.target.service ?? "")}" placeholder="nginx.service" ${cap?.journalctl ? "" : "disabled"}/></label>`;
  } else if (source === "container") {
    sourceFields = `<label class="field compact-field"><span>Container</span><select data-field="log-container" data-log-scope="workspace"><option value="">Choose a container…</option>${docker?.containers.map((container) => `<option value="${escapeHtml(container.name || container.id)}" ${logsViewer.target.container === (container.name || container.id) ? "selected" : ""}>${escapeHtml(container.name || container.id)}</option>`).join("") ?? ""}</select></label>`;
  } else if (source === "file") {
    sourceFields = `<label class="field compact-field log-location-field"><span>Location</span><select data-field="log-file-container" data-log-scope="workspace"><option value="" ${!logsViewer.target.container ? "selected" : ""}>Server filesystem</option>${docker?.containers.map((container) => `<option value="${escapeHtml(container.name || container.id)}" ${logsViewer.target.container === (container.name || container.id) ? "selected" : ""}>${escapeHtml(container.name || container.id)}</option>`).join("") ?? ""}</select></label><label class="field compact-field log-path-field"><span>Absolute path</span><input data-field="log-file-path" data-log-scope="workspace" list="serverbox-log-files" value="${escapeHtml(logsViewer.target.filePath ?? "")}" placeholder="/var/log/nginx/error.log"/><datalist id="serverbox-log-files">${discoveredLogFiles.map((path) => `<option value="${escapeHtml(path)}"></option>`).join("")}</datalist></label>`;
  }
  return renderLogViewer(logsViewer, "workspace", sourceControl, sourceFields, false);
}

function renderLogViewer(viewer: LogViewerState, scope: "workspace" | "container", sourceControl: string, sourceFields: string, embedded: boolean): string {
  const cap = activeCapabilities();
  const sinceDisabled = viewer.target.source === "file" || (viewer.target.source === "system" && !cap?.journalctl);
  const lineCount = countLogLines(viewer.text);
  const statusLabel = viewer.status === "live" ? "Live" : viewer.status === "polling" ? "Live · polling" : viewer.status === "paused" ? "Paused" : viewer.status === "loading" ? "Catching up" : viewer.status === "stopped" ? "Stopped" : "Ready";
  const followLabel = viewer.following ? "Pause" : viewer.status === "paused" ? "Resume" : "Follow";
  const controls = `<div class="logs-controls panel">${sourceControl}${sourceFields}<label class="field compact-field"><span>Since</span><select data-field="log-since" data-log-scope="${scope}" ${sinceDisabled ? "disabled" : ""}>${renderLogSinceOptions(viewer.since)}</select></label><label class="field compact-field log-lines-field"><span>Lines</span><select data-field="log-lines" data-log-scope="${scope}">${renderLogLineOptions(viewer.lines)}</select></label><button class="button button-primary logs-run" data-action="load-log-viewer" data-log-scope="${scope}" ${activeOperation ? "disabled" : ""}>${icon("refresh")} Load logs</button><label class="follow-toggle" title="${followLabel} live output"><input type="checkbox" data-field="log-follow" data-log-scope="${scope}" ${viewer.following ? "checked" : ""}/><span></span>${followLabel}</label><span class="log-live-state ${viewer.status}"><i></i>${statusLabel}</span></div>`;
  const panel = `<div class="panel log-panel ${embedded ? "container-log-panel" : ""}"><div class="log-head"><div><div class="panel-kicker">${escapeHtml(logKicker(viewer.target))}</div><h2>${escapeHtml(viewer.target.label)}</h2><small class="log-line-count" data-log-count="${scope}">${lineCount} ${lineCount === 1 ? "line" : "lines"}</small></div><div class="log-actions"><label class="log-search"><span>${icon("search")}</span><input data-field="log-query" data-log-scope="${scope}" value="${escapeHtml(viewer.query)}" placeholder="Search output…"/><select data-field="log-severity" data-log-scope="${scope}"><option value="all" ${viewer.severity === "all" ? "selected" : ""}>All levels</option><option value="error" ${viewer.severity === "error" ? "selected" : ""}>Errors</option><option value="warn" ${viewer.severity === "warn" ? "selected" : ""}>Warnings</option></select></label><button class="icon-button" data-action="copy-log-viewer" data-log-scope="${scope}" title="Copy logs">${icon("copy")}</button><button class="icon-button" data-action="clear-log-viewer" data-log-scope="${scope}" title="Clear logs">${icon("trash")}</button></div></div><pre class="log-output" data-log-output="${scope}">${escapeHtml(filteredLogs(viewer))}</pre></div>`;
  return `<section class="logs-workspace ${embedded ? "embedded-log-workspace" : ""}">${controls}${panel}</section>`;
}

function logKicker(target: LogTarget): string {
  if (target.source === "system") return activeCapabilities()?.journalctl ? "system journal" : "syslog buffer";
  if (target.source === "compose") return "Compose output";
  if (target.source === "file") return target.container ? "container file" : "server file";
  return "container output";
}

function filteredLogs(viewer: LogViewerState): string {
  if (!viewer.text) return "Load a log source to begin.";
  const query = viewer.query.trim().toLowerCase();
  return viewer.text.split("\n").filter((line) => {
    const lower = line.toLowerCase();
    const queryMatch = !query || lower.includes(query);
    const severityMatch = viewer.severity === "all" || (viewer.severity === "error" ? /error|fail|fatal|crit/.test(lower) : /warn|notice/.test(lower));
    return queryMatch && severityMatch;
  }).join("\n") || "No log lines match the current filter.";
}

function countLogLines(value: string): number {
  return value ? value.replace(/\n$/, "").split("\n").length : 0;
}

function renderNetwork(): string {
  const listening = ports.filter((port) => port.state.toLowerCase().includes("listen"));
  const active = ports.filter((port) => !port.state.toLowerCase().includes("listen"));
  const networkTool = activeCapabilities()?.networkTool ?? "network";
  return `<section class="network-workspace"><div class="network-cards"><div class="network-stat"><span class="stat-icon coral">${icon("network")}</span><div><strong>${listening.length}</strong><span>listening sockets loaded</span></div></div><div class="network-stat"><span class="stat-icon sage">${icon("network")}</span><div><strong>${active.length}</strong><span>active connections loaded</span></div></div><div class="network-stat"><span class="stat-icon blue">${icon("shield")}</span><div><strong>${new Set(ports.map((port) => port.protocol)).size}</strong><span>protocols loaded</span></div></div></div><section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">${escapeHtml(networkTool)} network sockets</div><h2>${ports.length} ports & connections loaded</h2><p>Process mapping depends on the remote user's permissions.</p></div><button class="icon-button" data-action="refresh">${icon("refresh")}</button></div><div class="table-scroll"><table><thead><tr><th>Protocol</th><th>State</th><th>Local address</th><th>Remote address</th><th>Process</th></tr></thead><tbody>${ports.length ? ports.map((port) => `<tr><td><span class="protocol-chip">${escapeHtml(port.protocol)}</span></td><td><span class="state-label ${port.state.toLowerCase().includes("listen") ? "good" : "muted"}">${escapeHtml(port.state)}</span></td><td class="mono">${escapeHtml(port.localAddress)}</td><td class="mono muted-text">${escapeHtml(port.remoteAddress)}</td><td><span class="process-inline">${escapeHtml(port.process || "—")}</span></td></tr>`).join("") : `<tr><td colspan="5"><div class="empty-table">No sockets returned. Refresh after connecting.</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(portsHaveMore, ports.length, "connections")}</section></section>`;
}

function renderCron(): string {
  if (activeCapabilities()?.cron === false) return renderUnsupported("Cron is unavailable", "Install a crontab implementation on this server to manage scheduled commands.");
  return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">crontab & system schedules</div><h2>${cronJobs.length} scheduled jobs</h2><p>User jobs are editable; system cron files are shown read-only.</p></div><button class="button button-primary" data-action="new-cron">${icon("plus")} Add job</button></div><div class="table-scroll"><table><thead><tr><th>Status</th><th>Schedule</th><th>Command</th><th>User / source</th><th>Next run</th><th></th></tr></thead><tbody>${cronJobs.length ? cronJobs.map((job) => `<tr><td><span class="state-label ${job.enabled ? "good" : "muted"}">${job.enabled ? "Enabled" : "Disabled"}</span></td><td><strong>${escapeHtml(job.humanSchedule)}</strong><small class="row-subtitle mono">${escapeHtml(job.schedule)}</small></td><td><span class="command-cell mono">${escapeHtml(job.command)}</span></td><td>${escapeHtml(job.user)}<small class="row-subtitle">${escapeHtml(job.source)}</small></td><td class="muted-text">${job.nextRun ? formatDate(job.nextRun) : "—"}</td><td><div class="row-actions">${job.editable ? `<button class="row-action" data-cron-edit="${escapeHtml(job.id)}" title="Edit">${icon("edit")}</button><button class="row-action" data-cron-action="${job.enabled ? "disable" : "enable"}" data-cron-id="${escapeHtml(job.id)}" title="${job.enabled ? "Disable" : "Enable"}">${job.enabled ? icon("pause") : icon("play")}</button><button class="row-action danger" data-cron-action="delete" data-cron-id="${escapeHtml(job.id)}" title="Delete">${icon("trash")}</button>` : `<span class="tag-chip">read-only</span>`}</div></td></tr>`).join("") : `<tr><td colspan="6"><div class="empty-table">No cron jobs found.</div></td></tr>`}</tbody></table></div></section>`;
}

function renderPackages(): string {
  if (activeCapabilities()?.packageManager && activeCapabilities()?.packageManager !== "apt-get") return renderUnsupported("APT is required", "Tier-2 package management currently targets Debian and Ubuntu servers using APT.");
  const items = packagePage?.packages.items ?? [];
  return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">${escapeHtml(packagePage?.manager ?? "APT")}</div><h2>${packagePage?.pendingUpgrades ?? 0} pending upgrades</h2><p>Search available packages or browse software installed on this machine.</p></div><div class="table-head-actions"><button class="button button-quiet" data-package-action="update">apt update</button><button class="button button-primary" data-package-action="upgrade-all" ${(packagePage?.pendingUpgrades ?? 0) ? "" : "disabled"}>Upgrade all</button></div></div><div class="management-toolbar"><label class="toolbar-search inline-search"><span>${icon("search")}</span><input data-field="package-query" value="${escapeHtml(packageQuery)}" placeholder="Search packages…"/></label><button class="button button-quiet" data-action="search-packages">Search</button><label class="toggle-control"><input type="checkbox" data-field="package-upgrades" ${packageUpgradesOnly ? "checked" : ""}/><span></span>Upgrades only</label></div><div class="table-scroll"><table><thead><tr><th>Package</th><th>Version</th><th>Architecture</th><th>Description</th><th></th></tr></thead><tbody>${items.length ? items.map((pkg) => `<tr><td><strong>${escapeHtml(pkg.name)}</strong>${pkg.upgradeVersion ? `<small class="row-subtitle upgrade-label">${escapeHtml(pkg.upgradeVersion)} available</small>` : ""}</td><td class="mono muted-text">${escapeHtml(pkg.version || "available")}</td><td>${escapeHtml(pkg.architecture || "—")}</td><td class="muted-text package-description">${escapeHtml(pkg.description)}</td><td><div class="row-actions"><button class="row-action" data-package-details="${escapeHtml(pkg.name)}" title="Details">${icon("info")}</button>${pkg.installed ? `${pkg.upgradeVersion ? `<button class="row-action" data-package-action="upgrade" data-package-name="${escapeHtml(pkg.name)}" title="Upgrade">${icon("refresh")}</button>` : ""}<button class="row-action danger" data-package-action="remove" data-package-name="${escapeHtml(pkg.name)}" title="Remove">${icon("trash")}</button>` : `<button class="row-action" data-package-action="install" data-package-name="${escapeHtml(pkg.name)}" title="Install">${icon("download")}</button>`}</div></td></tr>`).join("") : `<tr><td colspan="5"><div class="empty-table">No packages match this view.</div></td></tr>`}</tbody></table></div>${renderCollectionFooter(packagePage?.packages.hasMore ?? false, items.length, "packages")}</section>`;
}

function renderAccounts(): string {
  const users = accounts?.users ?? [];
  const groups = accounts?.groups ?? [];
  const userRows = users.map((user) => {
    const protectedAccount = user.uid === 0 || user.name === activeServer()?.username;
    return `<tr><td><strong>${escapeHtml(user.name)}</strong><small class="row-subtitle">${user.locked ? "Locked" : (user.lastLogin ?? "Login allowed")}</small></td><td class="mono">${user.uid} / ${user.gid}</td><td class="mono muted-text">${escapeHtml(user.home)}</td><td class="mono muted-text">${escapeHtml(user.shell)}</td><td><span class="command-cell">${escapeHtml(user.groups.join(", ") || "—")}</span></td><td><div class="row-actions"><button class="row-action" data-user-action="shell" data-user-name="${escapeHtml(user.name)}" title="Change shell">${icon("terminalSmall")}</button><button class="row-action" data-user-action="groups" data-user-name="${escapeHtml(user.name)}" title="Set groups (requires usermod; unavailable on minimal Alpine without shadow)">${icon("users")}</button><button class="row-action" data-user-action="password" data-user-name="${escapeHtml(user.name)}" title="Reset password">${icon("key")}</button><button class="row-action" data-user-action="${user.locked ? "unlock" : "lock"}" data-user-name="${escapeHtml(user.name)}" title="${protectedAccount ? "Protected account" : user.locked ? "Unlock" : "Lock"}" ${protectedAccount ? "disabled" : ""}>${user.locked ? icon("play") : icon("pause")}</button><button class="row-action danger" data-user-action="delete-user" data-user-name="${escapeHtml(user.name)}" title="${protectedAccount ? "Protected account" : "Delete"}" ${protectedAccount ? "disabled" : ""}>${icon("trash")}</button></div></td></tr>`;
  }).join("");
  const groupRows = groups.map((group) => `<tr><td><strong>${escapeHtml(group.name)}</strong></td><td class="mono">${group.gid}</td><td class="muted-text">${escapeHtml(group.members.join(", ") || "—")}</td><td><button class="row-action danger" data-group-delete="${escapeHtml(group.name)}" title="Delete group">${icon("trash")}</button></td></tr>`).join("");
  const table = accountTab === "users"
    ? `<thead><tr><th>User</th><th>UID / GID</th><th>Home</th><th>Shell</th><th>Groups</th><th></th></tr></thead><tbody>${userRows}</tbody>`
    : `<thead><tr><th>Group</th><th>GID</th><th>Members</th><th></th></tr></thead><tbody>${groupRows}</tbody>`;
  return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">Linux identities</div><h2>${users.length} users · ${groups.length} groups</h2><p>Protected changes use the connection's configured sudo path.</p></div><button class="button button-primary" data-action="${accountTab === "users" ? "new-user" : "new-group"}">${icon("plus")} New ${accountTab === "users" ? "user" : "group"}</button></div><div class="subnav-tabs management-tabs"><button class="subnav-tab ${accountTab === "users" ? "active" : ""}" data-account-tab="users">Users <span>${users.length}</span></button><button class="subnav-tab ${accountTab === "groups" ? "active" : ""}" data-account-tab="groups">Groups <span>${groups.length}</span></button></div><div class="table-scroll"><table>${table}</table></div></section>`;
}

function renderAdministration(): string {
  const tabs = [["firewall", "Firewall"], ["keys", "SSH keys"], ["security", "Security"], ["actions", "Maintenance"]] as const;
  return `<section class="administration-workspace"><div class="subnav-tabs workspace-tabs">${tabs.map(([tab, label]) => `<button class="subnav-tab ${administrationTab === tab ? "active" : ""}" data-administration-tab="${tab}">${label}</button>`).join("")}</div>${renderServerTool()}</section>`;
}

function renderServerTool(tab: ServerToolTab = administrationTab): string {
  if (tab === "firewall") return `<section class="panel"><div class="panel-head"><div><div class="panel-kicker">${escapeHtml(firewallSnapshot?.provider ?? "Firewall")}</div><h2>${firewallSnapshot?.provider ? (firewallSnapshot.enabled ? "Firewall enabled" : "Firewall disabled") : "No supported firewall detected"}</h2><p>UFW and firewalld rules. Confirm SSH access before changing port 22.</p></div>${firewallSnapshot?.provider ? `<button class="button ${firewallSnapshot.enabled ? "button-danger" : "button-primary"}" data-firewall-action="${firewallSnapshot.enabled ? "disable" : "enable"}">${firewallSnapshot.enabled ? "Disable" : "Enable"}</button>` : ""}</div><div class="lockout-warning">${icon("shield")} Firewall changes can lock you out. Keep the current SSH port allowed and an existing session open while testing.</div><form class="inline-tier3-form" data-form="firewall"><input name="port" type="number" min="1" max="65535" required placeholder="Port"/><select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select><input name="source" placeholder="Source IP/CIDR (optional)"/><button class="button button-primary" name="effect" value="allow">Allow</button><button class="button button-danger" name="effect" value="deny">Deny</button></form><pre class="tier3-output">${escapeHtml(firewallSnapshot?.rules.join("\n") || "No rules returned.")}</pre></section>`;
  if (tab === "keys") return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">~/.ssh/authorized_keys</div><h2>${authorizedKeys.length} authorized keys</h2><p>Fingerprints are calculated remotely with ssh-keygen.</p></div><button class="button button-primary" data-action="add-authorized-key">${icon("plus")} Add public key</button></div><div class="table-scroll"><table><thead><tr><th>Type</th><th>Fingerprint</th><th>Comment</th><th></th></tr></thead><tbody>${authorizedKeys.length ? authorizedKeys.map((key) => `<tr><td><span class="tag-chip">${escapeHtml(key.kind)}</span></td><td class="mono">${escapeHtml(key.fingerprint)}</td><td>${escapeHtml(key.comment || "—")}</td><td><button class="row-action danger" data-key-remove="${escapeHtml(key.id)}" title="Remove key">${icon("trash")}</button></td></tr>`).join("") : `<tr><td colspan="4"><div class="empty-table">No authorized keys found.</div></td></tr>`}</tbody></table></div></section>`;
  if (tab === "security") return `<div class="security-grid">${securitySnapshot ? `<div class="stat-card"><div class="stat-card-head"><span>Available updates</span></div><div class="stat-value">${securitySnapshot.packageUpdatesAvailable ? securitySnapshot.updates : "—"}</div><div class="stat-meta">${securitySnapshot.packageUpdatesAvailable ? `${securitySnapshot.securityUpdates} security updates` : "Unsupported package manager"}</div></div><div class="stat-card"><div class="stat-card-head"><span>Reboot required</span></div><div class="stat-value tier3-word">${securitySnapshot.rebootRequired ? "Yes" : "No"}</div><div class="stat-meta">Kernel ${escapeHtml(securitySnapshot.kernelVersion)}</div></div><section class="panel tier3-wide"><div class="panel-head compact"><div><div class="panel-kicker">Software status</div><h2>Update posture</h2></div></div><div class="machine-details update-posture-details"><div><span>Last package index update</span><strong>${escapeHtml(securitySnapshot.packageUpdatesAvailable ? (securitySnapshot.lastPackageUpdate ?? "Unknown") : "Unavailable")}</strong></div><div><span>Container runtime</span><strong>${escapeHtml(securitySnapshot.containerVersion ?? "Not detected")}${securitySnapshot.containerUpdateAvailable ? " · update available" : ""}</strong></div></div></section>` : renderViewLoading()}</div>`;
  if (tab === "actions") return `<section class="panel"><div class="panel-head"><div><div class="panel-kicker">One-click actions</div><h2>Common server maintenance</h2><p>Destructive and connectivity-sensitive actions always ask for confirmation.</p></div></div><div class="action-grid">${[["update-index", "Update package indexes", "refresh"], ["restart-docker", "Restart Docker", "docker"], ["restart-ssh", "Restart SSH", "key"], ["install-tools", "Install common tooling", "packages"], ["clear-cache", "Clear page cache", "memory"], ["reboot", "Schedule reboot", "restart"], ["shutdown", "Schedule shutdown", "stop"]].map(([action, label, iconName]) => `<button class="action-card ${["reboot", "shutdown", "restart-ssh"].includes(action) ? "sensitive" : ""}" data-quick-action="${action}"><span>${icon(iconName)}</span><strong>${label}</strong></button>`).join("")}</div>${renderCommandResults()}</section>`;
  if (tab === "commands") return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">Favorites & saved commands</div><h2>${savedCommands.length} reusable actions</h2><p>Global commands are available on every server; server commands stay with this profile.</p></div><button class="button button-primary" data-action="new-command">${icon("plus")} Save command</button></div><div class="command-list">${savedCommands.length ? savedCommands.map((item) => `<article class="command-row"><div><strong>${escapeHtml(item.name)}</strong><code>${escapeHtml(item.command)}</code><small>${item.serverId ? "This server" : "All servers"}</small></div><div class="row-actions"><button class="row-action" data-command-run="${escapeHtml(item.id)}" title="Run">${icon("play")}</button><button class="row-action" data-command-edit="${escapeHtml(item.id)}" title="Edit">${icon("edit")}</button><button class="row-action danger" data-command-delete="${escapeHtml(item.id)}" title="Delete">${icon("trash")}</button></div></article>`).join("") : `<div class="empty-table">No saved commands yet.</div>`}</div>${renderCommandResults()}</section>`;
  return `<section class="panel table-panel"><div class="panel-head"><div><div class="panel-kicker">SSH tunnels</div><h2>${tunnels.length} saved tunnels</h2><p>Local forwarding, remote forwarding, and SOCKS5 proxies run inside Serverbox.</p></div><button class="button button-primary" data-action="new-tunnel">${icon("plus")} Add tunnel</button></div><div class="table-scroll"><table><thead><tr><th>Name</th><th>Type</th><th>Bind</th><th>Target</th><th>Status</th><th></th></tr></thead><tbody>${tunnels.length ? tunnels.map((tunnel) => { const status = tunnelStatuses.find((item) => item.id === tunnel.id); return `<tr><td><strong>${escapeHtml(tunnel.name)}</strong></td><td><span class="tag-chip">${escapeHtml(tunnel.kind)}</span></td><td class="mono">${escapeHtml(tunnel.bindHost)}:${tunnel.bindPort}</td><td class="mono">${tunnel.kind === "socks" ? "Dynamic SOCKS5" : `${escapeHtml(tunnel.targetHost)}:${tunnel.targetPort}`}</td><td><span class="state-label ${status?.running ? "good" : status?.error ? "bad" : "muted"}">${status?.running ? "Running" : status?.error ? "Failed" : "Stopped"}</span>${status?.error ? `<small class="row-subtitle">${escapeHtml(status.error)}</small>` : ""}</td><td><div class="row-actions"><button class="row-action" data-tunnel-toggle="${escapeHtml(tunnel.id)}" data-tunnel-running="${status?.running ? "true" : "false"}" title="${status?.running ? "Stop" : "Start"}">${icon(status?.running ? "stop" : "play")}</button><button class="row-action" data-tunnel-edit="${escapeHtml(tunnel.id)}">${icon("edit")}</button><button class="row-action danger" data-tunnel-delete="${escapeHtml(tunnel.id)}">${icon("trash")}</button></div></td></tr>`; }).join("") : `<tr><td colspan="6"><div class="empty-table">No tunnels saved.</div></td></tr>`}</tbody></table></div></section>`;
}

function renderCommands(): string {
  return renderServerTool("commands");
}

function renderTunnels(): string {
  return renderServerTool("tunnels");
}

function renderCommandResults(): string {
  if (!commandResults.length) return "";
  return `<div class="command-results" data-command-results><div class="panel-kicker">Latest output</div>${commandResults.map((result) => `<details open><summary><strong>${escapeHtml(result.serverName)}</strong><span class="state-label ${result.exitCode === 0 ? "good" : "bad"}">${result.error ? "failed" : `exit ${result.exitCode}`}</span></summary><pre>${escapeHtml(result.error || [result.stdout, result.stderr].filter(Boolean).join("\n") || "Command completed without output.")}</pre></details>`).join("")}</div>`;
}

function renderUnsupported(title: string, copy: string): string {
  return renderUnsupportedView(title, copy);
}

function renderTransferToast(): string {
  if (!transfer) return "";
  const percent = transfer.totalBytes ? transfer.completedBytes / transfer.totalBytes * 100 : 0;
  return `<div class="transfer-toast" data-transfer-direction="${transfer.direction}"><span class="transfer-icon" data-transfer-icon>${icon(transfer.direction === "upload" ? "upload" : "download")}</span><div><strong data-transfer-label>${transfer.direction === "upload" ? "Uploading" : "Downloading"}</strong><span data-transfer-path>${escapeHtml(transfer.path)}</span></div><div class="transfer-progress"><div>${meter(percent, "coral")}</div><small data-transfer-bytes>${formatBytes(transfer.completedBytes)} / ${formatBytes(transfer.totalBytes)}</small></div><button class="transfer-cancel" type="button" data-action="cancel-transfer">Cancel</button></div>`;
}

function syncTransferToast(): void {
  const toast = root.querySelector<HTMLElement>(".transfer-toast");
  const markup = transfer && !transfer.done ? renderTransferToast() : "";
  if (toast) {
    if (!transfer || transfer.done) {
      toast.remove();
      return;
    }
    if (toast.dataset.transferDirection !== transfer.direction) {
      toast.dataset.transferDirection = transfer.direction;
      const iconContainer = toast.querySelector<HTMLElement>("[data-transfer-icon]");
      if (iconContainer) iconContainer.innerHTML = icon(transfer.direction === "upload" ? "upload" : "download");
    }
    const percent = transfer.totalBytes ? transfer.completedBytes / transfer.totalBytes * 100 : 0;
    const label = toast.querySelector<HTMLElement>("[data-transfer-label]");
    const path = toast.querySelector<HTMLElement>("[data-transfer-path]");
    const meterFill = toast.querySelector<HTMLElement>(".meter-fill");
    const bytes = toast.querySelector<HTMLElement>("[data-transfer-bytes]");
    if (label) label.textContent = transfer.direction === "upload" ? "Uploading" : "Downloading";
    if (path) path.textContent = transfer.path;
    if (meterFill) meterFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    if (bytes) bytes.textContent = `${formatBytes(transfer.completedBytes)} / ${formatBytes(transfer.totalBytes)}`;
    return;
  }
  if (!markup) return;
  const appNotification = root.querySelector<HTMLElement>(".app-toast");
  if (appNotification) appNotification.insertAdjacentHTML("beforebegin", markup);
  else root.insertAdjacentHTML("beforeend", markup);
}

function dismissTransferToast(transferId: string): void {
  if (transferDismissTimer !== undefined) window.clearTimeout(transferDismissTimer);
  transferDismissTimer = window.setTimeout(() => {
    if (transfer?.transferId !== transferId || !transfer.done) return;
    transfer = null;
    syncTransferToast();
  }, 1600);
}

function renderAppToast(): string {
  if (!appToast) return "";
  return `<div class="app-toast ${appToast.kind}" role="status" aria-live="polite"><span>${icon(appToast.kind === "success" ? "check" : "info")}</span><strong>${escapeHtml(appToast.message)}</strong><button data-action="dismiss-toast" aria-label="Dismiss notification">${icon("close")}</button></div>`;
}

function showToast(message: string, kind: "success" | "info" = "success"): void {
  appToast = { message, kind };
  if (appToastTimer !== undefined) window.clearTimeout(appToastTimer);
  root.querySelector<HTMLElement>(".app-toast")?.remove();
  root.insertAdjacentHTML("beforeend", renderAppToast());
  appToastTimer = window.setTimeout(() => dismissToast(), 2600);
}

function syncInterfaceScaleControls(): void {
  const currentIndex = INTERFACE_SCALE_LEVELS.indexOf(interfaceScale as typeof INTERFACE_SCALE_LEVELS[number]);
  const value = root.querySelector<HTMLElement>("[data-interface-scale-value]");
  const decrease = root.querySelector<HTMLButtonElement>("[data-action='interface-scale-decrease']");
  const increase = root.querySelector<HTMLButtonElement>("[data-action='interface-scale-increase']");
  const reset = root.querySelector<HTMLButtonElement>("[data-action='interface-scale-reset']");
  if (value) value.textContent = `${Math.round(interfaceScale * 100)}%`;
  if (decrease) decrease.disabled = currentIndex <= 0;
  if (increase) increase.disabled = currentIndex >= INTERFACE_SCALE_LEVELS.length - 1;
  if (reset) reset.disabled = interfaceScale === DEFAULT_INTERFACE_SCALE;
}

async function setInterfaceScale(scale: number, announce = true): Promise<void> {
  if (!INTERFACE_SCALE_LEVELS.includes(scale as typeof INTERFACE_SCALE_LEVELS[number])) return;
  try {
    await appWebview.setZoom(scale);
    interfaceScale = scale;
    localStorage.setItem("serverbox-interface-scale", String(scale));
    syncInterfaceScaleControls();
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => fitAddon?.fit()));
    if (announce) showToast(`Interface scale set to ${Math.round(scale * 100)}%.`, "info");
  } catch (error) {
    if (announce) showToast(`Could not change interface scale: ${errorText(error)}`, "info");
  }
}

async function stepInterfaceScale(direction: -1 | 1): Promise<void> {
  const currentIndex = INTERFACE_SCALE_LEVELS.indexOf(interfaceScale as typeof INTERFACE_SCALE_LEVELS[number]);
  const nextIndex = Math.max(0, Math.min(INTERFACE_SCALE_LEVELS.length - 1, currentIndex + direction));
  if (nextIndex === currentIndex) return;
  await setInterfaceScale(INTERFACE_SCALE_LEVELS[nextIndex]);
}

function dismissToast(): void {
  if (appToastTimer !== undefined) window.clearTimeout(appToastTimer);
  appToastTimer = undefined;
  appToast = null;
  root.querySelector<HTMLElement>(".app-toast")?.remove();
}

function renderAppDialog(): string {
  const prompt = appDialogPrompt;
  if (!prompt) return "";
  const iconName = prompt.kind === "warning" ? "shield" : "info";
  return `<div class="backdrop app-dialog-backdrop" data-app-dialog><div class="modal modal-small app-dialog" role="alertdialog" aria-modal="true"><div class="modal-head"><div><div class="eyebrow">Serverbox</div><h2>${escapeHtml(prompt.title)}</h2></div><button class="close-button" data-action="cancel-app-dialog" aria-label="Close dialog">${icon("close")}</button></div><div class="modal-body form-stack"><div class="app-dialog-message ${prompt.kind}">${icon(iconName)}<p>${escapeHtml(prompt.message)}</p></div><div class="modal-actions"><span></span><div class="modal-actions-right">${prompt.cancelLabel ? `<button class="button button-quiet" data-action="cancel-app-dialog">${escapeHtml(prompt.cancelLabel)}</button>` : ""}<button class="button ${prompt.kind === "warning" ? "button-danger" : "button-primary"}" data-action="accept-app-dialog">${escapeHtml(prompt.confirmLabel)}</button></div></div></div></div></div>`;
}

function confirm(messageText: string, options: { title?: string; kind?: string } = {}): Promise<boolean> {
  if (finishAppDialogWaiter) return Promise.resolve(false);
  appDialogPrompt = { title: options.title ?? "Confirm action", message: messageText, kind: options.kind === "warning" ? "warning" : "info", confirmLabel: "Continue", cancelLabel: "Cancel" };
  const waiter = new Promise<boolean>((resolve) => { finishAppDialogWaiter = resolve; });
  root.insertAdjacentHTML("beforeend", renderAppDialog());
  window.setTimeout(() => root.querySelector<HTMLButtonElement>('[data-action="accept-app-dialog"]')?.focus(), 0);
  return waiter;
}

async function message(messageText: string, options: { title?: string } = {}): Promise<void> {
  if (finishAppDialogWaiter) return;
  appDialogPrompt = { title: options.title ?? "Serverbox", message: messageText, kind: "info", confirmLabel: "Close" };
  const waiter = new Promise<boolean>((resolve) => { finishAppDialogWaiter = resolve; });
  root.insertAdjacentHTML("beforeend", renderAppDialog());
  window.setTimeout(() => root.querySelector<HTMLButtonElement>('[data-action="accept-app-dialog"]')?.focus(), 0);
  await waiter;
}

function finishAppDialog(value: boolean): void {
  const finish = finishAppDialogWaiter;
  finishAppDialogWaiter = null;
  appDialogPrompt = null;
  root.querySelector<HTMLElement>("[data-app-dialog]")?.remove();
  finish?.(value);
}

function renderModal(): string {
  if (modal === "server") return renderServerModal();
  if (modal === "workspace-tab-rename") return renderWorkspaceTabRenameModal();
  if (modal === "service") return renderServiceModal();
  if (modal === "editor") return renderEditorModal();
  if (modal === "folder") return renderFolderModal();
  if (modal === "docker") return renderDockerModal();
  if (modal === "input-prompt") return renderTextInputModal();
  if (modal === "compose-scale") return renderComposeScaleModal();
  if (modal === "security") return renderSecurityModal();
  if (modal === "master-password") return renderMasterPasswordModal();
  if (modal === "host-key") return renderHostKeyModal();
  if (modal === "change-password") return renderChangePasswordModal();
  if (modal === "reset-credentials") return renderResetCredentialsModal();
  if (modal === "cron") return renderCronModal();
  if (modal === "user") return renderUserModal();
  if (modal === "user-password") return renderUserPasswordModal();
  if (modal === "package-details") return renderPackageDetailsModal();
  if (modal === "command") return renderCommandModal();
  if (modal === "tunnel") return renderTunnelModal();
  return renderInspectModal();
}

function renderModalShell(title: string, subtitle: string, body: string, size = ""): string {
  return `<div class="backdrop" data-backdrop><div class="modal ${size}" role="dialog" aria-modal="true"><div class="modal-head"><div><div class="eyebrow">Serverbox</div><h2>${title}</h2><p>${subtitle}</p></div><button class="close-button" data-action="close-modal">${icon("close")}</button></div>${body}</div></div>`;
}

function renderTextInputModal(): string {
  const prompt = textInputPrompt;
  if (!prompt) return "";
  const required = prompt.allowEmpty ? "" : "required";
  const control = prompt.choices
    ? `<select name="value" ${required} autofocus>${prompt.allowEmpty ? `<option value="">All services</option>` : ""}${prompt.choices.map((choice) => `<option value="${escapeHtml(choice)}" ${choice === prompt.defaultValue ? "selected" : ""}>${escapeHtml(choice)}</option>`).join("")}</select>`
    : prompt.multiline
      ? `<textarea name="value" rows="5" ${required} autofocus placeholder="${escapeHtml(prompt.placeholder ?? "")}">${escapeHtml(prompt.defaultValue)}</textarea>`
      : `<input name="value" ${required} autofocus value="${escapeHtml(prompt.defaultValue)}" placeholder="${escapeHtml(prompt.placeholder ?? "")}"/>`;
  return renderModalShell(escapeHtml(prompt.title), "Enter the value below to continue.", `<form class="modal-body form-stack" data-form="input-prompt"><label class="field"><span>${escapeHtml(prompt.label)}</span>${control}</label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Continue</button></div></form>`, "modal-small");
}

function requestTextInput(prompt: NonNullable<typeof textInputPrompt>): Promise<string | null> {
  if (finishTextInputWaiter) return Promise.resolve(null);
  textInputPrompt = prompt;
  modal = "input-prompt";
  const waiter = new Promise<string | null>((resolve) => { finishTextInputWaiter = resolve; });
  render();
  return waiter;
}

function finishTextInput(value: string | null): void {
  const finish = finishTextInputWaiter;
  finishTextInputWaiter = null;
  textInputPrompt = null;
  modal = null;
  render();
  finish?.(value);
}

function renderWorkspaceTabRenameModal(): string {
  const tab = openServerTabs.find((item) => item.id === renamingWorkspaceTabId);
  const server = tab && snapshot.servers.find((item) => item.id === tab.serverId);
  if (!tab || !server) return "";
  return renderModalShell("Rename tab", "Give this workspace tab a short label. Leave it blank to use the server name.", `<form class="modal-body form-stack" data-form="workspace-tab-rename"><label class="field"><span>Tab name</span><input name="label" value="${escapeHtml(tab.label ?? server.name)}" maxlength="80" autofocus/></label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Save name</button></div></form>`, "modal-small");
}

function renderHostKeyModal(): string {
  const prompt = hostKeyPrompt;
  if (!prompt) return "";
  if (prompt.unknown) {
    const unknown = prompt.unknown;
    return renderModalShell(
      "First connection to this server",
      `${escapeHtml(unknown.host)}:${unknown.port} is not yet saved in <code>~/.ssh/known_hosts</code>.`,
      `<div class="modal-body form-stack"><div class="credential-warning">${icon("shield")}<div><strong>Review the server's fingerprint before trusting it.</strong><p>Serverbox never trusts a first-contact host key silently. Verify this fingerprint through a trusted channel before it is added to your known hosts.</p></div></div>${prompt.error ? `<div class="inline-error">${icon("info")}<span>${escapeHtml(prompt.error)}</span></div>` : ""}<div class="host-key-comparison"><div><span>Key type</span><code>${escapeHtml(unknown.keyType)}</code></div><div><span>Fingerprint</span><code>${escapeHtml(unknown.fingerprint)}</code></div></div><p class="security-footnote">Trusting adds this key to <code>~/.ssh/known_hosts</code>; future changes will be flagged.</p><div class="modal-actions"><button type="button" class="button button-quiet" data-action="reject-host-key">Cancel</button><button type="button" class="button button-danger" data-action="trust-host-key">Trust key &amp; connect</button></div></div>`,
      "modal-security",
    );
  }
  const mismatch = prompt.mismatch;
  if (!mismatch) return "";
  const oldKeys = mismatch.oldFingerprints.length
    ? mismatch.oldFingerprints.map((fingerprint) => `<code>${escapeHtml(fingerprint)}</code>`).join("")
    : `<code>Unavailable</code>`;
  return renderModalShell(
    "SSH host identity changed",
    `${escapeHtml(mismatch.host)}:${mismatch.port} presented a different ${escapeHtml(mismatch.keyType)} host key.`,
    `<div class="modal-body form-stack"><div class="credential-warning">${icon("shield")}<div><strong>Verify this change before continuing.</strong><p>A changed host key can be expected after a server rebuild, but it can also indicate that another machine is intercepting the connection.</p></div></div>${prompt.error ? `<div class="inline-error">${icon("info")}<span>${escapeHtml(prompt.error)}</span></div>` : ""}<div class="host-key-comparison"><div><span>Previously trusted</span>${oldKeys}</div><div><span>Presented now</span><code>${escapeHtml(mismatch.newFingerprint)}</code></div></div><p class="security-footnote">Confirm the new fingerprint through a trusted channel before replacing the saved entry in <code>~/.ssh/known_hosts</code>.</p><div class="modal-actions"><button type="button" class="button button-quiet" data-action="reject-host-key">Cancel</button><button type="button" class="button button-danger" data-action="trust-host-key">Trust new key & connect</button></div></div>`,
    "modal-security",
  );
}

function renderCronModal(): string {
  const job = editingCron;
  return renderModalShell(job ? "Edit cron job" : "Add cron job", "Use a five-field cron expression. Jobs run as the connected SSH user.", `<form class="modal-body form-stack" data-form="cron"><label class="field"><span>Common schedule</span><select data-field="cron-preset"><option value="">Custom expression</option><option value="*/5 * * * *">Every 5 minutes</option><option value="0 * * * *">Every hour</option><option value="0 0 * * *">Daily at midnight</option><option value="0 0 * * 0">Weekly on Sunday</option><option value="0 0 1 * *">Monthly</option></select></label><label class="field"><span>Cron expression</span><input name="schedule" value="${escapeHtml(job?.schedule ?? "0 * * * *")}" required placeholder="0 * * * *"/><small class="field-hint">minute · hour · day of month · month · day of week</small></label><label class="field"><span>Command</span><textarea name="command" required rows="4" placeholder="/usr/local/bin/backup">${escapeHtml(job?.command ?? "")}</textarea></label><label class="favorite-check"><input type="checkbox" name="enabled" ${job?.enabled === false ? "" : "checked"}/><span></span>Enabled</label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Save cron job</button></div></form>`, "modal-small");
}

function renderUserModal(): string {
  return renderModalShell("Create Linux user", "The password is sent through the protected SSH channel and is never saved by Serverbox.", `<form class="modal-body form-stack" data-form="user"><div class="credential-warning">${icon("info")}<div><strong>Password changes are immediate.</strong><p>Share credentials through a secure channel and require the user to rotate them after first login.</p></div></div><label class="field"><span>Username</span><input name="name" required pattern="[A-Za-z0-9_.+-]+"/></label><div class="form-grid"><label class="field"><span>Home directory</span><input name="home" placeholder="created automatically"/></label><label class="field"><span>Login shell <small>optional</small></span><input name="shell" placeholder="use the server default"/></label></div><label class="field"><span>Supplementary groups <small>comma separated</small></span><input name="groups" placeholder="sudo,docker"/></label><label class="field"><span>Initial password <small>optional</small></span><input name="password" type="password" autocomplete="new-password"/></label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Create user</button></div></form>`, "modal-security");
}

function renderUserPasswordModal(): string {
  return renderModalShell("Reset Linux password", `Set a new password for ${escapeHtml(passwordUser)}.`, `<form class="modal-body form-stack" data-form="user-password"><div class="credential-warning">${icon("info")}<div><strong>This takes effect immediately and cannot be undone.</strong><p>The password is sent through SSH stdin, is never saved locally, and should be shared securely.</p></div></div><label class="field"><span>New password</span><input name="password" type="password" required autocomplete="new-password"/></label><label class="field"><span>Confirm password</span><input name="confirmation" type="password" required autocomplete="new-password"/></label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-danger">Reset password</button></div></form>`, "modal-security");
}

function renderPackageDetailsModal(): string {
  return renderModalShell("Package details", "APT metadata reported by the remote server.", `<div class="modal-body"><pre class="inspect-output package-details-output">${escapeHtml(packageDetailsText || "Loading…")}</pre><div class="modal-actions"><button class="button button-quiet" data-action="close-modal">Close</button><button class="button button-primary" data-action="copy-package-details">${icon("copy")} Copy</button></div></div>`, "modal-inspect");
}

function renderCommandModal(): string {
  return renderModalShell(editingCommand ? "Edit saved command" : "Save a command", "Named commands can belong to this server or be available everywhere.", `<form class="modal-body form-stack" data-form="command"><label class="field"><span>Name</span><input name="name" required value="${escapeHtml(editingCommand?.name ?? "")}" placeholder="Tail API logs"/></label><label class="field"><span>Command</span><textarea name="command" required rows="6" spellcheck="false" placeholder="journalctl -u api.service -f">${escapeHtml(editingCommand?.command ?? "")}</textarea></label><label class="favorite-check"><input type="checkbox" name="global" ${editingCommand && !editingCommand.serverId ? "checked" : ""}/><span></span>Available on every server</label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button class="button button-primary">Save command</button></div></form>`, "modal-small");
}

function renderTunnelModal(): string {
  const tunnel = editingTunnel;
  return renderModalShell(tunnel ? "Edit SSH tunnel" : "Add SSH tunnel", "Tunnels remain active while Serverbox is running or until you stop them.", `<form class="modal-body form-stack" data-form="tunnel"><label class="field"><span>Name</span><input name="name" required value="${escapeHtml(tunnel?.name ?? "")}" placeholder="Production database"/></label><label class="field"><span>Type</span><select name="kind"><option value="local" ${tunnel?.kind === "local" ? "selected" : ""}>Local forwarding</option><option value="remote" ${tunnel?.kind === "remote" ? "selected" : ""}>Remote forwarding</option><option value="socks" ${tunnel?.kind === "socks" ? "selected" : ""}>SOCKS5 proxy</option></select></label><div class="form-grid"><label class="field"><span>Bind host</span><input name="bindHost" required value="${escapeHtml(tunnel?.bindHost ?? "127.0.0.1")}"/></label><label class="field"><span>Bind port</span><input name="bindPort" type="number" min="1" max="65535" required value="${tunnel?.bindPort ?? 5433}"/></label><label class="field"><span>Target host</span><input name="targetHost" value="${escapeHtml(tunnel?.targetHost ?? "127.0.0.1")}" placeholder="Ignored for SOCKS"/></label><label class="field"><span>Target port</span><input name="targetPort" type="number" min="1" max="65535" value="${tunnel?.targetPort ?? 5432}"/></label></div><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button class="button button-primary">Save tunnel</button></div></form>`, "modal-small");
}

function renderServerModal(): string {
  const server = editingServer;
  const isEdit = Boolean(server);
  const bastions = snapshot.servers.filter((candidate) => candidate.id !== server?.id && !profileRouteContains(candidate, server?.id));
  const route = `<div class="form-divider"><span>Connection route</span></div><label class="field"><span>Bastion host <small>optional</small></span><select name="jumpHostId"><option value="">Direct connection</option>${bastions.map((candidate) => `<option value="${escapeHtml(candidate.id)}" ${server?.jumpHostId === candidate.id ? "selected" : ""}>${escapeHtml(profileRouteLabel(candidate))}</option>`).join("")}</select><small class="field-hint">Serverbox connects to this profile through the selected bastion. Bastions may use another bastion, creating a secure jump chain.</small></label>`;
  return renderModalShell(isEdit ? "Edit connection" : "Connect a server", isEdit ? "Update the profile without losing its saved secrets." : "Credentials are encrypted locally with your master password.", `<form class="modal-body form-stack" data-form="server"><div class="form-grid"><label class="field"><span>Display name</span><input name="name" required value="${escapeHtml(server?.name ?? "")}" placeholder="Production API"/></label><label class="field"><span>Group</span><input name="groupName" value="${escapeHtml(server?.groupName ?? "")}" placeholder="Production"/></label><label class="field field-wide"><span>Host or IP</span><input name="host" required value="${escapeHtml(server?.host ?? "")}" placeholder="203.0.113.10"/></label><label class="field"><span>Port</span><input name="port" type="number" min="1" max="65535" value="${server?.port ?? 22}"/></label><label class="field"><span>Username</span><input name="username" required value="${escapeHtml(server?.username ?? "root")}" placeholder="ubuntu"/></label></div>${snapshot.sshConfigEntries.length ? `<label class="field"><span>Import from ~/.ssh/config</span><select data-field="ssh-config"><option value="">Choose a saved host alias…</option>${snapshot.sshConfigEntries.map((entry) => `<option value="${escapeHtml(entry.alias)}">${escapeHtml(entry.alias)}${entry.host ? ` · ${escapeHtml(entry.host)}` : ""}</option>`).join("")}</select></label>` : ""}${route}<div class="form-divider"><span>Authentication</span></div><div class="auth-switch"><label class="auth-option"><input type="radio" name="authMethod" value="password" ${!server || server.authMethod === "password" ? "checked" : ""}/><span>${icon("shield")}<strong>Password</strong><small>Encrypted in the local vault</small></span></label><label class="auth-option"><input type="radio" name="authMethod" value="privateKey" ${server?.authMethod === "privateKey" ? "checked" : ""}/><span>${icon("key")}<strong>Private key</strong><small>Use a key from ~/.ssh</small></span></label></div><div class="auth-fields" data-auth-fields>${renderAuthFields(server)}</div><div class="form-divider"><span>Organization & context</span></div><label class="field"><span>Tags <small>comma separated</small></span><input name="tags" value="${escapeHtml(server?.tags.join(", ") ?? "")}" placeholder="production, api, eu-west"/></label><label class="field"><span>Notes <small>stored locally and included in search</small></span><textarea name="notes" rows="5" placeholder="Purpose, provider, URLs, emergency steps…">${escapeHtml(server?.notes ?? "")}</textarea></label><label class="favorite-check"><input type="checkbox" name="favorite" ${server?.favorite ? "checked" : ""}/><span></span>Keep this server near the top</label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><div class="modal-actions-right"><button type="button" class="button button-quiet" data-action="save-and-test">${icon("refresh")} Save & test</button><button type="submit" class="button button-primary">${isEdit ? "Save changes" : "Save connection"}</button></div></div></form>`, "modal-server");
}

function profileRouteContains(profile: ServerProfile, serverId?: string): boolean {
  if (!serverId) return false;
  const seen = new Set<string>();
  let current: ServerProfile | undefined = profile;
  while (current && !seen.has(current.id)) {
    if (current.id === serverId) return true;
    seen.add(current.id);
    current = snapshot.servers.find((candidate) => candidate.id === current?.jumpHostId);
  }
  return false;
}

function profileRouteLabel(profile: ServerProfile): string {
  const names: string[] = [];
  const seen = new Set<string>();
  let current: ServerProfile | undefined = profile;
  while (current && !seen.has(current.id)) {
    names.push(current.name);
    seen.add(current.id);
    current = snapshot.servers.find((candidate) => candidate.id === current?.jumpHostId);
  }
  return names.reverse().join(" → ");
}

function renderAuthFields(server: ServerProfile | null, auth = server?.authMethod ?? "password"): string {
  if (auth === "privateKey") return `<label class="field"><span>Private key</span><select name="keyPath"><option value="">Choose a key…</option>${snapshot.sshKeys.map((key) => `<option value="${escapeHtml(key.path)}" ${server?.keyPath === key.path ? "selected" : ""}>${escapeHtml(key.name)} · ${escapeHtml(key.kind)}</option>`).join("")}</select>${snapshot.sshKeys.length ? "" : `<small class="field-hint">No keys detected in ~/.ssh. You can still paste a path below.</small>`}<input name="customKeyPath" value="${escapeHtml(server?.keyPath && !snapshot.sshKeys.some((key) => key.path === server.keyPath) ? server.keyPath : "")}" placeholder="/Users/you/.ssh/id_ed25519"/></label><label class="field"><span>Key passphrase <small>optional · leave blank to keep</small></span><input name="keyPassphrase" type="password" autocomplete="new-password" placeholder="Only if the key is encrypted"/></label><label class="field"><span>Sudo password <small>optional · for protected actions</small></span><input name="sudoPassword" type="password" autocomplete="new-password" placeholder="Leave blank if sudo is passwordless"/></label>`;
  return `<label class="field"><span>Password <small>${server ? "leave blank to keep" : ""}</small></span><input name="password" type="password" autocomplete="current-password" placeholder="SSH password"/></label><label class="field"><span>Sudo password <small>optional · leave blank to use passwordless sudo</small></span><input name="sudoPassword" type="password" autocomplete="new-password" placeholder="Only needed for protected actions"/></label>`;
}

function renderServiceModal(): string {
  if (!serviceDetails) return renderModalShell("Service details", "Loading the unit profile…", `<div class="modal-body"><div class="view-loading"><div class="spinner"></div></div></div>`, "modal-service");
  return renderModalShell(escapeHtml(serviceDetails.name), "Unit properties and its latest journal entries.", `<div class="modal-body service-details"><div class="service-properties">${serviceDetails.properties.map(([key, value]) => `<div><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}</div>${serviceDetails.unitFile ? `<div class="unit-file"><span>Unit file</span><code>${escapeHtml(serviceDetails.unitFile)}</code></div>` : ""}<div class="detail-log-label">Recent journal</div><pre class="log-output detail-log">${escapeHtml(serviceDetails.journal || "No recent journal entries.")}</pre><div class="modal-actions"><button class="button button-quiet" data-action="close-modal">Close</button><div class="modal-actions-right"><button class="button button-quiet" data-service-action="enable" data-service="${escapeHtml(serviceDetails.name)}">Enable</button><button class="button button-primary" data-service-action="restart" data-service="${escapeHtml(serviceDetails.name)}">${icon("restart")} Restart</button></div></div></div>`, "modal-service");
}

function renderEditorModal(): string {
  return renderModalShell("Edit remote file", escapeHtml(editorPath), `<form class="modal-body editor-modal-body" data-form="editor"><textarea name="content" data-field="editor-content" spellcheck="false">${escapeHtml(editorContent)}</textarea><div class="editor-footer"><span class="editor-status">${editorDirty ? "Unsaved changes" : "Saved"} · ${formatBytes(new Blob([editorContent]).size)}</span><div class="modal-actions-right"><button type="button" class="button button-quiet" data-action="close-editor">Cancel</button><button type="submit" class="button button-primary" ${editorDirty ? "" : "disabled"}>${icon("check")} Save remotely</button></div></div></form>`, "modal-editor");
}

function renderFolderModal(): string {
  return renderModalShell("Create folder", `A new folder inside ${escapeHtml(remotePath)}`, `<form class="modal-body form-stack" data-form="folder"><label class="field"><span>Folder name</span><input name="name" required autofocus placeholder="logs"/></label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Create folder</button></div></form>`, "modal-small");
}

function renderDockerModal(): string {
  return renderModalShell("Create container", "A compact form for the common Docker run options.", `<form class="modal-body form-stack" data-form="docker"><div class="form-grid"><label class="field field-wide"><span>Image</span><input name="image" required placeholder="nginx:latest"/></label><label class="field"><span>Name</span><input name="name" placeholder="web"/></label><label class="field"><span>Restart policy</span><select name="restartPolicy"><option value="no">No restart</option><option value="unless-stopped">Unless stopped</option><option value="always">Always</option><option value="on-failure">On failure</option></select></label><label class="field field-wide"><span>Command <small>optional</small></span><input name="command" placeholder="npm run start"/></label><label class="field field-wide"><span>Ports <small>one per line · host:container</small></span><textarea name="ports" rows="2" placeholder="8080:80"></textarea></label><label class="field field-wide"><span>Environment <small>one KEY=value per line</small></span><textarea name="environment" rows="2" placeholder="NODE_ENV=production"></textarea></label><label class="field field-wide"><span>Volumes <small>one per line · host:container</small></span><textarea name="volumes" rows="2" placeholder="/srv/app:/app"></textarea></label><label class="field field-wide"><span>Networks <small>one per line</small></span><input name="networks" placeholder="bridge"/></label><label class="field"><span>Memory limit <small>optional</small></span><input name="memoryLimit" placeholder="512m"/></label><label class="field"><span>CPU limit <small>optional</small></span><input name="cpuLimit" placeholder="1.5"/></label></div><div class="inline-form-options"><label class="favorite-check"><input type="checkbox" name="detached" checked/><span></span>Run detached</label><label class="favorite-check"><input type="checkbox" name="removeOnExit"/><span></span>Remove on exit</label></div><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Create container</button></div></form>`, "modal-docker");
}

function renderComposeScaleModal(): string {
  const project = composeScaleProject;
  if (!project) return "";
  const serviceOptions = project.services.map((service) => `<option value="${escapeHtml(service)}">${escapeHtml(service)}</option>`).join("");
  return renderModalShell("Scale Compose service", `Choose how many replicas to run in ${escapeHtml(project.name)}.`, `<form class="modal-body form-stack" data-form="compose-scale"><label class="field"><span>Service</span><select name="service" required>${serviceOptions}</select></label><label class="field"><span>Replicas</span><input name="replicas" type="number" min="0" step="1" value="2" required autofocus/><small class="field-hint">Use 0 to stop every container for this service.</small></label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Scale service</button></div></form>`, "modal-small");
}

function renderInspectModal(): string {
  return renderModalShell("Resource inspect", "Raw JSON from the remote container runtime.", `<div class="modal-body"><pre class="inspect-output">${escapeHtml(inspectText || "Loading…")}</pre><div class="modal-actions"><button class="button button-quiet" data-action="close-modal">Close</button><button class="button button-primary" data-action="copy-inspect">${icon("copy")} Copy JSON</button></div></div>`, "modal-inspect");
}

function renderCredentialWarning(): string {
  return `<div class="credential-warning" role="note">${icon("info")}<div><strong>Important: your master password cannot be recovered.</strong><p>Write it down somewhere safe. If you forget it, the only recovery option is a complete reset, which permanently deletes every saved SSH password, key passphrase, and sudo password.</p></div></div>`;
}

function renderSecurityModal(): string {
  const status = !credentialStatus.configured
    ? "Not set up yet"
    : credentialStatus.unlocked
      ? "Unlocked for this session"
      : "Locked until you enter your master password";
  const scalePercent = Math.round(interfaceScale * 100);
  const scaleIndex = INTERFACE_SCALE_LEVELS.indexOf(interfaceScale as typeof INTERFACE_SCALE_LEVELS[number]);
  return renderModalShell("Settings", "Adjust Serverbox's appearance and manage locally saved credentials.", `<div class="modal-body security-modal-body"><section class="settings-section" aria-labelledby="appearance-settings-title"><div class="settings-section-copy"><h3 id="appearance-settings-title">Interface scale</h3><p>Increase the entire interface on HiDPI displays. You can also use ${platform === "macos" ? "Command" : "Ctrl"} +/− and ${platform === "macos" ? "Command" : "Ctrl"} 0.</p></div><div class="interface-scale-control" role="group" aria-label="Interface scale"><button class="icon-button" type="button" data-action="interface-scale-decrease" aria-label="Decrease interface scale" title="Decrease interface scale" ${scaleIndex <= 0 ? "disabled" : ""}>${icon("minus")}</button><output data-interface-scale-value aria-live="polite">${scalePercent}%</output><button class="icon-button" type="button" data-action="interface-scale-increase" aria-label="Increase interface scale" title="Increase interface scale" ${scaleIndex >= INTERFACE_SCALE_LEVELS.length - 1 ? "disabled" : ""}>${icon("plus")}</button><button class="button button-quiet scale-reset" type="button" data-action="interface-scale-reset" ${interfaceScale === DEFAULT_INTERFACE_SCALE ? "disabled" : ""}>Reset</button></div></section><div class="settings-divider"></div><div class="credential-status-card"><span>Vault status</span><strong>${status}</strong><small>Server names and connection details remain in the local profile database; saved secrets are kept in a separate encrypted file.</small></div>${renderCredentialWarning()}${credentialSettingsNotice ? `<div class="security-notice">${icon("check")}<span>${escapeHtml(credentialSettingsNotice)}</span></div>` : ""}${credentialSettingsError ? `<div class="inline-error">${icon("info")}<span>${escapeHtml(credentialSettingsError)}</span></div>` : ""}<div class="security-actions"><button class="button button-quiet" data-action="change-master-password" ${credentialStatus.configured ? "" : "disabled"}>${icon("key")} Change master password</button><button class="button button-danger" data-action="reset-credentials" ${credentialStatus.configured ? "" : "disabled"}>${icon("trash")} Reset all saved credentials</button></div><p class="security-footnote">Resetting removes saved credentials from this device but leaves your server profiles in place. You will create a new master password the next time you save credentials.</p><div class="modal-actions"><button class="button button-quiet" data-action="close-modal">Close</button></div></div>`, "modal-security");
}

function renderMasterPasswordModal(): string {
  const mode = masterPasswordPrompt?.mode ?? "unlock";
  const setup = mode === "setup";
  const promptError = masterPasswordPrompt?.error;
  return renderModalShell(setup ? "Create a master password" : "Unlock saved credentials", setup ? "Protect your local credential vault before continuing." : "Enter your master password to continue the pending operation.", `<form class="modal-body form-stack" data-form="master-password">${renderCredentialWarning()}${promptError ? `<div class="inline-error">${icon("info")}<span>${escapeHtml(promptError)}</span></div>` : ""}<label class="field"><span>Master password</span><input name="masterPassword" type="password" required autocomplete="${setup ? "new-password" : "current-password"}" placeholder="At least 8 characters"/></label>${setup ? `<label class="field"><span>Confirm master password</span><input name="confirmPassword" type="password" required autocomplete="new-password" placeholder="Enter it again"/></label>` : ""}<div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">${setup ? "Protect credentials" : "Unlock and continue"}</button></div></form>`, "modal-security");
}

function renderChangePasswordModal(): string {
  return renderModalShell("Change master password", "Verify the current password, then re-encrypt every saved credential with the new one.", `<form class="modal-body form-stack" data-form="change-password">${renderCredentialWarning()}${credentialSettingsError ? `<div class="inline-error">${icon("info")}<span>${escapeHtml(credentialSettingsError)}</span></div>` : ""}<label class="field"><span>Current master password</span><input name="currentPassword" type="password" required autocomplete="current-password"/></label><div class="form-divider"><span>New password</span></div><label class="field"><span>New master password</span><input name="newPassword" type="password" required autocomplete="new-password" placeholder="At least 8 characters"/></label><label class="field"><span>Confirm new password</span><input name="confirmPassword" type="password" required autocomplete="new-password"/></label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">Re-encrypt credentials</button></div></form>`, "modal-security");
}

function renderResetCredentialsModal(): string {
  return renderModalShell("Reset all saved credentials", "This permanently removes every saved secret from this device.", `<form class="modal-body form-stack" data-form="reset-credentials">${renderCredentialWarning()}${credentialSettingsError ? `<div class="inline-error">${icon("info")}<span>${escapeHtml(credentialSettingsError)}</span></div>` : ""}<label class="field"><span>Master password</span><input name="masterPassword" type="password" required autocomplete="current-password"/></label><label class="field"><span>Type RESET to confirm</span><input name="confirmation" required autocomplete="off" placeholder="RESET"/></label><div class="modal-actions"><button type="button" class="button button-quiet" data-action="close-modal">Keep credentials</button><button type="submit" class="button button-danger">Delete saved credentials</button></div></form>`, "modal-security");
}

function renderAuthFieldsForForm(form: HTMLFormElement): void {
  const selected = form.querySelector<HTMLInputElement>('input[name="authMethod"]:checked')?.value ?? "password";
  const target = form.querySelector<HTMLElement>("[data-auth-fields]");
  if (target) {
    target.innerHTML = renderAuthFields(editingServer, selected as "password" | "privateKey");
    enhanceSelects(root, target);
  }
}

async function selectServer(serverId: string, openAnother = false): Promise<void> {
  const tab = (!openAnother ? openServerTabs.find((item) => item.serverId === serverId) : undefined)
    ?? { id: crypto.randomUUID(), serverId };
  if (!openServerTabs.includes(tab)) openServerTabs.push(tab);
  await selectWorkspaceTab(tab.id);
}

async function selectWorkspaceTab(workspaceTabId: string): Promise<void> {
  const nextTab = openServerTabs.find((tab) => tab.id === workspaceTabId);
  if (!nextTab) return;
  cancelCurrentOperation();
  if (logsViewer.streamId) await stopLogViewer(logsViewer, "paused");
  if (containerLogViewer?.streamId) await stopLogViewer(containerLogViewer, "paused");
  if (activeWorkspaceTabId) {
    if (dashboard) dashboardSnapshots.set(activeWorkspaceTabId, dashboard);
    serverTabViews.set(activeWorkspaceTabId, activeView);
    if (activeTerminalTabId) activeTerminalTabByWorkspace.set(activeWorkspaceTabId, activeTerminalTabId);
  }
  activeWorkspaceTabId = workspaceTabId;
  activeServerId = nextTab.serverId;
  activeView = serverTabViews.get(workspaceTabId) ?? "dashboard";
  const savedTerminalId = activeTerminalTabByWorkspace.get(workspaceTabId);
  activeTerminalTabId = savedTerminalId && terminalTabs.some((tab) => tab.id === savedTerminalId && tab.workspaceTabId === workspaceTabId)
    ? savedTerminalId
    : activeTerminalTabs().at(-1)?.id ?? null;
  connection = null;
  dashboard = dashboardSnapshots.get(workspaceTabId) ?? null;
  processes = [];
  services = [];
  docker = null;
  composeProjects = [];
  composeProjectsServerId = null;
  ports = [];
  cronJobs = [];
  packagePage = null;
  accounts = null;
  remoteFiles = [];
  logsViewer = createLogViewer({ source: "system", label: "System logs" }, 100);
  clearContainerLogs();
  resetPaginationState();
  viewTransition = null;
  clearRefreshTimer();
  await setView(activeView);
}

async function handleClick(event: MouseEvent): Promise<void> {
  const clickedElement = event.target as HTMLElement;
  if (workspaceTabDrag.suppressesClick() && clickedElement.closest(".workspace-tab[data-workspace-tab]")) {
    event.preventDefault();
    return;
  }
  const customOption = clickedElement.closest<HTMLButtonElement>(".custom-select-option");
  if (customOption) {
    const picker = customOption.closest<HTMLElement>(".custom-select");
    const select = picker?.querySelector<HTMLSelectElement>("select");
    if (picker && select && !customOption.disabled) {
      select.value = customOption.dataset.value ?? "";
      syncCustomSelect(picker);
      closeCustomSelects(root);
      picker.querySelector<HTMLButtonElement>(".custom-select-trigger")?.focus();
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    return;
  }
  const customTrigger = clickedElement.closest<HTMLButtonElement>(".custom-select-trigger");
  if (customTrigger) {
    const picker = customTrigger.closest<HTMLElement>(".custom-select");
    const options = picker?.querySelector<HTMLElement>(".custom-select-options");
    if (picker && options) {
      const opening = !picker.classList.contains("open");
      closeCustomSelects(root, opening ? picker : undefined);
      picker.classList.toggle("open", opening);
      customTrigger.setAttribute("aria-expanded", String(opening));
      options.hidden = !opening;
      if (opening) picker.querySelector<HTMLButtonElement>(".custom-select-option.selected")?.focus();
    }
    return;
  }
  closeCustomSelects(root);
  const target = (event.target as HTMLElement).closest<HTMLElement>("[data-window], [data-server-action], [data-action], [data-view], [data-server-id], [data-workspace-tab], [data-workspace-rename], [data-workspace-close], [data-terminal-tab], [data-terminal-close], [data-file-path], [data-file-edit], [data-file-download], [data-file-delete], [data-file-chmod], [data-file-chown], [data-disk-tab], [data-disk-varlog], [data-disk-open-path], [data-container-platform-tab], [data-docker-tab], [data-docker-action], [data-docker-logs], [data-docker-exec], [data-docker-inspect], [data-logs-source], [data-process-action], [data-service-action], [data-service-details], [data-cron-edit], [data-cron-action], [data-package-action], [data-package-details], [data-account-tab], [data-user-action], [data-group-delete], [data-administration-tab], [data-compose-action], [data-firewall-action], [data-key-remove], [data-quick-action], [data-command-run], [data-command-edit], [data-command-delete], [data-tunnel-toggle], [data-tunnel-edit], [data-tunnel-delete]");
  if (!target) return;
  if (target.dataset.serverAction) {
    event.preventDefault();
    event.stopPropagation();
    const server = snapshot.servers.find((item) => item.id === target.dataset.serverId);
    if (!server) return;
    if (target.dataset.serverAction === "new-tab") {
      await selectServer(server.id, true);
    } else if (target.dataset.serverAction === "edit") {
      editingServer = server;
      errorMessage = "";
      modal = "server";
      render();
    } else if (target.dataset.serverAction === "duplicate") {
      await duplicateServer(server.id);
    } else if (target.dataset.serverAction === "delete") {
      await deleteServer(server.id);
    }
    return;
  }
  if (target.dataset.terminalClose) {
    event.stopPropagation();
    await closeTerminal(target.dataset.terminalClose);
    return;
  }
  if (target.dataset.workspaceRename) {
    event.preventDefault();
    event.stopPropagation();
    renamingWorkspaceTabId = target.dataset.workspaceRename;
    modal = "workspace-tab-rename";
    render();
    window.setTimeout(() => {
      const input = root.querySelector<HTMLInputElement>('form[data-form="workspace-tab-rename"] input[name="label"]');
      input?.focus();
      input?.select();
    }, 0);
    return;
  }
  if (target.dataset.workspaceClose) {
    event.preventDefault();
    event.stopPropagation();
    await closeWorkspaceTab(target.dataset.workspaceClose);
    return;
  }
  if (target.dataset.workspaceTab) {
    await selectWorkspaceTab(target.dataset.workspaceTab);
    return;
  }
  if (target.dataset.window) {
    event.preventDefault();
    event.stopPropagation();
    try {
      if (target.dataset.window === "minimize") await appWindow.minimize();
      else if (target.dataset.window === "maximize") await appWindow.toggleMaximize();
      else await appWindow.close();
    } catch (error) {
      setError(error);
    }
    return;
  }
  if (target.dataset.view) {
    await setView(target.dataset.view as View);
    return;
  }
  if (target.dataset.serverId) {
    await selectServer(target.dataset.serverId);
    return;
  }
  if (target.dataset.terminalTab) {
    activeTerminalTabId = target.dataset.terminalTab;
    if (activeWorkspaceTabId) activeTerminalTabByWorkspace.set(activeWorkspaceTabId, activeTerminalTabId);
    render();
    return;
  }
  if (target.dataset.filePath) {
    await navigateFiles(target.dataset.filePath);
    return;
  }
  if (target.dataset.fileEdit) {
    await openEditor(target.dataset.fileEdit);
    return;
  }
  if (target.dataset.fileDownload) {
    await downloadRemote(target.dataset.fileDownload);
    return;
  }
  if (target.dataset.fileDelete) {
    await deleteRemote(target.dataset.fileDelete);
    return;
  }
  if (target.dataset.fileChmod) {
    await changeRemoteMode(target.dataset.fileChmod);
    return;
  }
  if (target.dataset.fileChown) {
    await changeRemoteOwner(target.dataset.fileChown);
    return;
  }
  if (target.dataset.diskVarlog !== undefined) {
    await ensureDiskVarLog(true);
    return;
  }
  if (target.dataset.diskTab) {
    await selectDiskTab(target.dataset.diskTab as DiskTab);
    return;
  }
  if (target.dataset.diskOpenPath) {
    await openDiskPathInFiles(target.dataset.diskOpenPath);
    return;
  }
  if (target.dataset.containerPlatformTab) {
    const nextTab = target.dataset.containerPlatformTab as ContainerPlatformTab;
    if (containerPlatformTab !== nextTab) clearContainerLogs();
    containerPlatformTab = nextTab;
    clearCommandResults();
    await loadActiveView(true);
    return;
  }
  if (target.dataset.dockerTab) {
    await selectDockerSection(target.dataset.dockerTab as DockerSection);
    return;
  }
  if (target.dataset.dockerAction) {
    await dockerAction(target.dataset.dockerAction, target.dataset.dockerTarget ?? "");
    return;
  }
  if (target.dataset.dockerLogs) {
    await loadDockerLogs(target.dataset.dockerLogs);
    return;
  }
  if (target.dataset.dockerExec) {
    await openDockerTerminal(target.dataset.dockerExec);
    return;
  }
  if (target.dataset.dockerInspect) {
    await openInspect(target.dataset.dockerInspect, target.dataset.dockerKind ?? "container");
    return;
  }
  if (target.dataset.logsSource) {
    cancelCurrentOperation();
    navigationVersion += 1;
    await stopLogViewer(logsViewer, "idle");
    const source = target.dataset.logsSource as LogSource;
    const lines = logsViewer.lines;
    const targetBySource: Record<"system" | "container" | "file", LogTarget> = {
      system: { source: "system", label: "System logs" },
      container: { source: "container", label: "Container logs" },
      file: { source: "file", label: "Log file", filePath: "/var/log/" },
    };
    if (source !== "system" && source !== "container" && source !== "file") return;
    logsViewer = createLogViewer(targetBySource[source], lines);
    errorMessage = "";
    clearRefreshTimer();
    render();
    if ((source === "container" || source === "file") && activeServerId) {
      try {
        if (source === "container" || (source === "file" && Boolean(activeCapabilities()?.docker || activeCapabilities()?.podman))) {
          await ensureDockerContainersForLogs(activeServerId, navigationVersion);
        }
        if (source === "file") await loadLogFileChoices(activeServerId, navigationVersion);
        render();
      } catch (error) {
        setError(error);
      }
    }
    return;
  }
  if (target.dataset.processAction) {
    const pid = Number(target.dataset.pid);
    const force = target.dataset.processAction === "kill";
    const proceed = await confirm(`${force ? "Force kill" : "Stop"} process ${pid}?`, { title: "Confirm process action", kind: "warning" });
    if (proceed) await runProcessAction(pid, force);
    return;
  }
  if (target.dataset.serviceAction) {
    await runServiceAction(target.dataset.serviceAction, target.dataset.service ?? "");
    return;
  }
  if (target.dataset.serviceDetails) {
    await openServiceDetails(target.dataset.serviceDetails);
    return;
  }
  if (target.dataset.cronEdit) {
    editingCron = cronJobs.find((job) => job.id === target.dataset.cronEdit) ?? null;
    modal = "cron"; render(); return;
  }
  if (target.dataset.cronAction) { await runCronAction(target.dataset.cronId ?? "", target.dataset.cronAction); return; }
  if (target.dataset.packageDetails) { await openPackageDetails(target.dataset.packageDetails); return; }
  if (target.dataset.packageAction) { await runPackageAction(target.dataset.packageAction, target.dataset.packageName); return; }
  if (target.dataset.accountTab) { accountTab = target.dataset.accountTab as typeof accountTab; render(); return; }
  if (target.dataset.userAction) { await runUserAction(target.dataset.userAction, target.dataset.userName ?? ""); return; }
  if (target.dataset.groupDelete) { await deleteGroup(target.dataset.groupDelete); return; }
  if (target.dataset.administrationTab) { administrationTab = target.dataset.administrationTab as AdministrationTab; clearCommandResults(); await loadAdministrationTab(); return; }
  if (target.dataset.composeAction) { await runComposeAction(target.dataset.composePath ?? "", target.dataset.composeAction); return; }
  if (target.dataset.firewallAction) { await runFirewallAction(target.dataset.firewallAction); return; }
  if (target.dataset.keyRemove) { await removeAuthorizedKey(target.dataset.keyRemove); return; }
  if (target.dataset.quickAction) { await runQuickAction(target.dataset.quickAction); return; }
  if (target.dataset.commandRun) { await runSavedCommand(target.dataset.commandRun); return; }
  if (target.dataset.commandEdit) { editingCommand = savedCommands.find((item) => item.id === target.dataset.commandEdit) ?? null; modal = "command"; render(); return; }
  if (target.dataset.commandDelete) { await deleteSavedCommand(target.dataset.commandDelete); return; }
  if (target.dataset.tunnelToggle) { await toggleTunnel(target.dataset.tunnelToggle, target.dataset.tunnelRunning === "true"); return; }
  if (target.dataset.tunnelEdit) { editingTunnel = tunnels.find((item) => item.id === target.dataset.tunnelEdit) ?? null; modal = "tunnel"; render(); return; }
  if (target.dataset.tunnelDelete) { await deleteTunnel(target.dataset.tunnelDelete); return; }
  const action = target.dataset.action;
  if (!action) return;
  switch (action) {
    case "add-server": editingServer = null; modal = "server"; errorMessage = ""; render(); break;
    case "credential-settings": credentialSettingsError = ""; credentialSettingsNotice = ""; modal = "security"; render(); break;
    case "change-master-password": credentialSettingsError = ""; credentialSettingsNotice = ""; modal = "change-password"; render(); break;
    case "reset-credentials": credentialSettingsError = ""; credentialSettingsNotice = ""; modal = "reset-credentials"; render(); break;
    case "connect": await setView("dashboard"); break;
    case "close-modal": closeModal(); break;
    case "accept-app-dialog": finishAppDialog(true); break;
    case "cancel-app-dialog": finishAppDialog(false); break;
    case "dismiss-toast": dismissToast(); break;
    case "reject-host-key": finishHostKeyPrompt(false); break;
    case "trust-host-key": finishHostKeyPrompt(true); break;
    case "close-editor": closeModal(); break;
    case "cancel-operation": cancelCurrentOperation(); break;
    case "cancel-transfer": cancelTransfer(); break;
    case "disconnect": await disconnectActiveServer(); break;
    case "save-and-test": { const form = root.querySelector<HTMLFormElement>('form[data-form="server"]'); if (form) await saveServerForm(form, true); break; }
    case "delete-server": await deleteActiveServer(); break;
    case "refresh": composeProjectsServerId = null; await loadActiveView(false, true); break;
    case "load-more": await loadMoreActiveView(); break;
    case "retry": errorMessage = ""; await loadActiveView(false, true); break;
    case "dismiss-error": errorMessage = ""; render(); break;
    case "theme": darkMode = !darkMode; localStorage.setItem("serverbox-theme", darkMode ? "dark" : "light"); render(); break;
    case "interface-scale-decrease": await stepInterfaceScale(-1); break;
    case "interface-scale-increase": await stepInterfaceScale(1); break;
    case "interface-scale-reset": await setInterfaceScale(DEFAULT_INTERFACE_SCALE); break;
    case "new-terminal": await openNewTerminal(); break;
    case "reconnect-terminal": await reconnectTerminal(); break;
    case "clear-terminal": clearActiveTerminal(); break;
    case "new-folder": modal = "folder"; render(); break;
    case "upload-file": await uploadLocal(); break;
    case "upload-folder": await uploadLocalFolder(); break;
    case "download-current": await downloadRemote(remotePath); break;
    case "load-log-viewer": { const viewer = logViewerForScope(target.dataset.logScope); if (viewer) await loadLogViewer(viewer, target.dataset.logScope === "container" ? "container" : "workspace"); break; }
    case "copy-log-viewer": { const viewer = logViewerForScope(target.dataset.logScope); if (viewer) await copyText(viewer.text); break; }
    case "clear-log-viewer": { const viewer = logViewerForScope(target.dataset.logScope); if (viewer) { viewer.text = ""; updateLogViewerDom(viewer, target.dataset.logScope === "container" ? "container" : "workspace"); } break; }
    case "docker-pull": await pullDockerImage(); break;
    case "docker-create": modal = "docker"; render(); break;
    case "docker-create-volume": await createDockerResource("volume-create", "volume"); break;
    case "docker-create-network": await createDockerResource("network-create", "network"); break;
    case "new-cron": editingCron = null; modal = "cron"; render(); break;
    case "search-packages": await loadActiveView(true); break;
    case "new-user": modal = "user"; render(); break;
    case "new-group": await createGroup(); break;
    case "copy-package-details": await copyText(packageDetailsText); break;
    case "copy-inspect": await copyText(inspectText); break;
    case "add-authorized-key": await addAuthorizedKey(); break;
    case "new-command": editingCommand = null; modal = "command"; render(); break;
    case "new-tunnel": editingTunnel = null; modal = "tunnel"; render(); break;
    case "show-help": await message("Serverbox connects directly over SSH. Add a password or private-key profile, then use the sidebar to move between the dashboard, terminal, files, systemd services, SFTP files, container runtime, system logs, and network sockets.", { title: "How Serverbox works" }); break;
  }
}

function handleInput(event: Event): void {
  const input = event.target as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
  if (!input.dataset.field) return;
  if (input.dataset.field === "server-search") {
    serverQuery = input.value;
    const list = root.querySelector<HTMLElement>(".server-list");
    if (list) {
      const servers = filteredServers();
      list.innerHTML = servers.length ? renderServerGroups(servers) : `<div class="server-empty">${serverQuery.trim() ? "No matching servers" : "No servers saved yet"}</div>`;
    } else {
      render();
    }
  } else if (input.dataset.field === "service-search") {
    const query = input.value.toLowerCase();
    root.querySelectorAll<HTMLElement>("[data-service-row]").forEach((row) => { row.hidden = !row.dataset.serviceRow!.toLowerCase().includes(query); });
  } else if (input.dataset.field === "file-search") {
    remoteFileSearch = input.value;
    render();
    const next = root.querySelector<HTMLInputElement>('[data-field="file-search"]');
    next?.focus(); next?.setSelectionRange(remoteFileSearch.length, remoteFileSearch.length);
  } else if (input.dataset.field === "editor-content") {
    editorContent = input.value;
    editorDirty = true;
    const saveButton = root.querySelector<HTMLButtonElement>('form[data-form="editor"] button[type="submit"]');
    if (saveButton) saveButton.disabled = false;
    const status = root.querySelector<HTMLElement>(".editor-status");
    if (status) status.textContent = `Unsaved changes · ${formatBytes(new Blob([editorContent]).size)}`;
  } else if (input.dataset.field === "log-service") {
    const viewer = logViewerForScope(input.dataset.logScope);
    if (viewer) { viewer.target.service = input.value || undefined; updateLogTargetLabel(viewer); }
  } else if (input.dataset.field === "log-file-path") {
    logsViewer.target.filePath = input.value;
    updateLogTargetLabel(logsViewer);
  } else if (input.dataset.field === "log-query") {
    const viewer = logViewerForScope(input.dataset.logScope);
    if (viewer) { viewer.query = input.value; updateLogViewerDom(viewer, input.dataset.logScope === "container" ? "container" : "workspace"); }
  } else if (input.dataset.field === "package-query") {
    packageQuery = input.value;
  }
}

function handleChange(event: Event): void {
  const input = event.target as HTMLInputElement | HTMLSelectElement;
  if (input.dataset.field === "cron-preset") {
    const schedule = input.closest<HTMLFormElement>("form")?.elements.namedItem("schedule") as HTMLInputElement | null;
    if (schedule && input.value) schedule.value = input.value;
    return;
  }
  if (input.dataset.field === "package-upgrades") {
    packageUpgradesOnly = (input as HTMLInputElement).checked;
    void loadActiveView(true);
    return;
  }
  if (input.dataset.field === "ssh-config") {
    const entry = snapshot.sshConfigEntries.find((item) => item.alias === input.value);
    const form = input.closest<HTMLFormElement>('form[data-form="server"]');
    if (entry && form) {
      const set = (name: string, value: string) => { const field = form.elements.namedItem(name) as HTMLInputElement | null; if (field) field.value = value; };
      set("host", entry.host ?? "");
      set("username", entry.username ?? "");
      set("port", String(entry.port ?? 22));
      if (entry.keyPath) {
        const radio = form.querySelector<HTMLInputElement>('input[name="authMethod"][value="privateKey"]');
        if (radio) { radio.checked = true; renderAuthFieldsForForm(form); }
        const keySelect = form.elements.namedItem("keyPath") as HTMLSelectElement | null;
        const customKey = form.elements.namedItem("customKeyPath") as HTMLInputElement | null;
        if (keySelect && snapshot.sshKeys.some((key) => key.path === entry.keyPath)) {
          keySelect.value = entry.keyPath;
          const picker = keySelect.closest<HTMLElement>(".custom-select");
          if (picker) syncCustomSelect(picker);
        }
        else if (customKey) customKey.value = entry.keyPath;
      }
    }
    return;
  }
  if (input.name === "authMethod") {
    const form = input.closest<HTMLFormElement>("form");
    if (form) renderAuthFieldsForForm(form);
    return;
  }
  if (input.dataset.field === "show-hidden") { showHidden = (input as HTMLInputElement).checked; remoteFiles = []; filesHaveMore = false; void loadActiveView(true); }
  const logViewer = logViewerForScope(input.dataset.logScope);
  const logScope = input.dataset.logScope === "container" ? "container" : "workspace";
  if (input.dataset.field === "log-follow" && logViewer) { logViewer.following = (input as HTMLInputElement).checked; void setLogFollowing(logViewer, logScope); }
  if (input.dataset.field === "log-container" && logViewer) { logViewer.target.container = input.value || undefined; updateLogTargetLabel(logViewer); }
  if (input.dataset.field === "log-file-container" && logViewer) { logViewer.target.container = input.value || undefined; updateLogTargetLabel(logViewer); }
  if (input.dataset.field === "log-lines" && logViewer) { logViewer.lines = Number(input.value) || 100; }
  if (input.dataset.field === "log-since" && logViewer) { logViewer.since = input.value; }
  if (input.dataset.field === "log-severity" && logViewer) { logViewer.severity = input.value as LogViewerState["severity"]; updateLogViewerDom(logViewer, logScope); }
  if (logViewer && ["log-service", "log-container", "log-file-container", "log-file-path"].includes(input.dataset.field ?? "")) {
    const targetReady = logViewer.target.source === "system"
      || logViewer.target.source === "compose"
      || (logViewer.target.source === "container" && Boolean(logViewer.target.container))
      || (logViewer.target.source === "file" && Boolean(logViewer.target.filePath));
    if (targetReady) {
      logViewer.text = "";
      void loadLogViewer(logViewer, logScope);
    }
  }
}

async function handleSubmit(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  const form = event.target as HTMLFormElement;
  const kind = form.dataset.form;
  if (kind === "master-password") await submitMasterPasswordForm(form);
  else if (kind === "change-password") await changeMasterPasswordForm(form);
  else if (kind === "reset-credentials") await resetCredentialsForm(form);
  else if (kind === "server") await saveServerForm(form, false);
  else if (kind === "editor") await saveEditorForm(form);
  else if (kind === "folder") await createFolder(form);
  else if (kind === "docker") await createDocker(form);
  else if (kind === "input-prompt") finishTextInput(String(new FormData(form).get("value") ?? ""));
  else if (kind === "compose-scale") await submitComposeScaleForm(form);
  else if (kind === "cron") await saveCronForm(form);
  else if (kind === "user") await createUserForm(form);
  else if (kind === "user-password") await resetUserPasswordForm(form);
  else if (kind === "firewall") await submitFirewallForm(form, event.submitter as HTMLButtonElement | null);
  else if (kind === "command") await saveCommandForm(form);
  else if (kind === "tunnel") await saveTunnelForm(form);
  else if (kind === "workspace-tab-rename") saveWorkspaceTabRenameForm(form);
}

function saveWorkspaceTabRenameForm(form: HTMLFormElement): void {
  const tab = openServerTabs.find((item) => item.id === renamingWorkspaceTabId);
  if (!tab) return;
  const label = String(new FormData(form).get("label") ?? "").trim();
  tab.label = label || undefined;
  renamingWorkspaceTabId = null;
  modal = null;
  render();
}

async function submitMasterPasswordForm(form: HTMLFormElement): Promise<void> {
  const prompt = masterPasswordPrompt;
  if (!prompt || !finishMasterPasswordWaiter) return;
  const data = new FormData(form);
  const password = String(data.get("masterPassword") ?? "");
  if ([...password].length < 8) {
    prompt.error = "Choose a master password that is at least 8 characters long.";
    render();
    return;
  }
  if (prompt.mode === "setup" && password !== String(data.get("confirmPassword") ?? "")) {
    prompt.error = "The two master passwords do not match.";
    render();
    return;
  }
  finishMasterPasswordPrompt(password);
}

async function changeMasterPasswordForm(form: HTMLFormElement): Promise<void> {
  const data = new FormData(form);
  const currentPassword = String(data.get("currentPassword") ?? "");
  const newPassword = String(data.get("newPassword") ?? "");
  const confirmation = String(data.get("confirmPassword") ?? "");
  credentialSettingsError = "";
  if ([...newPassword].length < 8) credentialSettingsError = "Choose a new master password that is at least 8 characters long.";
  else if (newPassword !== confirmation) credentialSettingsError = "The two new master passwords do not match.";
  if (credentialSettingsError) { render(); return; }
  try {
    cancelCurrentOperation();
    clearRefreshTimer();
    await closeInteractiveSessions();
    credentialStatus = await invoke<CredentialStatus>("change_master_password", { currentPassword, newPassword });
    connectedServerIds.clear();
    connection = null;
    dashboard = null;
    dashboardSnapshots.clear();
    processes = [];
    services = [];
    docker = null;
    ports = [];
    remoteFiles = [];
    logsViewer = createLogViewer({ source: "system", label: "System logs" }, 100);
    resetPaginationState();
    errorMessage = "";
    credentialSettingsError = "";
    credentialSettingsNotice = "Master password changed. All saved credentials were re-encrypted with the new password.";
    modal = "security";
    render();
  } catch (error) {
    credentialSettingsError = errorKind(error) === "masterPasswordInvalid"
      ? "The current master password is incorrect."
      : errorText(error);
    render();
  }
}

async function resetCredentialsForm(form: HTMLFormElement): Promise<void> {
  const data = new FormData(form);
  const password = String(data.get("masterPassword") ?? "");
  const confirmation = String(data.get("confirmation") ?? "");
  credentialSettingsError = "";
  if (confirmation !== "RESET") credentialSettingsError = "Type RESET exactly to confirm this irreversible action.";
  if (credentialSettingsError) { render(); return; }
  try {
    cancelCurrentOperation();
    clearRefreshTimer();
    await closeInteractiveSessions();
    await invoke("reset_credentials", { masterPassword: password });
    connectedServerIds.clear();
    credentialStatus = { configured: false, unlocked: false };
    connection = null;
    dashboard = null;
    dashboardSnapshots.clear();
    processes = [];
    services = [];
    docker = null;
    ports = [];
    remoteFiles = [];
    logsViewer = createLogViewer({ source: "system", label: "System logs" }, 100);
    resetPaginationState();
    errorMessage = "";
    credentialSettingsError = "";
    credentialSettingsNotice = "All saved credentials were deleted. Your server profiles are still here.";
    modal = "security";
    render();
  } catch (error) {
    credentialSettingsError = errorKind(error) === "masterPasswordInvalid"
      ? "The master password is incorrect. Nothing was reset."
      : errorText(error);
    render();
  }
}

async function saveServerForm(form: HTMLFormElement, testAfter: boolean): Promise<void> {
  const data = new FormData(form);
  const authMethod = String(data.get("authMethod") ?? "password") as "password" | "privateKey";
  const customKeyPath = String(data.get("customKeyPath") ?? "").trim();
  const selectedKeyPath = String(data.get("keyPath") ?? "").trim();
  const password = String(data.get("password") ?? "");
  const keyPassphrase = String(data.get("keyPassphrase") ?? "");
  const sudoPassword = String(data.get("sudoPassword") ?? "");
  const payload: Record<string, unknown> = {
    id: editingServer?.id,
    name: String(data.get("name") ?? ""),
    host: String(data.get("host") ?? ""),
    username: String(data.get("username") ?? ""),
    port: Number(data.get("port") ?? 22),
    authMethod,
    keyPath: authMethod === "privateKey" ? customKeyPath || selectedKeyPath || undefined : undefined,
    jumpHostId: String(data.get("jumpHostId") ?? "").trim() || undefined,
    groupName: normalizedGroupName(String(data.get("groupName") ?? "")) || undefined,
    tags: String(data.get("tags") ?? "").split(",").map((tag) => tag.trim()).filter(Boolean),
    notes: String(data.get("notes") ?? ""),
    favorite: data.get("favorite") === "on",
  };
  if (!editingServer || password) payload.password = password;
  if (!editingServer || keyPassphrase) payload.keyPassphrase = keyPassphrase;
  if (!editingServer || sudoPassword) payload.sudoPassword = sudoPassword;
  cancelCurrentOperation();
  errorMessage = ""; render();
  try {
    const result = await invokeCommand<ServerSaveResult>("save_server", { draft: payload });
    const saved = result.server;
    for (const invalidatedServerId of result.invalidatedServerIds) {
      await closeInteractiveSessions(invalidatedServerId);
      connectedServerIds.delete(invalidatedServerId);
      for (const tab of openServerTabs.filter((item) => item.serverId === invalidatedServerId)) dashboardSnapshots.delete(tab.id);
    }
    await refreshSnapshot(false);
    let workspaceTab = openServerTabs.find((item) => item.serverId === saved.id);
    if (!workspaceTab) {
      workspaceTab = { id: crypto.randomUUID(), serverId: saved.id };
      openServerTabs.push(workspaceTab);
    }
    editingServer = null;
    modal = null;
    if (activeWorkspaceTabId !== workspaceTab.id) {
      await selectWorkspaceTab(workspaceTab.id);
    } else if (result.invalidatedServerIds.includes(saved.id)) {
      connection = null;
      dashboard = null;
      processes = [];
      services = [];
      docker = null;
      ports = [];
      remoteFiles = [];
      logsViewer = createLogViewer({ source: "system", label: "System logs" }, 100);
      resetPaginationState();
    }
    render();
    if (testAfter) {
      await testActiveServer();
    } else {
      await setView("dashboard");
    }
  } catch (error) { setError(error); }
}

async function testActiveServer(): Promise<void> {
  if (!activeServerId) return;
  await setView("dashboard");
}

async function duplicateServer(serverId: string): Promise<void> {
  try {
    const duplicated = await invokeCommand<ServerProfile>("duplicate_server", { serverId });
    await refreshSnapshot(false);
    sidebarCopyPlacement = { sourceId: serverId, copyId: duplicated.id };
    editingServer = duplicated;
    modal = "server";
    render();
  } catch (error) { setError(error); }
}

async function saveCronForm(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return;
  const data = new FormData(form);
  try {
    await invokeCommand("save_cron_job", { serverId: activeServerId, input: { id: editingCron?.id, schedule: String(data.get("schedule") ?? ""), command: String(data.get("command") ?? ""), enabled: data.get("enabled") === "on" } });
    modal = null; editingCron = null; await loadActiveView();
  } catch (error) { setError(error); }
}

async function runCronAction(id: string, action: string): Promise<void> {
  if (!activeServerId) return;
  if (action === "delete" && !await confirm("Delete this cron job?", { title: "Delete cron job", kind: "warning" })) return;
  try { await invokeCommand("cron_action", { serverId: activeServerId, id, action }); await loadActiveView(); } catch (error) { setError(error); }
}

async function openPackageDetails(name: string): Promise<void> {
  if (!activeServerId) return;
  modal = "package-details"; packageDetailsText = ""; render();
  try { packageDetailsText = await invokeCommand<string>("get_package_details", { serverId: activeServerId, name }); render(); } catch (error) { setError(error); }
}

async function runPackageAction(action: string, name?: string): Promise<void> {
  if (!activeServerId) return;
  const destructive = action === "remove" || action === "upgrade-all";
  if (destructive && !await confirm(action === "remove" ? `Remove ${name}?` : "Install every pending upgrade?", { title: "Confirm package operation", kind: "warning" })) return;
  try {
    await invokeCommand<string>("package_action", { serverId: activeServerId, action, name });
    await loadActiveView();
  } catch (error) { setError(error); }
}

async function createUserForm(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return;
  const data = new FormData(form);
  const input = { name: String(data.get("name") ?? ""), home: String(data.get("home") ?? "") || undefined, shell: String(data.get("shell") ?? "") || undefined, groups: String(data.get("groups") ?? "").split(",").map((item) => item.trim()).filter(Boolean), password: String(data.get("password") ?? "") || undefined };
  try { await invokeCommand("create_user", { serverId: activeServerId, input }); modal = null; await loadActiveView(); } catch (error) { setError(error); }
}

async function runUserAction(action: string, name: string): Promise<void> {
  if (!activeServerId) return;
  if (action === "password") { passwordUser = name; modal = "user-password"; render(); return; }
  let value: string | undefined;
  if (action === "shell") { value = (await requestTextInput({ title: "Change login shell", label: `New login shell for ${name}`, defaultValue: accounts?.users.find((user) => user.name === name)?.shell ?? "", placeholder: "/bin/sh" })) ?? undefined; if (!value) return; }
  if (action === "groups") {
    value = (await requestTextInput({ title: "Change supplementary groups", label: `Complete comma-separated group list for ${name}`, defaultValue: "", allowEmpty: true, placeholder: "sudo,docker" })) ?? undefined;
    if (value === undefined) return;
    if (!value.trim() && !await confirm(`Remove ${name} from every supplementary group?`, { title: "Clear supplementary groups", kind: "warning" })) return;
  }
  if ((action === "delete-user" || action === "lock") && !await confirm(action === "delete-user" ? `Delete ${name} and their home directory?` : `Lock ${name}?`, { title: "Confirm account change", kind: "warning" })) return;
  try { await invokeCommand("account_action", { serverId: activeServerId, action, name, value }); await loadActiveView(); } catch (error) { setError(error); }
}

async function resetUserPasswordForm(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return;
  const data = new FormData(form);
  const password = String(data.get("password") ?? "");
  if (password !== String(data.get("confirmation") ?? "")) { errorMessage = "The passwords do not match."; render(); return; }
  try { await invokeCommand("reset_user_password", { serverId: activeServerId, name: passwordUser, password }); modal = null; passwordUser = ""; await loadActiveView(); } catch (error) { setError(error); }
}

async function createGroup(): Promise<void> {
  if (!activeServerId) return;
  const name = (await requestTextInput({ title: "Create group", label: "Group name", defaultValue: "" }))?.trim();
  if (!name) return;
  try { await invokeCommand("account_action", { serverId: activeServerId, action: "create-group", name }); await loadActiveView(); } catch (error) { setError(error); }
}

async function deleteGroup(name: string): Promise<void> {
  if (!activeServerId || !await confirm(`Delete group ${name}?`, { title: "Delete group", kind: "warning" })) return;
  try { await invokeCommand("account_action", { serverId: activeServerId, action: "delete-group", name }); await loadActiveView(); } catch (error) { setError(error); }
}

async function deleteServer(serverId: string): Promise<void> {
  const server = snapshot.servers.find((item) => item.id === serverId);
  if (!server) return;
  const dependents = snapshot.servers.filter((item) => item.jumpHostId === server.id);
  const routeWarning = dependents.length
    ? ` ${dependents.length} profile${dependents.length === 1 ? "" : "s"} (${dependents.map((item) => item.name).join(", ")}) will switch to direct connections.`
    : "";
  const proceed = await confirm(`Remove “${server.name}” and its encrypted saved credentials?${routeWarning}`, { title: "Remove connection", kind: "warning" });
  if (!proceed) return;
  try {
    cancelCurrentOperation();
    const currentActive = activeServer();
    const affectedActiveRoute = Boolean(currentActive && profileRouteContains(currentActive, server.id));
    const affectedServerIds = snapshot.servers.filter((profile) => profileRouteContains(profile, server.id)).map((profile) => profile.id);
    for (const affectedServerId of affectedServerIds) {
      await closeInteractiveSessions(affectedServerId);
      connectedServerIds.delete(affectedServerId);
      for (const tab of openServerTabs.filter((item) => item.serverId === affectedServerId)) dashboardSnapshots.delete(tab.id);
    }
    await invokeCommand("delete_server", { serverId: server.id });
    await refreshSnapshot(false);
    if (affectedActiveRoute) {
      connection = null;
      dashboard = null;
      processes = [];
      services = [];
      docker = null;
      composeProjects = [];
      composeProjectsServerId = null;
      ports = [];
      remoteFiles = [];
      logsViewer = createLogViewer({ source: "system", label: "System logs" }, 100);
      clearContainerLogs();
      resetPaginationState();
    }
    editingServer = null;
    modal = null;
    render();
    if (affectedActiveRoute && activeServerId) await setView("dashboard");
  } catch (error) { setError(error); }
}

async function deleteActiveServer(): Promise<void> {
  if (activeServerId) await deleteServer(activeServerId);
}

async function disconnectActiveServer(): Promise<void> {
  const serverId = activeServerId;
  if (!serverId) return;
  cancelCurrentOperation();
  clearRefreshTimer();
  await closeInteractiveSessions(serverId);
  await invokeCommand("disconnect_server", { serverId }).catch((error) => setError(error));
  connectedServerIds.delete(serverId);
  navigationVersion += 1;
  connection = null;
  dashboard = null;
  for (const tab of openServerTabs.filter((item) => item.serverId === serverId)) dashboardSnapshots.delete(tab.id);
  processes = [];
  services = [];
  docker = null;
  composeProjects = [];
  composeProjectsServerId = null;
  ports = [];
  remoteFiles = [];
  logsViewer = createLogViewer({ source: "system", label: "System logs" }, 100);
  clearContainerLogs();
  resetPaginationState();
  render();
}

async function closeInteractiveSessions(serverId?: string): Promise<void> {
  const closingTabs = serverId ? terminalTabs.filter((tab) => tab.serverId === serverId) : terminalTabs;
  for (const tab of closingTabs) {
    if (tab.sessionId) await invoke("close_terminal", { sessionId: tab.sessionId }).catch(() => undefined);
  }
  terminalTabs = serverId ? terminalTabs.filter((tab) => tab.serverId !== serverId) : [];
  if (!serverId || activeServerId === serverId) activeTerminalTabId = null;
  if (serverId) {
    for (const tab of openServerTabs.filter((item) => item.serverId === serverId)) activeTerminalTabByWorkspace.delete(tab.id);
  } else activeTerminalTabByWorkspace.clear();
  if (!serverId || activeServerId === serverId) {
    terminalMountTabId = null;
    terminal?.dispose(); terminal = null; fitAddon = null; serializeAddon = null;
  }
  for (const tab of closingTabs) if (tab.sessionId) terminalInputChains.delete(tab.sessionId);
}

async function closeWorkspaceInteractiveSessions(workspaceTabId: string): Promise<void> {
  const closingTabs = terminalTabs.filter((tab) => tab.workspaceTabId === workspaceTabId);
  for (const tab of closingTabs) {
    if (tab.sessionId) await invoke("close_terminal", { sessionId: tab.sessionId }).catch(() => undefined);
  }
  terminalTabs = terminalTabs.filter((tab) => tab.workspaceTabId !== workspaceTabId);
  activeTerminalTabByWorkspace.delete(workspaceTabId);
  if (activeWorkspaceTabId === workspaceTabId) {
    activeTerminalTabId = null;
    terminalMountTabId = null;
    terminal?.dispose(); terminal = null; fitAddon = null; serializeAddon = null;
  }
  for (const tab of closingTabs) if (tab.sessionId) terminalInputChains.delete(tab.sessionId);
}

async function closeWorkspaceTab(workspaceTabId: string): Promise<void> {
  const tabIndex = openServerTabs.findIndex((tab) => tab.id === workspaceTabId);
  if (tabIndex < 0) return;
  const closingTab = openServerTabs[tabIndex];
  if (activeWorkspaceTabId === workspaceTabId) cancelCurrentOperation();
  await closeWorkspaceInteractiveSessions(workspaceTabId);
  serverTabViews.delete(workspaceTabId);
  dashboardSnapshots.delete(workspaceTabId);
  openServerTabs = openServerTabs.filter((tab) => tab.id !== workspaceTabId);
  if (!openServerTabs.some((tab) => tab.serverId === closingTab.serverId)) {
    await invoke("disconnect_server", { serverId: closingTab.serverId }).catch(() => undefined);
    connectedServerIds.delete(closingTab.serverId);
  }
  if (activeWorkspaceTabId !== workspaceTabId) { render(); return; }
  const nextTab = openServerTabs[Math.min(tabIndex, openServerTabs.length - 1)] ?? null;
  activeWorkspaceTabId = null;
  activeServerId = null;
  connection = null;
  if (nextTab) await selectWorkspaceTab(nextTab.id);
  else render();
}

async function refreshSnapshot(loadView = true): Promise<void> {
  snapshot = await invokeCommand<AppStateSnapshot>("get_state");
  const activeTabIndex = activeWorkspaceTabId ? openServerTabs.findIndex((tab) => tab.id === activeWorkspaceTabId) : -1;
  openServerTabs = openServerTabs.filter((tab) => snapshot.servers.some((server) => server.id === tab.serverId));
  if (activeServerId && !snapshot.servers.some((server) => server.id === activeServerId)) {
    const nextTab = openServerTabs[Math.min(Math.max(activeTabIndex, 0), openServerTabs.length - 1)] ?? null;
    activeWorkspaceTabId = nextTab?.id ?? null;
    activeServerId = nextTab?.serverId ?? null;
  }
  if (activeServerId && !activeWorkspaceTab()) {
    const tab = { id: crypto.randomUUID(), serverId: activeServerId };
    openServerTabs.push(tab);
    activeWorkspaceTabId = tab.id;
  }
  if (loadView && activeServerId) await loadActiveView();
}

async function setView(view: View): Promise<void> {
  if (!activeServerId) return;
  cancelCurrentOperation();
  navigationVersion += 1;
  if (activeView !== view) clearCommandResults();
  if (activeView === "logs" && view !== "logs") {
    logsViewer.following = false;
    await stopLogViewer(logsViewer, "paused");
  }
  if (activeView === "docker" && view !== "docker") clearContainerLogs();
  activeView = view;
  if (activeWorkspaceTabId) serverTabViews.set(activeWorkspaceTabId, view);
  errorMessage = "";
  clearRefreshTimer();
  const reuseDashboardSnapshot = view === "dashboard" && dashboard !== null;
  const reuseContainerSnapshot = view === "docker" && (containerPlatformTab === "compose"
    ? composeProjectsServerId === activeServerId
    : dockerLoaded[dockerTab]);
  viewTransition = view === "terminal" || reuseDashboardSnapshot || reuseContainerSnapshot ? null : { serverId: activeServerId, view, version: navigationVersion };
  render();
  if (view === "terminal") {
    if (!activeTerminalTabs().length) await openNewTerminal();
    return;
  }
  await loadActiveView(!reuseDashboardSnapshot && !reuseContainerSnapshot);
}

async function loadActiveView(showTransition = false, forceRefresh = false): Promise<void> {
  if (!activeServerId || activeView === "terminal") { render(); return; }
  const serverId = activeServerId;
  const view = activeView;
  const version = navigationVersion;
  if (showTransition) viewTransition = { serverId, view, version };
  errorMessage = ""; clearRefreshTimer(); render();
  try {
    switch (view) {
      case "dashboard": {
        if (!dashboard || forceRefresh) await loadDashboard(serverId, version);
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        break;
      }
      case "processes": {
        const nextProcesses = await invokeCommand<Page<ProcessInfo>>("get_processes", { serverId, offset: 0, limit: Math.max(PROCESS_PAGE_SIZE, processes.length) });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        processes = nextProcesses.items; processesHasMore = nextProcesses.hasMore; refreshTimer = window.setInterval(() => { if (!activeOperation) void loadActiveView(); }, 5_000); break;
      }
      case "services": {
        const nextServices = await invokeCommand<Page<ServiceInfo>>("get_services", { serverId, offset: 0, limit: Math.max(SERVICE_PAGE_SIZE, services.length) });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        services = nextServices.items; servicesHasMore = nextServices.hasMore; break;
      }
      case "disk": {
        const nextSnapshot = await invokeCommand<DiskExplorerSnapshot>("get_disk_snapshot", { serverId });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        diskSnapshot = nextSnapshot;
        if (!nextSnapshot.dockerUsage && diskTab === "docker") diskTab = "mounts";
        diskVarLog = null;
        diskVarLogLoading = false;
        break;
      }
      case "files": await loadFiles(serverId, version); break;
      case "docker": {
        if (containerPlatformTab === "compose" && (forceRefresh || composeProjectsServerId !== serverId)) {
          composeProjects = await invokeCommand<ComposeProject[]>("get_compose_projects", { serverId });
          composeProjectsServerId = serverId;
        }
        else if (containerPlatformTab === "runtime" && (forceRefresh || !dockerLoaded[dockerTab])) {
          await loadDockerSection(false, serverId, version);
        }
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        break;
      }
      case "logs": {
        const capabilities = activeCapabilities();
        if (logsViewer.target.source === "system" && !capabilities?.journalctl && !capabilities?.logread) {
          logsViewer = createLogViewer({ source: "file", label: "/var/log/", filePath: "/var/log/" }, logsViewer.lines);
        }
        updateLogTargetLabel(logsViewer);
        if (logsViewer.target.source === "container" || (logsViewer.target.source === "file" && Boolean(capabilities?.docker || capabilities?.podman))) {
          await ensureDockerContainersForLogs(serverId, version);
        }
        if (logsViewer.target.source === "file") await loadLogFileChoices(serverId, version);
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        await loadLogViewer(logsViewer, "workspace", false);
        break;
      }
      case "network": {
        const nextPorts = await invokeCommand<Page<import("./types").PortInfo>>("get_ports", { serverId, offset: 0, limit: Math.max(PORT_PAGE_SIZE, ports.length) });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        ports = nextPorts.items; portsHaveMore = nextPorts.hasMore; refreshTimer = window.setInterval(() => { if (!activeOperation) void loadActiveView(); }, 8_000); break;
      }
      case "cron": {
        const next = await invokeCommand<CronJob[]>("get_cron_jobs", { serverId });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        cronJobs = next; break;
      }
      case "packages": {
        const next = await invokeCommand<PackagePage>("get_packages", { serverId, query: packageQuery, upgradesOnly: packageUpgradesOnly, offset: 0, limit: Math.max(100, packagePage?.packages.items.length ?? 0) });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        packagePage = next; break;
      }
      case "accounts": {
        const next = await invokeCommand<AccountSnapshot>("get_accounts", { serverId });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        accounts = next; break;
      }
      case "administration": await loadAdministrationTab(serverId, version); break;
      case "commands": {
        const nextCommands = await invokeCommand<SavedCommand[]>("get_saved_commands", { serverId });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        savedCommands = nextCommands;
        break;
      }
      case "tunnels": {
        tunnels = await invokeCommand<TunnelConfig[]>("get_tunnels", { serverId });
        tunnelStatuses = await invokeCommand<TunnelStatus[]>("get_tunnel_statuses", { serverId });
        break;
      }
    }
  } catch (error) {
    if (!(error instanceof OperationCancelledError) && !errorText(error).toLowerCase().includes("operation cancelled") && viewRequestIsCurrent(serverId, view, version)) {
      errorMessage = errorText(error);
    }
  } finally {
    if (viewTransition?.serverId === serverId && viewTransition.view === view && viewTransition.version === version) viewTransition = null;
    if (viewRequestIsCurrent(serverId, view, version)) render();
  }
}

async function loadAdministrationTab(expectedServerId = activeServerId, expectedVersion = navigationVersion): Promise<void> {
  if (!expectedServerId) return;
  try {
    if (administrationTab === "firewall") firewallSnapshot = await invokeCommand<FirewallSnapshot>("get_firewall", { serverId: expectedServerId });
    else if (administrationTab === "keys") authorizedKeys = await invokeCommand<AuthorizedKey[]>("get_authorized_keys", { serverId: expectedServerId });
    else if (administrationTab === "security") securitySnapshot = await invokeCommand<SecuritySnapshot>("get_security_snapshot", { serverId: expectedServerId });
    if (viewRequestIsCurrent(expectedServerId, "administration", expectedVersion)) render();
  } catch (error) { if (viewRequestIsCurrent(expectedServerId, "administration", expectedVersion)) setError(error); }
}

const dashboardCardOrder: DashboardCardName[] = ["profile", "memory", "storage", "uptime", "network", "cpu"];

async function loadDashboard(serverId: string, version: number): Promise<void> {
  if (!connection) {
    const connected = await invokeCommand<ServerConnection>("connect_server", { serverId });
    if (!viewRequestIsCurrent(serverId, "dashboard", version)) return;
    connection = connected;
    connectedServerIds.add(serverId);
  }
  if (!viewRequestIsCurrent(serverId, "dashboard", version)) return;

  const targetDashboard: DashboardState = { errors: {}, loading: true };
  dashboard = targetDashboard;
  if (activeWorkspaceTabId) dashboardSnapshots.set(activeWorkspaceTabId, targetDashboard);
  if (viewTransition?.serverId === serverId && viewTransition.view === "dashboard" && viewTransition.version === version) {
    viewTransition = null;
  }
  render();

  try {
    const cards = await invokeDashboard(serverId);
    if (!viewRequestIsCurrent(serverId, "dashboard", version) || dashboard !== targetDashboard) return;
    for (const card of cards) applyDashboardCard(card);
  } catch (error) {
    if (error instanceof OperationCancelledError || errorText(error).toLowerCase().includes("operation cancelled")) throw error;
    if (!viewRequestIsCurrent(serverId, "dashboard", version) || dashboard !== targetDashboard) return;
    for (const cardName of dashboardCardOrder) targetDashboard.errors[cardName] = errorText(error);
    throw error;
  } finally {
    if (viewRequestIsCurrent(serverId, "dashboard", version) && dashboard === targetDashboard) {
      targetDashboard.loading = false;
      render();
    }
  }
}

async function invokeDashboard(serverId: string): Promise<DashboardCard[]> {
  let timedOut = false;
  const request = invokeCommand<DashboardCard[]>("get_dashboard", { serverId });
  const operationId = activeOperation?.id;
  const timeout = window.setTimeout(() => {
    if (!operationId || activeOperation?.id !== operationId) return;
    timedOut = true;
    cancelCurrentOperation(operationId);
  }, DASHBOARD_OVERVIEW_TIMEOUT_MS);
  try {
    return await request;
  } catch (error) {
    if (timedOut) throw new Error("The server overview took too long to load.");
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

function applyDashboardCard(card: DashboardCard): void {
  if (!dashboard) return;
  switch (card.kind) {
    case "profile": dashboard.profile = card.summary; break;
    case "cpu": dashboard.cpu = card; break;
    case "memory": dashboard.memory = card; break;
    case "storage": dashboard.storage = card; break;
    case "uptime": dashboard.uptime = card; break;
    case "network": dashboard.network = card; break;
  }
}

async function loadFiles(expectedServerId = activeServerId, expectedVersion = navigationVersion, append = false): Promise<void> {
  if (!expectedServerId) return;
  const offset = append ? remoteFiles.length : 0;
  const limit = append ? FILE_PAGE_SIZE : Math.max(FILE_PAGE_SIZE, remoteFiles.length);
  const files = await invokeCommand<Page<RemoteFile>>("list_remote_files", { serverId: expectedServerId, request: { path: remotePath, showHidden, offset, limit } });
  if (!viewRequestIsCurrent(expectedServerId, "files", expectedVersion)) return;
  if (append) {
    const loadedPaths = new Set(remoteFiles.map((file) => file.path));
    remoteFiles = [...remoteFiles, ...files.items.filter((file) => !loadedPaths.has(file.path))];
  } else {
    remoteFiles = files.items;
  }
  filesHaveMore = files.hasMore;
  render();
}

function mergeDockerPage(next: DockerPage): void {
  const current = docker ?? { runtime: next.runtime, containers: [], images: [], volumes: [], networks: [] };
  switch (next.section) {
    case "containers": current.containers = next.containers; break;
    case "images": current.images = next.images; break;
    case "volumes": current.volumes = next.volumes; break;
    case "networks": current.networks = next.networks; break;
  }
  current.runtime = next.runtime;
  docker = current;
  dockerLoaded[next.section] = true;
  dockerHasMore[next.section] = next.hasMore;
}

async function loadDockerSection(expand: boolean, expectedServerId = activeServerId, expectedVersion = navigationVersion): Promise<void> {
  if (!expectedServerId) return;
  const section = dockerTab;
  const loaded = docker?.[section].length ?? 0;
  const limit = expand ? loaded + DOCKER_PAGE_SIZE : Math.max(DOCKER_PAGE_SIZE, loaded);
  const next = await invokeCommand<DockerPage>("get_docker", { serverId: expectedServerId, section, offset: 0, limit });
  if (!viewRequestIsCurrent(expectedServerId, "docker", expectedVersion) || dockerTab !== section) return;
  mergeDockerPage(next);
  render();
}

async function selectDockerSection(section: DockerSection): Promise<void> {
  dockerTab = section;
  errorMessage = "";
  render();
  if (dockerLoaded[section]) return;
  try { await loadDockerSection(false); } catch (error) { setError(error); }
}

async function loadMoreActiveView(): Promise<void> {
  if (!activeServerId || activeOperation) return;
  const serverId = activeServerId;
  const view = activeView;
  const version = navigationVersion;
  try {
    switch (view) {
      case "processes": {
        const next = await invokeCommand<Page<ProcessInfo>>("get_processes", { serverId, offset: 0, limit: processes.length + PROCESS_PAGE_SIZE });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        processes = next.items; processesHasMore = next.hasMore; break;
      }
      case "services": {
        const next = await invokeCommand<Page<ServiceInfo>>("get_services", { serverId, offset: 0, limit: services.length + SERVICE_PAGE_SIZE });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        services = next.items; servicesHasMore = next.hasMore; break;
      }
      case "files": await loadFiles(serverId, version, true); return;
      case "docker": await loadDockerSection(true, serverId, version); return;
      case "network": {
        const next = await invokeCommand<Page<import("./types").PortInfo>>("get_ports", { serverId, offset: 0, limit: ports.length + PORT_PAGE_SIZE });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        ports = next.items; portsHaveMore = next.hasMore; break;
      }
      case "packages": {
        const loaded = packagePage?.packages.items.length ?? 0;
        const next = await invokeCommand<PackagePage>("get_packages", { serverId, query: packageQuery, upgradesOnly: packageUpgradesOnly, offset: 0, limit: loaded + 100 });
        if (!viewRequestIsCurrent(serverId, view, version)) return;
        packagePage = next; break;
      }
      default: return;
    }
    render();
  } catch (error) { setError(error); }
}

async function navigateFiles(path: string): Promise<void> {
  remotePath = path || "/"; remoteFileSearch = ""; remoteFiles = []; filesHaveMore = false; await loadActiveView(true);
}

async function openEditor(path: string): Promise<void> {
  if (!activeServerId) return;
  const serverId = activeServerId;
  const version = navigationVersion;
  render();
  try {
    const content = await invokeCommand<string>("read_remote_file", { serverId, path });
    if (activeServerId !== serverId || activeView !== "files" || navigationVersion !== version) return;
    editorPath = path; editorContent = content; editorDirty = false; modal = "editor"; render();
  } catch (error) { setError(error); }
}

async function saveEditorForm(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return;
  const content = String(new FormData(form).get("content") ?? editorContent);
  try {
    await invokeCommand("write_remote_file", { serverId: activeServerId, path: editorPath, content });
    editorContent = content; editorDirty = false; modal = null; await loadFiles();
  } catch (error) { setError(error); }
}

async function createFolder(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return;
  const name = String(new FormData(form).get("name") ?? "").trim();
  if (!/^[^/]+$/.test(name)) { errorMessage = "Folder name cannot contain a slash."; render(); return; }
  try {
    const path = `${remotePath.replace(/\/$/, "")}/${name}` || `/${name}`;
    await invokeCommand("remote_file_action", { serverId: activeServerId, action: "mkdir", path }); modal = null; await loadFiles();
  } catch (error) { setError(error); }
}

async function deleteRemote(path: string): Promise<void> {
  if (!activeServerId) return;
  const file = remoteFiles.find((item) => item.path === path);
  if (!await confirm(`Delete ${file?.name ?? path}? This cannot be undone remotely.`, { title: "Delete remote item", kind: "warning" })) return;
  try { await invokeCommand("remote_file_action", { serverId: activeServerId, action: "delete", path }); await loadFiles(); } catch (error) { setError(error); }
}

async function changeRemoteMode(path: string): Promise<void> {
  if (!activeServerId) return;
  const mode = await requestTextInput({ title: "Change permissions", label: "Permissions in octal", defaultValue: "644" });
  if (!mode) return;
  try { await invokeCommand("remote_file_action", { serverId: activeServerId, action: "chmod", path, mode }); await loadFiles(); } catch (error) { setError(error); }
}

async function changeRemoteOwner(path: string): Promise<void> {
  if (!activeServerId) return;
  const file = remoteFiles.find((item) => item.path === path);
  const owner = await requestTextInput({ title: "Change owner", label: "Owner as uid:gid", defaultValue: `${file?.uid ?? "0"}:${file?.gid ?? "0"}` });
  if (!owner) return;
  try { await invokeCommand("remote_file_action", { serverId: activeServerId, action: "chown", path, target: owner }); await loadFiles(); } catch (error) { setError(error); }
}

async function uploadLocal(): Promise<void> {
  if (!activeServerId) return;
  const selected = await requestTextInput({ title: "Upload a local file", label: "Absolute local file path", defaultValue: "", placeholder: platform === "windows" ? "C:\\Users\\name\\Desktop\\archive.tar.gz" : "~/Desktop/archive.tar.gz" });
  if (selected?.trim()) await transferUpload(selected.trim());
}

async function uploadLocalFolder(): Promise<void> {
  if (!activeServerId) return;
  const selected = await requestTextInput({ title: "Upload a local folder", label: "Absolute local folder path", defaultValue: "", placeholder: platform === "windows" ? "C:\\Users\\name\\Desktop\\project" : "~/Desktop/project" });
  if (selected?.trim()) await transferUpload(selected.trim());
}

async function transferUpload(localPath: string): Promise<void> {
  if (!activeServerId) return;
  transfer = { transferId: "pending", direction: "upload", path: localPath, completedBytes: 0, totalBytes: 0, completedFiles: 0, totalFiles: 0, done: false };
  syncTransferToast();
  try {
    transfer = await invokeCommand<TransferProgress>("upload_path", { serverId: activeServerId, localPath, remotePath, overwrite: false });
    await loadFiles();
  } catch (error) {
    const conflict = error !== null && typeof error === "object" && (error as { kind?: unknown }).kind === "uploadConflict"
      ? error as { paths?: unknown; count?: unknown }
      : null;
    if (conflict) {
      const paths = Array.isArray(conflict.paths) ? conflict.paths.filter((path): path is string => typeof path === "string") : [];
      const count = typeof conflict.count === "number" ? conflict.count : paths.length;
      const listed = paths.map((path) => `• ${path}`).join("\n");
      const remaining = count > paths.length ? `\n…and ${count - paths.length} more.` : "";
      if (await confirm(`${count} remote ${count === 1 ? "file already exists" : "files already exist"}. Replace ${count === 1 ? "it" : "them"}?\n${listed}${remaining}`, { title: "Replace remote files?", kind: "warning" })) {
        try {
          transfer = await invokeCommand<TransferProgress>("upload_path", { serverId: activeServerId, localPath, remotePath, overwrite: true });
          await loadFiles();
        } catch (retryError) {
          transfer = { ...transfer, done: true, error: errorText(retryError) };
          setError(retryError);
        }
      } else {
        transfer = null;
      }
    } else {
      transfer = { ...transfer, done: true, error: errorText(error) };
      setError(error);
    }
  }
  if (transfer?.done) {
    syncTransferToast();
    dismissTransferToast(transfer.transferId);
  }
}

async function downloadRemote(path: string): Promise<void> {
  if (!activeServerId) return;
  const file = remoteFiles.find((item) => item.path === path);
  const directory = file?.kind === "directory";
  const localPath = await requestTextInput({
    title: directory ? "Download remote folder" : "Download remote file",
    label: directory ? "Local destination folder" : "Local destination file",
    defaultValue: directory ? "~/Downloads" : `~/Downloads/${file?.name ?? "download"}`,
    placeholder: platform === "windows" ? "C:\\Users\\name\\Downloads" : "~/Downloads",
  });
  if (!localPath?.trim()) return;
  try {
    transfer = await invokeCommand<TransferProgress>("download_path", { serverId: activeServerId, remotePath: path, localPath: localPath.trim() });
    syncTransferToast();
    dismissTransferToast(transfer.transferId);
  } catch (error) { setError(error); }
}

function cancelTransfer(): void {
  if (!transfer || transfer.done) return;
  cancelCurrentOperation();
}

async function runProcessAction(pid: number, force: boolean): Promise<void> {
  if (!activeServerId) return;
  try { await invokeCommand("signal_process", { serverId: activeServerId, pid, force }); await loadActiveView(); } catch (error) { setError(error); }
}

async function openServiceDetails(service: string): Promise<void> {
  if (!activeServerId) return;
  modal = "service"; serviceDetails = null; render();
  try { serviceDetails = await invokeCommand<ServiceDetails>("get_service_details", { serverId: activeServerId, service }); render(); } catch (error) { setError(error); }
}

async function runServiceAction(action: string, service: string): Promise<void> {
  if (!activeServerId || !service) return;
  if (["stop", "disable"].includes(action) && !await confirm(`${action[0].toUpperCase() + action.slice(1)} ${service}?`, { title: "Confirm service action", kind: "warning" })) return;
  try { await invokeCommand("service_action", { serverId: activeServerId, service, action }); await loadActiveView(); if (modal === "service") await openServiceDetails(service); } catch (error) { setError(error); }
}

async function dockerAction(action: string, target: string): Promise<void> {
  if (!activeServerId) return;
  if (["rm", "rmi", "volume-rm", "network-rm"].includes(action) && !await confirm(`Run ${action} on ${target}?`, { title: "Confirm container action", kind: "warning" })) return;
  try { await invokeCommand("docker_action", { serverId: activeServerId, action, target }); await loadActiveView(false, true); } catch (error) { setError(error); }
}

async function createDockerResource(action: "volume-create" | "network-create", label: string): Promise<void> {
  const name = await requestTextInput({ title: `Create ${label}`, label: `${label[0].toUpperCase() + label.slice(1)} name`, defaultValue: "" });
  if (!name || !activeServerId) return;
  try { await invokeCommand("docker_action", { serverId: activeServerId, action, target: name.trim() }); await loadActiveView(false, true); } catch (error) { setError(error); }
}

async function loadDockerLogs(container: string): Promise<void> {
  await openContainerLogs({ source: "container", label: container, container });
}

async function openComposeLogs(path: string, label: string): Promise<void> {
  await openContainerLogs({ source: "compose", label, composePath: path });
}

async function openContainerLogs(target: LogTarget): Promise<void> {
  if (!activeServerId) return;
  cancelCurrentOperation();
  navigationVersion += 1;
  clearRefreshTimer();
  clearCommandResults();
  if (containerLogViewer) await stopLogViewer(containerLogViewer, "idle");
  containerLogViewer = createLogViewer(target, 300);
  shouldScrollToContainerLogs = true;
  render();
  await loadLogViewer(containerLogViewer, "container", false);
}

function containerLogBelongsToActiveTab(): boolean {
  return Boolean(containerLogViewer && ((containerPlatformTab === "compose" && containerLogViewer.target.source === "compose") || (containerPlatformTab === "runtime" && containerLogViewer.target.source === "container")));
}

async function ensureDockerContainersForLogs(expectedServerId: string, expectedVersion: number): Promise<void> {
  if (!viewRequestIsCurrent(expectedServerId, "logs", expectedVersion)) return;
  if (!dockerLoaded.containers || !docker) {
    const next = await invokeCommand<DockerPage>("get_docker", { serverId: expectedServerId, section: "containers", offset: 0, limit: DOCKER_PAGE_SIZE });
    if (!viewRequestIsCurrent(expectedServerId, "logs", expectedVersion)) return;
    mergeDockerPage(next);
  }
  while (dockerHasMore.containers) {
    const loaded = docker?.containers.length ?? 0;
    const next = await invokeCommand<DockerPage>("get_docker", { serverId: expectedServerId, section: "containers", offset: loaded, limit: DOCKER_PAGE_SIZE });
    if (!viewRequestIsCurrent(expectedServerId, "logs", expectedVersion)) return;
    if (!next.containers.length) {
      dockerHasMore.containers = false;
      break;
    }
    if (docker) docker.containers = [...docker.containers, ...next.containers];
    dockerHasMore.containers = next.hasMore;
  }
  if (!viewRequestIsCurrent(expectedServerId, "logs", expectedVersion)) return;
  const available = docker?.containers.map((container) => container.name || container.id) ?? [];
  if (logsViewer.target.source === "container" && !available.includes(logsViewer.target.container ?? "")) {
    logsViewer.target.container = available[0];
    updateLogTargetLabel(logsViewer);
  }
}

async function openDockerTerminal(container: string): Promise<void> {
  const runtime = docker?.runtime;
  if (runtime !== "docker" && runtime !== "podman") {
    setError("Could not determine the container runtime. Refresh the Containers view and try again.");
    return;
  }
  const target = docker?.containers.find((item) => item.id === container || item.name === container);
  if (target?.state.trim().toLowerCase() !== "running") {
    showToast("Start the container before opening an exec shell.", "info");
    return;
  }
  try {
    const exec = await invokeCommand<ContainerExec>("container_exec", { serverId: activeServerId, container });
    navigationVersion += 1;
    activeView = "terminal";
    clearRefreshTimer();
    render();
    await openNewTerminal(exec.command, `${exec.shell} · ${shortId(container)}`);
  } catch (error) {
    setError(error);
  }
}

async function openInspect(target: string, kind: string): Promise<void> {
  if (!activeServerId) return;
  modal = "inspect"; inspectText = "Loading…"; render();
  try { inspectText = await invokeCommand<string>("docker_inspect", { serverId: activeServerId, target, kind }); render(); } catch (error) { setError(error); }
}

async function pullDockerImage(): Promise<void> {
  const image = await requestTextInput({ title: "Pull image", label: "Image name and tag", defaultValue: "nginx:latest" });
  if (!image || !activeServerId) return;
  render();
  try { await invokeCommand("docker_pull", { serverId: activeServerId, image }); await loadActiveView(false, true); } catch (error) { setError(error); }
}

async function createDocker(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return;
  const data = new FormData(form);
  const lines = (key: string) => String(data.get(key) ?? "").split("\n").map((value) => value.trim()).filter(Boolean);
  const input = { image: String(data.get("image") ?? ""), name: String(data.get("name") ?? "") || undefined, command: String(data.get("command") ?? "") || undefined, ports: lines("ports"), environment: lines("environment"), volumes: lines("volumes"), networks: lines("networks"), restartPolicy: String(data.get("restartPolicy") ?? "no"), detached: data.get("detached") === "on", removeOnExit: data.get("removeOnExit") === "on", memoryLimit: String(data.get("memoryLimit") ?? "") || undefined, cpuLimit: String(data.get("cpuLimit") ?? "") || undefined };
  try { await invokeCommand("docker_create", { serverId: activeServerId, input }); modal = null; await loadActiveView(false, true); } catch (error) { setError(error); }
}

function logViewerForScope(scope?: string): LogViewerState | null {
  return scope === "container" ? containerLogViewer : logsViewer;
}

function logRequest(viewer: LogViewerState): Record<string, unknown> {
  const common = {
    lines: viewer.lines,
    since: viewer.since || undefined,
    query: undefined,
    severity: undefined,
  };
  switch (viewer.target.source) {
    case "container": return { ...common, source: "container", container: viewer.target.container };
    case "compose": return { ...common, source: "compose", composePath: viewer.target.composePath, service: viewer.target.service };
    case "file": return { ...common, source: "file", filePath: viewer.target.filePath, container: viewer.target.container };
    case "system": return { ...common, source: "system", service: viewer.target.service };
  }
}

function logViewerIsCurrent(viewer: LogViewerState, scope: "workspace" | "container", serverId = activeServerId): boolean {
  if (!serverId || activeServerId !== serverId) return false;
  return scope === "workspace" ? activeView === "logs" && logsViewer === viewer : activeView === "docker" && containerLogViewer === viewer && containerLogBelongsToActiveTab();
}

async function loadLogViewer(viewer: LogViewerState, scope: "workspace" | "container", keepBusy = true): Promise<void> {
  if (viewer.following) {
    await startLogFollowing(viewer, scope);
    return;
  }
  await loadLogSnapshot(viewer, scope, keepBusy);
}

async function loadLogSnapshot(viewer: LogViewerState, scope: "workspace" | "container", keepBusy = true): Promise<void> {
  const serverId = activeServerId;
  if (!serverId || !logViewerIsCurrent(viewer, scope, serverId)) return;
  if (keepBusy) {
    viewer.status = "loading";
    errorMessage = "";
    render();
  }
  try {
    const nextLogs = await invokeCommand<string>("get_logs", { serverId, request: logRequest(viewer) });
    if (!logViewerIsCurrent(viewer, scope, serverId)) return;
    viewer.text = normalizeLogOutput(nextLogs);
    viewer.status = viewer.following ? "polling" : "idle";
    render();
  } catch (error) {
    if (!logViewerIsCurrent(viewer, scope, serverId)) return;
    viewer.following = false;
    viewer.status = "stopped";
    setError(error);
  }
}

function logSourceCanStream(viewer: LogViewerState): boolean {
  return viewer.target.source !== "system" || Boolean(activeCapabilities()?.journalctl);
}

async function setLogFollowing(viewer: LogViewerState, scope: "workspace" | "container"): Promise<void> {
  if (!viewer.following) {
    await stopLogViewer(viewer, "paused");
    render();
    return;
  }
  await startLogFollowing(viewer, scope);
}

async function startLogFollowing(viewer: LogViewerState, scope: "workspace" | "container"): Promise<void> {
  const serverId = activeServerId;
  if (!serverId || !logViewerIsCurrent(viewer, scope, serverId)) return;
  await stopLogViewer(viewer, "loading");
  viewer.following = true;
  viewer.status = "loading";
  errorMessage = "";
  render();
  if (!logSourceCanStream(viewer)) {
    await loadLogSnapshot(viewer, scope, false);
    if (!viewer.following || !logViewerIsCurrent(viewer, scope, serverId)) return;
    viewer.status = "polling";
    render();
    clearRefreshTimer();
    refreshTimer = window.setInterval(() => { if (!activeOperation) void loadLogSnapshot(viewer, scope, false); }, 2_500);
    return;
  }
  const sessionId = crypto.randomUUID();
  viewer.streamId = sessionId;
  try {
    const request = { ...logRequest(viewer), lines: viewer.text ? 0 : viewer.lines };
    await invokeCommand<LogStreamStarted>("start_log_stream", { request: { sessionId, serverId, logs: request } });
    if (!logViewerIsCurrent(viewer, scope, serverId) || viewer.streamId !== sessionId) {
      await invoke("close_log_stream", { sessionId }).catch(() => undefined);
      return;
    }
    viewer.status = "live";
    render();
  } catch (error) {
    if (viewer.streamId === sessionId) viewer.streamId = undefined;
    viewer.following = false;
    viewer.status = "stopped";
    setError(error);
  }
}

async function stopLogViewer(viewer: LogViewerState, status: LogViewerState["status"]): Promise<void> {
  const sessionId = viewer.streamId;
  viewer.streamId = undefined;
  viewer.status = status;
  if (sessionId) await invoke("close_log_stream", { sessionId }).catch(() => undefined);
  clearRefreshTimer();
}

function updateLogTargetLabel(viewer: LogViewerState): void {
  const target = viewer.target;
  if (target.source === "system") target.label = target.service || (activeCapabilities()?.journalctl ? "System journal" : "Syslog buffer");
  else if (target.source === "container") target.label = target.container || "Container logs";
  else if (target.source === "file") target.label = target.filePath || "Log file";
}

function appendLogOutput(viewer: LogViewerState, data: string, scope: "workspace" | "container"): void {
  viewer.text += normalizeLogOutput(data);
  if (viewer.text.length > 1_048_576) {
    const start = viewer.text.indexOf("\n", viewer.text.length - 1_048_576);
    viewer.text = viewer.text.slice(start >= 0 ? start + 1 : viewer.text.length - 1_048_576);
  }
  updateLogViewerDom(viewer, scope, true);
}

function updateLogViewerDom(viewer: LogViewerState, scope: "workspace" | "container", preserveLiveEdge = false): void {
  const output = root.querySelector<HTMLElement>(`[data-log-output="${scope}"]`);
  if (output) {
    const atLiveEdge = output.scrollHeight - output.scrollTop - output.clientHeight < 48;
    output.textContent = filteredLogs(viewer);
    if (preserveLiveEdge && atLiveEdge) output.scrollTop = output.scrollHeight;
  }
  const count = root.querySelector<HTMLElement>(`[data-log-count="${scope}"]`);
  if (count) {
    const lines = countLogLines(viewer.text);
    count.textContent = `${lines} ${lines === 1 ? "line" : "lines"}`;
  }
}

async function loadLogFileChoices(serverId: string, version: number): Promise<void> {
  try {
    const files = await invokeCommand<string[]>("get_log_files", { serverId });
    if (viewRequestIsCurrent(serverId, "logs", version) && logsViewer.target.source === "file") {
      discoveredLogFiles = files;
      if ((!logsViewer.target.filePath || logsViewer.target.filePath.endsWith("/")) && files[0]) {
        logsViewer.target.filePath = files[0];
        updateLogTargetLabel(logsViewer);
      }
    }
  } catch {
    discoveredLogFiles = [];
  }
}

async function copyText(value: string): Promise<void> {
  if (!value) return;
  try { await navigator.clipboard.writeText(value); showToast("Copied to the clipboard."); } catch (error) { setError(error); }
}

async function runComposeAction(path: string, action: string): Promise<void> {
  if (!activeServerId) return;
  const project = composeProjects.find((item) => item.path === path);
  if (action === "logs") {
    await openComposeLogs(path, project?.name ?? path);
    return;
  }
  if (action === "scale") {
    if (!project?.services.length) {
      setError("No Compose services are available to scale");
      return;
    }
    composeScaleProject = project;
    modal = "compose-scale";
    render();
    return;
  }
  let service: string | undefined; let command: string | undefined;
  if (action === "exec" && !project?.services.length) {
    setError("No Compose services are available for exec");
    return;
  }
  if (action === "exec" && (!project || project.running === 0)) {
    showToast("Start a Compose service before running a command.", "info");
    return;
  }
  if (["restart", "exec"].includes(action) && project?.services.length) {
    const selectedService = await requestTextInput({ title: action === "exec" ? "Run command in Compose service" : "Restart Compose service", label: "Service", defaultValue: project.services[0], allowEmpty: action === "restart", choices: project.services });
    if (selectedService === null) return;
    service = selectedService || undefined;
  }
  if (action === "exec") {
    const enteredCommand = await requestTextInput({ title: "Run command in Compose service", label: `Command for ${service}`, defaultValue: "id && pwd", multiline: true });
    if (enteredCommand === null || !enteredCommand.trim()) return;
    command = enteredCommand.trim();
  }
  if (["down", "rebuild"].includes(action) && !await confirm(`${action} ${project?.name ?? path}?`, { title: "Confirm Compose action", kind: "warning" })) return;
  try {
    const output = await invokeCommand<string>("compose_action", { serverId: activeServerId, path, action, service, command, lines: undefined, since: undefined });
    if (action === "exec") setCommandResults([{ serverId: activeServerId, serverName: project?.name ?? "Compose", stdout: output, stderr: "", exitCode: 0 }], false);
    composeProjectsServerId = null;
    await loadActiveView();
    if (action === "exec" && activeView === "docker" && containerPlatformTab === "compose") {
      shouldScrollToCommandResults = true;
      render();
    }
  } catch (error) {
    if (action === "exec" && /(?:service|container).*not running/i.test(errorText(error))) {
      showToast(`Start ${service ?? "the selected service"} before running a command.`, "info");
      return;
    }
    if (action === "exec" && !(error instanceof OperationCancelledError) && !errorText(error).toLowerCase().includes("operation cancelled")) {
      setCommandResults([{
        serverId: activeServerId,
        serverName: project?.name ?? "Compose",
        stdout: "",
        stderr: "",
        exitCode: 1,
        error: errorText(error),
      }]);
      render();
      return;
    }
    setError(error);
  }
}

async function submitComposeScaleForm(form: HTMLFormElement): Promise<void> {
  if (!activeServerId || !composeScaleProject) return;
  const project = composeScaleProject;
  const data = new FormData(form);
  const service = String(data.get("service") ?? "").trim();
  const replicas = String(data.get("replicas") ?? "").trim();
  if (!project.services.includes(service) || !/^\d+$/.test(replicas)) return;
  try {
    await invokeCommand<string>("compose_action", { serverId: activeServerId, path: project.path, action: "scale", service: undefined, command: `${service}=${replicas}`, lines: undefined, since: undefined });
    modal = null;
    composeScaleProject = null;
    composeProjectsServerId = null;
    await loadActiveView();
  } catch (error) { setError(error); }
}

async function runFirewallAction(action: string, port?: number, protocol?: string, source?: string): Promise<void> {
  if (!activeServerId) return;
  if (["disable", "deny"].includes(action) && !await confirm("This firewall change may block SSH access. Continue only if the current SSH port remains allowed.", { title: "Possible SSH lockout", kind: "warning" })) return;
  try { await invokeCommand("firewall_action", { serverId: activeServerId, action, port, protocol, source: source || undefined }); await loadAdministrationTab(); } catch (error) { setError(error); }
}

async function submitFirewallForm(form: HTMLFormElement, submitter: HTMLButtonElement | null): Promise<void> {
  const data = new FormData(form); await runFirewallAction(submitter?.value || "allow", Number(data.get("port")), String(data.get("protocol") ?? "tcp"), String(data.get("source") ?? "").trim());
}

async function addAuthorizedKey(): Promise<void> {
  if (!activeServerId) return; const key = await requestTextInput({ title: "Add authorized key", label: "OpenSSH public key", defaultValue: "", multiline: true, placeholder: "ssh-ed25519 AAAA…" }); if (!key) return;
  try { await invokeCommand("authorized_key_action", { serverId: activeServerId, action: "add", key: key.trim() }); await loadAdministrationTab(); } catch (error) { setError(error); }
}

async function removeAuthorizedKey(id: string): Promise<void> {
  if (!activeServerId) return; const key = authorizedKeys.find((item) => item.id === id); if (!key || !await confirm(`Remove ${key.fingerprint}? Make sure another login method works first.`, { title: "Remove authorized key", kind: "warning" })) return;
  try { await invokeCommand("authorized_key_action", { serverId: activeServerId, action: "remove", key: key.key }); await loadAdministrationTab(); } catch (error) { setError(error); }
}

async function runQuickAction(action: string): Promise<void> {
  if (!activeServerId) return;
  if (["reboot", "shutdown", "restart-ssh", "clear-cache"].includes(action) && !await confirm(`Run ${action.replaceAll("-", " ")} on ${activeServer()?.name}?`, { title: "Confirm server action", kind: "warning" })) return;
  try { const output = await invokeCommand<string>("run_quick_action", { serverId: activeServerId, action }); setCommandResults([{ serverId: activeServerId, serverName: activeServer()?.name ?? "Server", stdout: output, stderr: "", exitCode: 0 }]); render(); } catch (error) { setError(error); }
}

async function saveCommandForm(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return; const data = new FormData(form);
  try { await invokeCommand("save_saved_command", { input: { id: editingCommand?.id, serverId: data.get("global") === "on" ? undefined : activeServerId, name: String(data.get("name") ?? ""), command: String(data.get("command") ?? "") } }); modal = null; editingCommand = null; await loadActiveView(); } catch (error) { setError(error); }
}

async function runSavedCommand(id: string): Promise<void> {
  if (!activeServerId) return; const item = savedCommands.find((command) => command.id === id); if (!item) return;
  try { setCommandResults([await invokeCommand<CommandResult>("run_saved_command", { serverId: activeServerId, command: item.command })]); render(); } catch (error) { setError(error); }
}

async function deleteSavedCommand(id: string): Promise<void> {
  const item = savedCommands.find((command) => command.id === id); if (!item || !await confirm(`Delete “${item.name}”?`, { title: "Delete saved command", kind: "warning" })) return;
  try { await invokeCommand("delete_saved_command", { id }); await loadActiveView(); } catch (error) { setError(error); }
}

async function saveTunnelForm(form: HTMLFormElement): Promise<void> {
  if (!activeServerId) return; const data = new FormData(form);
  const input = { id: editingTunnel?.id, serverId: activeServerId, name: String(data.get("name") ?? ""), kind: String(data.get("kind") ?? "local"), bindHost: String(data.get("bindHost") ?? "127.0.0.1"), bindPort: Number(data.get("bindPort")), targetHost: String(data.get("targetHost") ?? ""), targetPort: Number(data.get("targetPort") || 1) };
  if (!["127.0.0.1", "::1", "localhost"].includes(input.bindHost) && !await confirm(`Binding to ${input.bindHost} may expose this tunnel to other machines. Continue?`, { title: "Public tunnel binding", kind: "warning" })) return;
  try { if (editingTunnel && tunnelStatuses.find((status) => status.id === editingTunnel?.id)?.running) await invokeCommand("stop_tunnel", { id: editingTunnel.id }); await invokeCommand("save_tunnel", { input }); modal = null; editingTunnel = null; await loadActiveView(); } catch (error) { setError(error); }
}

async function toggleTunnel(id: string, running: boolean): Promise<void> {
  try { await invokeCommand(running ? "stop_tunnel" : "start_tunnel", { id }); await new Promise((resolve) => window.setTimeout(resolve, 120)); await loadActiveView(); } catch (error) { setError(error); }
}

async function deleteTunnel(id: string): Promise<void> {
  if (!await confirm("Delete this saved tunnel?", { title: "Delete tunnel", kind: "warning" })) return;
  try { await invokeCommand("stop_tunnel", { id }); await invokeCommand("delete_tunnel", { id }); await loadActiveView(); } catch (error) { setError(error); }
}

function closeModal(): void {
  if (finishAppDialogWaiter) {
    finishAppDialog(false);
    return;
  }
  if (modal === "master-password" && masterPasswordWaiter) {
    finishMasterPasswordPrompt(null);
    return;
  }
  if (modal === "host-key" && hostKeyWaiter) {
    finishHostKeyPrompt(false);
    return;
  }
  if (modal === "input-prompt" && finishTextInputWaiter) {
    finishTextInput(null);
    return;
  }
  modal = null;
  composeScaleProject = null;
  renamingWorkspaceTabId = null;
  serviceDetails = null;
  inspectText = "";
  credentialSettingsError = "";
  credentialSettingsNotice = "";
  render();
}

async function openNewTerminal(command?: string, title?: string): Promise<void> {
  if (!activeServerId || !activeWorkspaceTabId) return;
  const serverId = activeServerId;
  const workspaceTabId = activeWorkspaceTabId;
  const number = activeTerminalTabs().length + 1;
  const cols = terminal?.cols ?? 110;
  const rows = terminal?.rows ?? 28;
  const tab: TerminalTab = { id: crypto.randomUUID(), serverId, workspaceTabId, title: title ?? `session ${number}`, command, buffer: "", connecting: true, cols, rows };
  tab.sessionId = tab.id;
  terminalTabs.push(tab); activeTerminalTabId = tab.id; activeTerminalTabByWorkspace.set(workspaceTabId, tab.id); activeView = "terminal"; render();
  try {
    const started = await invokeCommand<TerminalStarted>("start_terminal", { request: { sessionId: tab.id, serverId, cols, rows, command } });
    tab.sessionId = started.sessionId; tab.connecting = false; connectedServerIds.add(serverId); render();
  } catch (error) {
    if (error instanceof OperationCancelledError || errorText(error).toLowerCase().includes("operation cancelled")) {
      terminalTabs = terminalTabs.filter((item) => item.id !== tab.id);
      if (activeTerminalTabId === tab.id) activeTerminalTabId = activeTerminalTabs().at(-1)?.id ?? null;
      render();
      return;
    }
    tab.connecting = false; tab.closed = true; tab.buffer += `\r\n[Unable to open terminal: ${errorText(error)}]\r\n`; setError(error);
  }
}

async function closeTerminal(tabId: string): Promise<void> {
  const tab = terminalTabs.find((item) => item.id === tabId);
  if (tab?.sessionId) await invokeCommand("close_terminal", { sessionId: tab.sessionId }).catch(() => undefined);
  terminalTabs = terminalTabs.filter((item) => item.id !== tabId);
  if (activeTerminalTabId === tabId) activeTerminalTabId = activeTerminalTabs().at(-1)?.id ?? null;
  if (activeWorkspaceTabId && activeTerminalTabId) activeTerminalTabByWorkspace.set(activeWorkspaceTabId, activeTerminalTabId);
  if (!activeTerminalTabs().length) { terminalMountTabId = null; terminal?.dispose(); terminal = null; fitAddon = null; serializeAddon = null; }
  render();
}

function clearActiveTerminal(): void {
  const tab = terminalTabs.find((item) => item.id === activeTerminalTabId);
  if (!tab) return;
  tab.buffer = "";
  terminal?.clear();
}

function captureMountedTerminal(): void {
  if (!terminal || !serializeAddon || !terminalMountTabId) return;
  const tab = terminalTabs.find((item) => item.id === terminalMountTabId);
  if (!tab) return;
  tab.buffer = serializeAddon.serialize({ scrollback: 5000 });
  tab.cols = terminal.cols;
  tab.rows = terminal.rows;
}

function queueTerminalInput(sessionId: string, data: string): void {
  const previous = terminalInputChains.get(sessionId) ?? Promise.resolve();
  const next = previous
    .then(() => invokeCommand("terminal_input", { sessionId, data }))
    .then(() => undefined)
    .catch(() => undefined);
  terminalInputChains.set(sessionId, next);
  void next.then(() => {
    if (terminalInputChains.get(sessionId) === next) terminalInputChains.delete(sessionId);
  });
}

async function reconnectTerminal(): Promise<void> {
  const current = terminalTabs.find((tab) => tab.id === activeTerminalTabId);
  if (!current) return;
  const command = current.command;
  const title = current.title;
  const previousSessionId = current.sessionId;
  terminalTabs = terminalTabs.filter((tab) => tab.id !== current.id);
  terminalMountTabId = null;
  terminal?.dispose(); terminal = null; fitAddon = null; serializeAddon = null;
  if (previousSessionId) await invoke("close_terminal", { sessionId: previousSessionId }).catch(() => undefined);
  await openNewTerminal(command, title);
}

function mountTerminal(): void {
  const current = terminalTabs.find((tab) => tab.id === activeTerminalTabId);
  const surface = root.querySelector<HTMLElement>("[data-terminal-surface]");
  if (!current || !surface) return;
  if (terminal) { terminal.dispose(); terminal = null; fitAddon = null; serializeAddon = null; }
  terminalMountTabId = current.id;
  fitAddon = new FitAddon();
  serializeAddon = new SerializeAddon();
  terminal = new Terminal({
    cols: current.cols,
    rows: current.rows,
    cursorBlink: true,
    convertEol: false,
    fontFamily: "'SFMono-Regular', 'Cascadia Code', 'Roboto Mono', monospace",
    fontSize: 13,
    theme: { background: darkMode ? "#111412" : "#1f2521", foreground: "#e5ebe4", cursor: "#f1b986", selectionBackground: "#506b5a" },
    scrollback: 5000,
  });
  terminal.loadAddon(fitAddon);
  terminal.loadAddon(serializeAddon);
  terminal.open(surface);
  terminal.onData((data) => {
    if (current.sessionId) queueTerminalInput(current.sessionId, data);
  });
  terminal.onResize(({ cols, rows }) => {
    if (current.sessionId) void invokeCommand("terminal_resize", { request: { sessionId: current.sessionId, cols, rows } }).catch(() => undefined);
  });
  if (current.buffer) terminal.write(current.buffer, () => fitAddon?.fit());
  else fitAddon.fit();
  surface.addEventListener("click", () => terminal?.focus());
  terminal.focus();
}

async function installEventListeners(): Promise<void> {
  terminalUnlisteners.push(await listen<TerminalEvent>("log-stream-output", (event) => {
    if (logsViewer.streamId === event.payload.sessionId) appendLogOutput(logsViewer, event.payload.data, "workspace");
    else if (containerLogViewer?.streamId === event.payload.sessionId) appendLogOutput(containerLogViewer, event.payload.data, "container");
  }));
  terminalUnlisteners.push(await listen<TerminalEvent>("log-stream-closed", (event) => {
    const viewer = logsViewer.streamId === event.payload.sessionId ? logsViewer : containerLogViewer?.streamId === event.payload.sessionId ? containerLogViewer : null;
    if (!viewer) return;
    viewer.streamId = undefined;
    viewer.following = false;
    viewer.status = "stopped";
    render();
  }));
  terminalUnlisteners.push(await listen<TerminalEvent>("terminal-output", (event) => {
    const tab = terminalTabs.find((item) => item.sessionId === event.payload.sessionId);
    if (!tab) return;
    tab.buffer = `${tab.buffer}${event.payload.data}`.slice(-200_000);
    if (tab.serverId === activeServerId && tab.id === activeTerminalTabId && terminal) terminal.write(event.payload.data);
  }));
  terminalUnlisteners.push(await listen<TerminalEvent>("terminal-closed", (event) => {
    const tab = terminalTabs.find((item) => item.sessionId === event.payload.sessionId);
    if (tab) {
      captureMountedTerminal();
      tab.closed = true;
      tab.buffer += `\r\n[${event.payload.data}]\r\n`;
      if (tab.serverId === activeServerId && tab.id === activeTerminalTabId) {
        terminalMountTabId = null;
        render();
      }
    }
  }));
  terminalUnlisteners.push(await listen<TransferProgress>("transfer-progress", (event) => {
    transfer = event.payload;
    syncTransferToast();
    if (event.payload.done) dismissTransferToast(event.payload.transferId);
  }));
  terminalUnlisteners.push(await listen<{ paths?: string[] }>("tauri://drag-drop", (event) => {
    if (activeView !== "files" || !event.payload?.paths?.length) return;
    for (const path of event.payload.paths) void transferUpload(path);
  }));
}

function handleKeydown(event: KeyboardEvent): void {
  const customPicker = (event.target as HTMLElement).closest<HTMLElement>(".custom-select");
  if (customPicker) {
    const trigger = customPicker.querySelector<HTMLButtonElement>(".custom-select-trigger");
    const options = [...customPicker.querySelectorAll<HTMLButtonElement>(".custom-select-option:not(:disabled)")];
    const currentIndex = options.indexOf(event.target as HTMLButtonElement);
    if ((event.key === "ArrowDown" || event.key === "ArrowUp") && event.target === trigger) {
      event.preventDefault();
      trigger?.click();
      return;
    }
    if (currentIndex >= 0 && (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Home" || event.key === "End")) {
      event.preventDefault();
      const nextIndex = event.key === "Home" ? 0 : event.key === "End" ? options.length - 1 : (currentIndex + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
      options[nextIndex]?.focus();
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeCustomSelects(root);
      trigger?.focus();
      return;
    }
  }
  if (event.key !== "Enter" && event.key !== " ") return;
  const target = event.target as HTMLElement;
  if (target.closest("[data-server-action]")) return;
  const serverItem = target.closest<HTMLElement>(".server-item[data-server-id]");
  if (!serverItem?.dataset.serverId) return;
  event.preventDefault();
  void selectServer(serverItem.dataset.serverId);
}

const workspaceTabDrag = createWorkspaceTabDragController(
  root,
  () => openServerTabs,
  (tabs) => { openServerTabs = tabs; },
);

root.addEventListener("click", (event) => { void handleClick(event); });
root.addEventListener("input", handleInput);
root.addEventListener("change", handleChange);
root.addEventListener("submit", (event) => { void handleSubmit(event); });
root.addEventListener("keydown", handleKeydown);
root.addEventListener("pointerdown", workspaceTabDrag.pointerDown);
root.addEventListener("pointermove", workspaceTabDrag.pointerMove);
root.addEventListener("pointerup", workspaceTabDrag.finishPointerDrag);
root.addEventListener("pointercancel", workspaceTabDrag.finishPointerDrag);
root.addEventListener("click", (event) => {
  const backdrop = (event.target as HTMLElement).closest<HTMLElement>("[data-backdrop], [data-app-dialog]");
  if (backdrop && event.target === backdrop) closeModal();
});

window.addEventListener("resize", () => { fitAddon?.fit(); });
window.addEventListener("contextmenu", (event) => { event.preventDefault(); }, { capture: true });
window.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && !event.altKey) {
    if (event.key === "+" || event.key === "=") {
      event.preventDefault();
      void stepInterfaceScale(1);
      return;
    }
    if (event.key === "-") {
      event.preventDefault();
      void stepInterfaceScale(-1);
      return;
    }
    if (event.key === "0") {
      event.preventDefault();
      void setInterfaceScale(DEFAULT_INTERFACE_SCALE);
      return;
    }
  }
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    root.querySelector<HTMLInputElement>('[data-field="server-search"]')?.focus();
  }
  if (event.key === "Escape" && (modal || appDialogPrompt)) closeModal();
}, { capture: true });

async function bootstrap(): Promise<void> {
  await setInterfaceScale(interfaceScale, false);
  render();
  try {
    await installEventListeners();
    await refreshSnapshot(false);
    credentialStatus = await invoke<CredentialStatus>("get_credential_status");
    loading = false;
    render();
  } catch (error) {
    loading = false; errorMessage = errorText(error); render();
  }
}

void bootstrap();
