import { icon } from "../icons";
import { escapeHtml } from "./format";

export interface TitlebarViewData {
  platform: string;
  server?: { name: string; host: string };
}

export function renderTitlebarView({ platform, server }: TitlebarViewData): string {
  return `<header class="titlebar" data-tauri-drag-region data-platform="${platform}">
    <div class="titlebar-brand"><span class="titlebar-mark">${icon("logo")}</span><span>Serverbox</span></div>
    <div class="titlebar-caption"><strong>${escapeHtml(server?.name ?? "Your server room")}</strong><span>${server ? escapeHtml(server.host) : "Agentless SSH control"}</span></div>
    <div class="window-controls" aria-label="Window controls">
      <button class="window-control window-control-minimize" data-window="minimize" title="Minimize window" aria-label="Minimize window">${icon("minus")}</button>
      <button class="window-control window-control-maximize" data-window="maximize" title="Maximize window" aria-label="Maximize window">${icon("square")}</button>
      <button class="window-control window-control-close" data-window="close" title="Close window" aria-label="Close window">${icon("close")}</button>
    </div>
  </header>`;
}

export function renderLoadingView(): string {
  return `<main class="boot-screen"><div class="boot-card"><div class="brand-mark">${icon("logo")}</div><div class="eyebrow">Getting things ready</div><h1>Opening your server room</h1><p>Connection profiles stay on this device. Saved credentials are protected by your master password.</p><div class="loading-line"><span></span></div></div></main>`;
}

export function renderWelcomeView(): string {
  return `<div class="welcome-page"><div class="welcome-art"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><span>${icon("logo")}</span></div><div class="eyebrow">Your quiet server room</div><h1>Control the machines<br/><em>without the noise.</em></h1><p class="welcome-copy">Connect over SSH and keep an eye on Linux servers from one calm, focused desktop workspace.</p><div class="welcome-actions"><button class="button button-primary" data-action="add-server">${icon("plus")} Connect your first server</button><button class="text-button" data-action="show-help">How it works ${icon("chevron")}</button></div><div class="welcome-points"><span>${icon("shield")} Agentless</span><span>${icon("key" )} Encrypted locally</span><span>${icon("terminalSmall")} Real SSH</span></div></div>`;
}

export function renderEmptyWorkspaceView(): string {
  return `<div class="welcome-page"><div class="welcome-art"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><span>${icon("logo")}</span></div><div class="eyebrow">No server selected</div><h1>Choose a server<br/><em>to begin.</em></h1><p class="welcome-copy">Select any saved server from the sidebar. It will open as the first workspace tab and connect over SSH.</p><div class="welcome-actions"><button class="button button-quiet" data-action="add-server">${icon("plus")} Add another server</button></div></div>`;
}

export function renderErrorView(error: string): string {
  return `<div class="error-state"><div class="error-icon">${icon("info")}</div><div><strong>Serverbox couldn't complete that request</strong><p>${escapeHtml(error)}</p><button class="button button-quiet" data-action="retry">${icon("refresh")} Refresh this view</button></div></div>`;
}

export function renderInlineErrorView(error: string): string {
  return `<div class="inline-error">${icon("info")}<span>${escapeHtml(error)}</span><button data-action="dismiss-error">${icon("close")}</button></div>`;
}

export function renderUnsupportedView(title: string, copy: string): string {
  return `<div class="unsupported"><div class="unsupported-art">${icon("shield")}</div><div class="eyebrow">Capability not detected</div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(copy)}</p><button class="button button-quiet" data-action="refresh">${icon("refresh")} Check again</button></div>`;
}
