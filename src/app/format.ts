export const escapeHtml = (value: unknown): string => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

const ANSI_ESCAPE_SEQUENCE = /\u001B(?:\][^\u0007]*(?:\u0007|\u001B\\)|\[[0-?]*[ -/]*[@-~])/g;

export function normalizeLogOutput(value: string): string {
  return value.replace(ANSI_ESCAPE_SEQUENCE, "").replace(/\r\n?/g, "");
}

export function quoteShellArgument(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

export function formatBytes(value?: number): string {
  const bytes = Number(value ?? 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index > 1 ? 1 : 0)} ${units[index]}`;
}

export function formatDuration(seconds: number): string {
  const value = Math.max(0, Math.floor(seconds));
  const days = Math.floor(value / 86_400);
  const hours = Math.floor(value % 86_400 / 3_600);
  const minutes = Math.floor(value % 3_600 / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function formatDate(value?: string | number): string {
  if (!value) return "Never";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", hour: "numeric", minute: "2-digit" }).format(date);
}

export function meter(value: number, tone = "coral"): string {
  const normalized = Math.max(0, Math.min(100, value));
  return `<div class="meter"><span class="meter-fill meter-${tone}" style="width:${normalized}%"></span></div>`;
}

export function sparkline(value: number, tone = "coral"): string {
  const seed = Math.round(value * 7) + 11;
  const points = Array.from({ length: 12 }, (_, index) => {
    const point = Math.max(8, Math.min(90, 42 + Math.sin(index * 1.14 + seed) * 18 + value * 0.22 + (index % 3) * 3));
    return `${index * 10},${100 - point}`;
  }).join(" ");
  return `<svg class="sparkline spark-${tone}" viewBox="0 0 110 100" preserveAspectRatio="none"><polyline points="${points}"/></svg>`;
}
