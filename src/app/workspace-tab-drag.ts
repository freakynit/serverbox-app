import type { WorkspaceTab } from "./types";

interface WorkspaceTabDrag {
  pointerId: number;
  tabId: string;
  element: HTMLElement;
  startX: number;
  startY: number;
  dragging: boolean;
}

/** Keeps drag-reordering isolated from application navigation and rendering. */
export function createWorkspaceTabDragController(
  root: HTMLElement,
  getTabs: () => WorkspaceTab[],
  setTabs: (tabs: WorkspaceTab[]) => void,
) {
  let drag: WorkspaceTabDrag | null = null;
  let suppressClick = false;

  const clearDropIndicators = (): void => {
    root.querySelectorAll(".workspace-tab.dragging, .workspace-tab.drop-before, .workspace-tab.drop-after").forEach((tab) => {
      tab.classList.remove("dragging", "drop-before", "drop-after");
    });
  };

  const pointerDown = (event: PointerEvent): void => {
    if (!event.isPrimary || event.button !== 0) return;
    const target = (event.target as HTMLElement).closest<HTMLElement>(".workspace-tab[data-workspace-tab]");
    if (!target?.dataset.workspaceTab || (event.target as HTMLElement).closest("[data-workspace-tab-action]")) return;
    drag = { pointerId: event.pointerId, tabId: target.dataset.workspaceTab, element: target, startX: event.clientX, startY: event.clientY, dragging: false };
    target.setPointerCapture(event.pointerId);
  };

  const pointerMove = (event: PointerEvent): void => {
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (!drag.dragging) {
      if (Math.hypot(event.clientX - drag.startX, event.clientY - drag.startY) < 5) return;
      drag.dragging = true;
      suppressClick = true;
      drag.element.classList.add("dragging");
    }
    event.preventDefault();
    const tabList = drag.element.closest<HTMLElement>(".workspace-tabs");
    if (!tabList) return;
    const siblings = [...tabList.querySelectorAll<HTMLElement>(".workspace-tab[data-workspace-tab]")].filter((tab) => tab !== drag?.element);
    let insertionIndex = siblings.findIndex((tab) => event.clientX < tab.getBoundingClientRect().left + tab.getBoundingClientRect().width / 2);
    if (insertionIndex < 0) insertionIndex = siblings.length;
    const draggedTab = getTabs().find((tab) => tab.id === drag?.tabId);
    if (!draggedTab) return;
    const reorderedTabs = getTabs().filter((tab) => tab.id !== draggedTab.id);
    reorderedTabs.splice(insertionIndex, 0, draggedTab);
    setTabs(reorderedTabs);
    tabList.insertBefore(drag.element, siblings[insertionIndex] ?? null);
    root.querySelectorAll(".workspace-tab.drop-before, .workspace-tab.drop-after").forEach((tab) => tab.classList.remove("drop-before", "drop-after"));
    if (siblings[insertionIndex]) siblings[insertionIndex].classList.add("drop-before");
    else siblings.at(-1)?.classList.add("drop-after");
  };

  const finishPointerDrag = (event: PointerEvent): void => {
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (drag.element.hasPointerCapture(event.pointerId)) drag.element.releasePointerCapture(event.pointerId);
    if (drag.dragging) event.preventDefault();
    const wasDragging = drag.dragging;
    clearDropIndicators();
    drag = null;
    if (wasDragging) window.setTimeout(() => { suppressClick = false; }, 0);
  };

  return { pointerDown, pointerMove, finishPointerDrag, suppressesClick: () => suppressClick };
}
