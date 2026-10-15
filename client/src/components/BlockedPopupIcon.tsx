/** The browser's blocked-popup icon (Chromium style): a window with a slash through it. */
export function BlockedPopupIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <rect x="3" y="5" width="18" height="14" rx="1" />
      <rect x="13" y="8" width="5" height="4" />
      <line x1="3" y1="3" x2="21" y2="21" />
    </svg>
  );
}
