// Popup support detection. Tide approvals run in a popup window (the approval
// enclave), so a browser that blocks popups breaks them.

/** Where the "allow pop-ups" instructions live. Public, no login required. */
export const POPUP_HELP_URL = "/allow-popups";

// Remembers a passed check so the test window doesn't flash on every reload.
const POPUP_OK_KEY = "keylessh:popup-ok";

/**
 * Try to open (and immediately close) a tiny window. Must run outside a user
 * gesture: a click lets popups through regardless of the site setting, so the
 * result would say nothing about whether the enclave can open later.
 */
export function popupsAllowed(): Promise<boolean> {
  let w: Window | null = null;
  try {
    w = window.open("about:blank", "_blank", "width=1,height=1,left=-10000,top=-10000");
  } catch {
    return Promise.resolve(false);
  }
  if (!w || w.closed) return Promise.resolve(false);
  // Some blockers hand back a window and then close it straight away.
  return new Promise((resolve) => {
    setTimeout(() => {
      const ok = !w!.closed;
      try {
        w!.close();
      } catch {
        // ignore
      }
      resolve(ok);
    }, 250);
  });
}

/** True while a recent click/keypress would let a popup through anyway. */
export function hasTransientActivation(): boolean {
  return (navigator as Navigator & { userActivation?: { isActive: boolean } }).userActivation?.isActive ?? false;
}

export function popupsKnownOk(): boolean {
  try {
    return sessionStorage.getItem(POPUP_OK_KEY) === "1";
  } catch {
    return false;
  }
}

export function rememberPopupsOk() {
  try {
    sessionStorage.setItem(POPUP_OK_KEY, "1");
  } catch {
    // ignore
  }
}

/**
 * Re-probe every few seconds until popups are allowed, so the user never has
 * to reload. Skips a tick right after a click, when any popup gets through.
 * Returns a cleanup function.
 */
export function watchUntilPopupsAllowed(onAllowed: () => void, intervalMs = 3000): () => void {
  let busy = false;
  const id = window.setInterval(() => {
    if (busy || document.hidden || hasTransientActivation()) return;
    busy = true;
    popupsAllowed()
      .then((ok) => {
        if (ok) {
          window.clearInterval(id);
          rememberPopupsOk();
          onAllowed();
        }
      })
      .finally(() => {
        busy = false;
      });
  }, intervalMs);
  return () => window.clearInterval(id);
}

export type Browser = "chrome" | "edge" | "brave" | "firefox" | "safari" | "other";

export function detectBrowser(): Browser {
  // Brave reports a Chrome user agent; it exposes navigator.brave instead.
  if ((navigator as Navigator & { brave?: unknown }).brave) return "brave";
  const ua = navigator.userAgent;
  if (/Edg\//.test(ua)) return "edge";
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Chrome\/|Chromium\/|CriOS\//.test(ua)) return "chrome";
  if (/Safari\//.test(ua)) return "safari";
  return "other";
}

export const BROWSER_NAME: Record<Browser, string> = {
  chrome: "Chrome",
  edge: "Edge",
  brave: "Brave",
  firefox: "Firefox",
  safari: "Safari",
  other: "Other",
};
