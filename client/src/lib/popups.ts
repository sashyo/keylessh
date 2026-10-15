// Popup support detection. Tide approvals run in a popup window (the approval
// enclave), so a browser that blocks popups breaks them.

/**
 * The standalone "allow pop-ups" instructions page (client/public/allow-popups.html).
 * Set VITE_POPUP_HELP_URL to host it on another domain. It's told which site
 * to name, since on another domain it can't infer that from its own address.
 */
export function popupHelpUrl(): string {
  const base = (import.meta.env.VITE_POPUP_HELP_URL as string | undefined) || "/allow-popups.html";
  const url = new URL(base, window.location.origin);
  url.searchParams.set("site", window.location.host);
  url.searchParams.set("return", window.location.href);
  return url.toString();
}

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
