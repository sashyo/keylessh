import { useEffect, useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { AlertCircle, ArrowUp, X } from "lucide-react";

// Remembers a passed check so the test window doesn't flash on every reload.
const POPUP_OK_KEY = "keylessh:popup-ok";

/**
 * Tide approvals run in a popup window (the approval enclave), so a browser
 * that blocks popups breaks them. Probe once after login, outside a user
 * gesture: that only succeeds when popups are allowed for this site.
 */
function popupsAllowed(): Promise<boolean> {
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

type Browser = "edge" | "chrome" | "firefox" | "safari" | "other";

function detectBrowser(): Browser {
  const ua = navigator.userAgent;
  if (/Edg\//.test(ua)) return "edge";
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Chrome\/|Chromium\/|CriOS\//.test(ua)) return "chrome";
  if (/Safari\//.test(ua)) return "safari";
  return "other";
}

// Where the browser surfaces the blocked popup, and how to allow it from there.
const UNBLOCK_STEPS: Record<Browser, string[]> = {
  chrome: [
    "Click the blocked-popup icon at the right end of the address bar (↑ top right).",
    "Choose “Always allow pop-ups and redirects from this site”, then click Done.",
    "Click Reload below.",
  ],
  edge: [
    "Click the blocked-popup icon at the right end of the address bar (↑ top right).",
    "Choose “Always allow pop-ups and redirects from this site”, then click Done.",
    "Click Reload below.",
  ],
  firefox: [
    "Find the yellow “Firefox prevented this site from opening a pop-up window” bar just below the address bar.",
    "Click its Options (or Preferences) button on the right (↑ top right).",
    "Choose “Allow pop-ups for this site”, then click Reload below.",
  ],
  safari: [
    "Click the blocked-popup icon in the address bar (↑ top), or open Safari › Settings › Websites › Pop-up Windows.",
    "Set this website to “Allow”.",
    "Click Reload below.",
  ],
  other: [
    "Look for a blocked-popup icon or notice near the address bar (↑ top right).",
    "Allow pop-ups for this site.",
    "Click Reload below.",
  ],
};

export function PopupBlockedBanner() {
  const [blocked, setBlocked] = useState(false);
  const [browser] = useState(detectBrowser);

  useEffect(() => {
    try {
      if (sessionStorage.getItem(POPUP_OK_KEY) === "1") return;
    } catch {
      // storage unavailable; just run the check
    }
    let cancelled = false;
    popupsAllowed().then((ok) => {
      if (cancelled) return;
      if (ok) {
        try {
          sessionStorage.setItem(POPUP_OK_KEY, "1");
        } catch {
          // ignore
        }
      }
      setBlocked(!ok);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!blocked) return null;

  return (
    <Alert
      role="alert"
      className="relative rounded-none border-x-0 border-t-0 bg-amber-50 border-amber-300 pr-24 dark:bg-amber-950/30 dark:border-amber-800"
      data-testid="popup-blocked-banner"
    >
      <AlertCircle className="h-4 w-4 text-amber-600 dark:text-amber-400" />
      <AlertDescription className="text-amber-900 dark:text-amber-100">
        <p className="font-semibold">Pop-ups are blocked: please unblock them to use KeyleSSH.</p>
        <p className="mt-0.5 text-amber-800 dark:text-amber-200">
          Tide approvals open in a pop-up window and won&rsquo;t work until pop-ups are allowed for this site.
        </p>
        <ol className="mt-2 list-decimal space-y-0.5 pl-5 text-amber-800 dark:text-amber-200">
          {UNBLOCK_STEPS[browser].map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
        <div className="mt-3 flex items-center gap-2">
          <Button
            size="sm"
            className="bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-500 dark:text-amber-950 dark:hover:bg-amber-400"
            onClick={() => window.location.reload()}
          >
            Reload
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="text-amber-800 hover:bg-amber-100 dark:text-amber-200 dark:hover:bg-amber-950"
            onClick={() => setBlocked(false)}
          >
            <X className="mr-1 h-4 w-4" />
            Dismiss
          </Button>
        </div>
      </AlertDescription>

      {/* Points up at the address bar, where the browser shows its blocked-popup icon. */}
      <div
        className="pointer-events-none absolute right-6 top-1 flex flex-col items-center text-amber-600 dark:text-amber-400"
        aria-hidden="true"
      >
        <ArrowUp className="h-10 w-10 animate-bounce" strokeWidth={2.5} />
        <span className="-mt-1 text-xs font-semibold uppercase tracking-wide">Here</span>
      </div>
    </Alert>
  );
}
