import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, X } from "lucide-react";
import { POPUP_HELP_URL, popupsAllowed, popupsKnownOk, rememberPopupsOk, watchUntilPopupsAllowed } from "@/lib/popups";

type Status = "checking" | "blocked" | "allowed" | "hidden";

/** One-line notice shown after login when the browser blocks popups. */
export function PopupBlockedBanner() {
  const [status, setStatus] = useState<Status>("checking");

  useEffect(() => {
    if (popupsKnownOk()) {
      setStatus("hidden");
      return;
    }
    let cancelled = false;
    popupsAllowed().then((ok) => {
      if (cancelled) return;
      if (ok) rememberPopupsOk();
      setStatus(ok ? "hidden" : "blocked");
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Clears itself once the user allows popups (e.g. from the help page).
  useEffect(() => {
    if (status !== "blocked") return;
    return watchUntilPopupsAllowed(() => setStatus("allowed"));
  }, [status]);

  useEffect(() => {
    if (status !== "allowed") return;
    const id = window.setTimeout(() => setStatus("hidden"), 3500);
    return () => window.clearTimeout(id);
  }, [status]);

  if (status === "checking" || status === "hidden") return null;

  if (status === "allowed") {
    return (
      <div
        role="status"
        className="flex items-center gap-2 border-b border-emerald-200 bg-emerald-50 px-4 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200"
      >
        <CheckCircle2 className="h-4 w-4 shrink-0" />
        Pop-ups are now allowed. You&rsquo;re all set.
      </div>
    );
  }

  return (
    <div
      role="alert"
      className="flex items-center gap-2 border-b border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-100"
      data-testid="popup-blocked-banner"
    >
      <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
      <p className="min-w-0 flex-1">
        Pop-ups are currently blocked. For{" "}
        <a
          href={POPUP_HELP_URL}
          target="_blank"
          rel="noopener"
          className="font-medium underline underline-offset-2 hover:text-amber-700 dark:hover:text-amber-300"
        >
          advanced security features
        </a>
        , please allow pop-ups for this site.
      </p>
      <button
        type="button"
        onClick={() => setStatus("hidden")}
        aria-label="Dismiss"
        className="rounded p-1 text-amber-700 hover:bg-amber-100 dark:text-amber-300 dark:hover:bg-amber-950"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
