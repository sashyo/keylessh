import { useEffect, useState, type ReactNode } from "react";
import { ArrowUp, CheckCircle2, ChevronDown, KeyRound, Loader2, Lock, ShieldCheck, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  BROWSER_NAME,
  detectBrowser,
  popupsAllowed,
  rememberPopupsOk,
  watchUntilPopupsAllowed,
  type Browser,
} from "@/lib/popups";

/** Chromium's blocked-popup icon: a window with a slash through it. */
function BlockedPopupIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <rect x="3" y="5" width="18" height="14" rx="1" />
      <rect x="13" y="8" width="5" height="4" />
      <line x1="3" y1="3" x2="21" y2="21" />
    </svg>
  );
}

// ---------- Mock browser UI ----------
// A page can't locate the real address bar (Brave centres it, Chrome stretches
// it), so each step points at a small replica instead of guessing coordinates.

const mockSurface =
  "rounded-md border border-slate-200 bg-white text-slate-700 shadow-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200";

function Highlight({ children }: { children: ReactNode }) {
  return (
    <span className="relative inline-flex">
      <span className="absolute -inset-1 animate-ping rounded-md bg-amber-400/40" />
      <span className="relative rounded-md bg-amber-100 ring-2 ring-amber-500 dark:bg-amber-400/20">{children}</span>
    </span>
  );
}

function AddressBarMock({ iconOnLeft }: { iconOnLeft: boolean }) {
  const icon = (
    <span className="relative">
      <Highlight>
        <BlockedPopupIcon className="m-0.5 h-4 w-4" />
      </Highlight>
      <ArrowUp
        className="absolute left-1/2 top-full mt-1 h-5 w-5 -translate-x-1/2 animate-bounce text-amber-600 dark:text-amber-400"
        strokeWidth={3}
      />
    </span>
  );
  return (
    <div className="pb-7">
      <div className={cn(mockSurface, "flex items-center gap-1.5 rounded-full px-3 py-2 text-xs")}>
        {iconOnLeft && icon}
        <Lock className="h-3 w-3 shrink-0 text-slate-400" />
        <span className="truncate">{window.location.host}</span>
        <span className="flex-1" />
        {!iconOnLeft && (
          <>
            {icon}
            {/* Neighbouring address-bar icon, so the replica is recognisable. */}
            <KeyRound className="h-3.5 w-3.5 text-slate-300 dark:text-slate-600" />
          </>
        )}
      </div>
    </div>
  );
}

function ChromiumBubbleMock() {
  return (
    <div className={cn(mockSurface, "space-y-2 p-3 text-xs")}>
      <div className="font-medium">Pop-ups blocked</div>
      <div className="flex items-start gap-1.5">
        <Highlight>
          <span className="m-0.5 block h-3 w-3 rounded-full border-[3px] border-blue-600" />
        </Highlight>
        <span className="font-medium">Always allow pop-ups and redirects from {window.location.host}</span>
      </div>
      <div className="flex items-center gap-1.5 text-slate-400">
        <span className="ml-0.5 block h-3 w-3 rounded-full border border-slate-400" />
        Continue blocking
      </div>
      <div className="flex justify-end">
        <span className="rounded bg-blue-600 px-2.5 py-0.5 text-[11px] font-medium text-white">Done</span>
      </div>
    </div>
  );
}

function FirefoxMenuMock() {
  return (
    <div className={cn(mockSurface, "overflow-hidden text-xs")}>
      <div className="flex items-center justify-between gap-2 bg-amber-100 px-2.5 py-1.5 text-amber-900 dark:bg-amber-400/20 dark:text-amber-100">
        <span className="truncate">Firefox prevented this site from opening a pop-up.</span>
        <span className="shrink-0 rounded border border-amber-400 px-1.5">Options</span>
      </div>
      <div className="p-2">
        <Highlight>
          <span className="block px-1.5 py-0.5 font-medium">Allow pop-ups for {window.location.host}</span>
        </Highlight>
      </div>
    </div>
  );
}

function SafariSettingsMock({ highlight }: { highlight: boolean }) {
  const allow = (
    <span className="flex items-center gap-0.5 px-1.5 font-medium">
      Allow <ChevronDown className="h-3 w-3" />
    </span>
  );
  return (
    <div className={cn(mockSurface, "space-y-2 p-3 text-xs")}>
      <div className={highlight ? "text-slate-400" : "font-medium"}>Safari › Settings › Websites › Pop-up Windows</div>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate">{window.location.host}</span>
        {highlight ? <Highlight>{allow}</Highlight> : allow}
      </div>
    </div>
  );
}

interface Step {
  title: string;
  detail: ReactNode;
  visual: ReactNode;
}

function stepsFor(browser: Browser): Step[] {
  const done: Step = {
    title: "You're done",
    detail: "The status at the top of this page turns green. Head back to your app and carry on.",
    visual: (
      <div className={cn(mockSurface, "flex items-center gap-2 p-3 text-xs")}>
        <CheckCircle2 className="h-4 w-4 text-emerald-600" />
        Pop-ups allowed
      </div>
    ),
  };

  if (browser === "firefox") {
    return [
      {
        title: "Open the pop-up notice",
        detail: "Click the blocked pop-up icon at the left of the address bar, or Options on the yellow bar.",
        visual: <AddressBarMock iconOnLeft />,
      },
      { title: "Allow this site", detail: <>Choose &ldquo;Allow pop-ups for this site&rdquo;.</>, visual: <FirefoxMenuMock /> },
      done,
    ];
  }
  if (browser === "safari") {
    return [
      {
        title: "Open website settings",
        detail: "In the menu bar choose Safari › Settings, then Websites › Pop-up Windows.",
        visual: <SafariSettingsMock highlight={false} />,
      },
      { title: "Allow this site", detail: <>Set this site to &ldquo;Allow&rdquo;.</>, visual: <SafariSettingsMock highlight /> },
      done,
    ];
  }
  return [
    {
      title: "Click the pop-up icon",
      detail:
        browser === "brave"
          ? "It's inside the address bar, on the right of the web address, just left of the Brave lion."
          : browser === "other"
            ? "Look for a blocked pop-up icon or notice in or near the address bar."
            : "It's inside the address bar, on the right of the web address.",
      visual: <AddressBarMock iconOnLeft={false} />,
    },
    {
      title: "Always allow this site",
      detail: "Select the option to always allow pop-ups from this site, then click Done.",
      visual: <ChromiumBubbleMock />,
    },
    done,
  ];
}

const BROWSER_TABS: Browser[] = ["chrome", "edge", "brave", "firefox", "safari", "other"];

type Status = "checking" | "blocked" | "allowed";

function StatusPill({ status }: { status: Status }) {
  if (status === "allowed") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-sm font-medium text-emerald-700 ring-1 ring-emerald-200">
        <CheckCircle2 className="h-4 w-4" />
        Pop-ups are allowed for this site
      </span>
    );
  }
  if (status === "blocked") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-3 py-1 text-sm font-medium text-amber-800 ring-1 ring-amber-200">
        <Loader2 className="h-4 w-4 animate-spin" />
        Pop-ups are blocked. Waiting for you to allow them…
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1 text-sm text-slate-600 ring-1 ring-slate-200">
      <Loader2 className="h-4 w-4 animate-spin" />
      Checking…
    </span>
  );
}

/**
 * Public instructions page for allowing pop-ups. Linked from the in-app
 * banner. It probes popups itself, which also makes the browser show its
 * blocked-popup icon in this tab's address bar, right where step 1 points.
 */
export default function AllowPopups() {
  const [browser, setBrowser] = useState<Browser>(detectBrowser);
  const [detected] = useState<Browser>(detectBrowser);
  const [status, setStatus] = useState<Status>("checking");

  useEffect(() => {
    document.title = "Allow pop-ups";
    let cancelled = false;
    popupsAllowed().then((ok) => {
      if (cancelled) return;
      if (ok) rememberPopupsOk();
      setStatus(ok ? "allowed" : "blocked");
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (status !== "blocked") return;
    return watchUntilPopupsAllowed(() => setStatus("allowed"));
  }, [status]);

  const steps = stepsFor(browser);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <main className="mx-auto max-w-5xl px-4 py-10 sm:py-16">
        <header className="flex flex-col items-center text-center">
          <span
            className={cn(
              "flex h-14 w-14 items-center justify-center rounded-2xl",
              status === "allowed" ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700",
            )}
          >
            {status === "allowed" ? <ShieldCheck className="h-7 w-7" /> : <ShieldAlert className="h-7 w-7" />}
          </span>
          <h1 className="mt-5 text-2xl font-semibold tracking-tight sm:text-3xl">Allow pop-ups for advanced security</h1>
          <p className="mt-3 max-w-2xl text-slate-600">
            Some security features, such as approving sensitive changes, open in a secure pop-up window served by
            Tide&rsquo;s decentralised network. Your browser needs to allow pop-ups from{" "}
            <span className="font-medium text-slate-800">{window.location.host}</span> for them to work.
          </p>
          <div className="mt-5">
            <StatusPill status={status} />
          </div>
        </header>

        <section className="mt-12">
          <div className="flex flex-wrap items-center justify-center gap-1.5" role="tablist" aria-label="Browser">
            {BROWSER_TABS.map((b) => (
              <button
                key={b}
                type="button"
                role="tab"
                aria-selected={browser === b}
                onClick={() => setBrowser(b)}
                className={cn(
                  "rounded-full px-3.5 py-1.5 text-sm transition-colors",
                  browser === b
                    ? "bg-slate-900 text-white"
                    : "bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-100",
                )}
              >
                {BROWSER_NAME[b]}
                {b === detected && b !== "other" && (
                  <span className={cn("ml-1.5 text-xs", browser === b ? "text-slate-300" : "text-slate-400")}>
                    (yours)
                  </span>
                )}
              </button>
            ))}
          </div>

          <ol className="mt-6 grid gap-4 md:grid-cols-3">
            {steps.map((step, i) => (
              <li key={step.title} className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="flex items-center gap-2.5 font-semibold">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-amber-500 text-xs text-white">
                    {i + 1}
                  </span>
                  {step.title}
                </div>
                <div>{step.visual}</div>
                <p className="text-sm text-slate-600">{step.detail}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="mx-auto mt-12 max-w-2xl space-y-4 text-sm text-slate-600">
          <div>
            <h2 className="font-semibold text-slate-800">Is this safe?</h2>
            <p className="mt-1">
              Yes. You&rsquo;re only allowing pop-ups from this one site, not the whole web. The pop-up is
              Tide&rsquo;s secure enclave, where approvals are signed separately from this app.
            </p>
          </div>
          <div>
            <h2 className="font-semibold text-slate-800">I allowed pop-ups but it still says blocked</h2>
            <p className="mt-1">
              Reload this page. If you use a separate pop-up blocker extension, allow this site there too.
            </p>
          </div>
        </section>

        <footer className="mt-14 flex items-center justify-center gap-1.5 text-xs text-slate-400">
          <ShieldCheck className="h-3.5 w-3.5" />
          Secured by Tide
        </footer>
      </main>
    </div>
  );
}
