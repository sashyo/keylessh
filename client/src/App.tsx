import { Switch, Route, Redirect, useLocation, useParams, useSearch } from "wouter";
import { useEffect, useState } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AppLayout } from "@/components/layout/AppLayout";
import Login from "@/pages/Login";
import AuthRedirect from "@/pages/AuthRedirect";
import Dashboard from "@/pages/Dashboard";
import ConsoleWorkspace from "@/pages/ConsoleWorkspace";
import AdminDashboard from "@/pages/AdminDashboard";
import AdminServers from "@/pages/AdminServers";
import AdminUsers from "@/pages/AdminUsers";
import AdminRoles from "@/pages/AdminRoles";
import AdminPolicyTemplates from "@/pages/AdminPolicyTemplates";
import AdminApprovals from "@/pages/AdminApprovals";
import AdminSessions from "@/pages/AdminSessions";
import AdminLogs from "@/pages/AdminLogs";
import AdminLicense from "@/pages/AdminLicense";
import AdminRecordings from "@/pages/AdminRecordings";
import AdminBridges from "@/pages/AdminBridges";
import NotFound from "@/pages/not-found";
import { Loader2, Terminal } from "lucide-react";

function LoadingScreen({ showRetry = false }: { showRetry?: boolean }) {
  const handleClearAndRetry = () => {
    // Clear all auth-related state
    localStorage.removeItem("access_token");
    // Clear TideCloak/OIDC state
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && (key.startsWith("oidc.") || key.startsWith("kc-") || key.includes("tidecloak"))) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));
    sessionStorage.clear();
    window.location.href = "/login";
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
          <Terminal className="h-6 w-6 text-primary" />
        </div>
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <p className="text-sm text-muted-foreground">Loading KeyleSSH...</p>
        {showRetry && (
          <button
            onClick={handleClearAndRetry}
            className="mt-4 px-4 py-2 text-sm text-muted-foreground hover:text-foreground border border-border rounded-md hover:bg-accent transition-colors"
          >
            Taking too long? Click to restart
          </button>
        )}
      </div>
    </div>
  );
}

/**
 * Legacy redirect: /app/console/:serverId?user=xxx → /app/console?serverId=...&user=...
 * Already inside AuthenticatedApp so auth is guaranteed.
 */
function ConsoleLegacyRedirect() {
  const [, setLocation] = useLocation();
  const params = useParams<{ serverId: string }>();
  const search = useSearch();

  useEffect(() => {
    const sp = new URLSearchParams(search);
    const user = sp.get("user") || "root";
    setLocation(`/app/console?serverId=${encodeURIComponent(params.serverId)}&user=${encodeURIComponent(user)}`);
  }, [setLocation, params.serverId, search]);

  return null;
}

/**
 * All authenticated routes share a single AppLayout.
 * ConsoleWorkspace is always mounted (hidden when not on the console page)
 * so SSH connections persist across page navigation.
 */
function AuthenticatedApp() {
  const { isAuthenticated, isLoading, hasRole } = useAuth();
  const [location] = useLocation();
  const [, setLocation] = useLocation();
  const [showRetry, setShowRetry] = useState(false);
  const isAdmin = hasRole("admin");

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      setLocation("/login");
    }
  }, [isLoading, isAuthenticated, setLocation]);

  // Show retry button after 5 seconds of loading
  useEffect(() => {
    if (isLoading) {
      const timeout = setTimeout(() => setShowRetry(true), 5000);
      return () => clearTimeout(timeout);
    }
    setShowRetry(false);
  }, [isLoading]);

  if (isLoading) {
    return <LoadingScreen showRetry={showRetry} />;
  }

  if (!isAuthenticated) {
    return <LoadingScreen />;
  }

  const isConsolePage = location === "/app/console";

  return (
    <AppLayout>
      {/* ConsoleWorkspace is always mounted so SSH connections survive page navigation.
          Hidden via CSS when the user is on a different page. The existing ResizeObserver
          in TerminalSession automatically refits the terminal when it becomes visible again. */}
      <div className={isConsolePage ? "h-full" : "hidden"}>
        <ConsoleWorkspace />
      </div>
      {!isConsolePage && (
        <Switch>
          <Route path="/">
            <Redirect to="/app" />
          </Route>
          <Route path="/app">
            <Dashboard />
          </Route>
          <Route path="/app/console/:serverId">
            <ConsoleLegacyRedirect />
          </Route>
          <Route path="/admin">
            {isAdmin ? <AdminDashboard /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/servers">
            {isAdmin ? <AdminServers /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/bridges">
            {isAdmin ? <AdminBridges /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/users">
            {isAdmin ? <AdminUsers /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/roles">
            {isAdmin ? <AdminRoles /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/policy-templates">
            {isAdmin ? <AdminPolicyTemplates /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/approvals">
            {isAdmin ? <AdminApprovals /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/sessions">
            {isAdmin ? <AdminSessions /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/logs">
            {isAdmin ? <AdminLogs /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/license">
            {isAdmin ? <AdminLicense /> : <Redirect to="/app" />}
          </Route>
          <Route path="/admin/recordings">
            {isAdmin ? <AdminRecordings /> : <Redirect to="/app" />}
          </Route>
          <Route component={NotFound} />
        </Switch>
      )}
    </AppLayout>
  );
}

function Router() {
  return (
    <Switch>
      <Route path="/login" component={Login} />
      <Route path="/auth/redirect" component={AuthRedirect} />
      {/* All other routes require authentication */}
      <Route>
        <AuthenticatedApp />
      </Route>
    </Switch>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <TooltipProvider>
            <AuthProvider>
              <Toaster />
              <Router />
            </AuthProvider>
          </TooltipProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
