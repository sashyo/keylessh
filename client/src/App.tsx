import { Switch, Route, Redirect, useLocation } from "wouter";
import { useEffect } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { AppLayout } from "@/components/layout/AppLayout";
import Login from "@/pages/Login";
import AuthRedirect from "@/pages/AuthRedirect";
import Dashboard from "@/pages/Dashboard";
import Console from "@/pages/Console";
import AdminDashboard from "@/pages/AdminDashboard";
import AdminServers from "@/pages/AdminServers";
import AdminUsers from "@/pages/AdminUsers";
import AdminSessions from "@/pages/AdminSessions";
import NotFound from "@/pages/not-found";
import { Loader2, Terminal } from "lucide-react";
import type { ReactNode } from "react";

function LoadingScreen() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
          <Terminal className="h-6 w-6 text-primary" />
        </div>
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <p className="text-sm text-muted-foreground">Loading KeyleSSH...</p>
      </div>
    </div>
  );
}

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const [location, setLocation] = useLocation();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      setLocation("/login");
    }
  }, [isLoading, isAuthenticated, setLocation]);

  if (isLoading) {
    return <LoadingScreen />;
  }

  if (!isAuthenticated) {
    return <LoadingScreen />;
  }

  return <AppLayout>{children}</AppLayout>;
}

function AdminRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading, hasRole } = useAuth();
  const [, setLocation] = useLocation();

  useEffect(() => {
    if (!isLoading) {
      if (!isAuthenticated) {
        setLocation("/login");
      } else if (!hasRole("admin")) {
        setLocation("/app");
      }
    }
  }, [isLoading, isAuthenticated, hasRole, setLocation]);

  if (isLoading) {
    return <LoadingScreen />;
  }

  if (!isAuthenticated || !hasRole("admin")) {
    return <LoadingScreen />;
  }

  return <AppLayout>{children}</AppLayout>;
}

function ConsoleRoute() {
  const { isAuthenticated, isLoading } = useAuth();
  const [, setLocation] = useLocation();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      setLocation("/login");
    }
  }, [isLoading, isAuthenticated, setLocation]);

  if (isLoading) {
    return <LoadingScreen />;
  }

  if (!isAuthenticated) {
    return <LoadingScreen />;
  }

  return (
    <AppLayout>
      <Console />
    </AppLayout>
  );
}

function Router() {
  return (
    <Switch>
      <Route path="/">
        <Redirect to="/app" />
      </Route>
      
      <Route path="/login" component={Login} />
      <Route path="/auth/redirect" component={AuthRedirect} />
      
      <Route path="/app">
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      </Route>
      
      <Route path="/app/servers">
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      </Route>
      
      <Route path="/app/sessions">
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      </Route>
      
      <Route path="/app/console/:serverId">
        <ConsoleRoute />
      </Route>
      
      <Route path="/admin">
        <AdminRoute>
          <AdminDashboard />
        </AdminRoute>
      </Route>
      
      <Route path="/admin/servers">
        <AdminRoute>
          <AdminServers />
        </AdminRoute>
      </Route>
      
      <Route path="/admin/users">
        <AdminRoute>
          <AdminUsers />
        </AdminRoute>
      </Route>
      
      <Route path="/admin/sessions">
        <AdminRoute>
          <AdminSessions />
        </AdminRoute>
      </Route>
      
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <AuthProvider>
          <Toaster />
          <Router />
        </AuthProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
