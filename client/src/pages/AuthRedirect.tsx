import { useEffect } from 'react';
import { useLocation } from 'wouter';
import { useTideCloak } from '@tidecloak/react';
import { Loader2, Terminal } from 'lucide-react';

export default function AuthRedirect() {
  const { authenticated, isInitializing, logout } = useTideCloak();
  const [, setLocation] = useLocation();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("auth") === "failed") {
      sessionStorage.setItem("tokenExpired", "true");
      logout();
    }
  }, [logout]);

  useEffect(() => {
    if (!isInitializing) {
      setLocation(authenticated ? '/app' : '/login');
    }
  }, [authenticated, isInitializing, setLocation]);

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
          <Terminal className="h-6 w-6 text-primary" />
        </div>
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <p className="text-sm text-muted-foreground" data-testid="text-auth-status">
          Waiting for authentication...
        </p>
      </div>
    </div>
  );
}
