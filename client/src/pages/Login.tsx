import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Terminal, Shield, Server, Key, ArrowRight, Building2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useLocation, Link } from "wouter";

function KeyleSSHLogo({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 36 36" className={className} xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="loginLogoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#ffffff"/>
          <stop offset="100%" stopColor="#a0a0a8"/>
        </linearGradient>
        <filter id="loginLogoGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      <rect width="36" height="36" rx="8" fill="hsl(120 15% 8%)"/>
      <g filter="url(#loginLogoGlow)">
        <path d="M10 8 L10 28" stroke="url(#loginLogoGrad)" strokeWidth="3" strokeLinecap="round" fill="none"/>
        <path d="M11 18 L21 8" stroke="#ffffff" strokeWidth="3" strokeLinecap="round" fill="none"/>
        <path d="M11 18 L21 28" stroke="#a0a0a8" strokeWidth="3" strokeLinecap="round" fill="none"/>
      </g>
      <rect x="25" y="21" width="5" height="7" rx="1" fill="#e0e0e0"/>
    </svg>
  );
}

export default function Login() {
  const { login, isAuthenticated, isLoading } = useAuth();
  const [, setLocation] = useLocation();
  const [sessionExpired, setSessionExpired] = useState(false);
  const [accountDisabled, setAccountDisabled] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    const expired = sessionStorage.getItem("tokenExpired");
    if (expired === "true") {
      setSessionExpired(true);
      sessionStorage.removeItem("tokenExpired");
    }

    const disabled = sessionStorage.getItem("accountDisabled");
    if (disabled === "true") {
      setAccountDisabled(true);
      sessionStorage.removeItem("accountDisabled");
    }

    const error = sessionStorage.getItem("authError");
    if (error) {
      setAuthError(error);
      sessionStorage.removeItem("authError");
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      setLocation("/app");
    }
  }, [isAuthenticated, isLoading, setLocation]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center animate-pulse">
            <Terminal className="h-6 w-6 text-primary" />
          </div>
          <p className="text-sm text-muted-foreground">Initializing...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="border-b border-border">
        <div className="container mx-auto px-4 sm:px-6 py-4 flex items-center gap-3">
          <KeyleSSHLogo className="h-8 w-8 sm:h-9 sm:w-9" />
          <span className="font-semibold text-base sm:text-lg text-foreground">KeyleSSH</span>
        </div>
      </header>

      <main className="flex-1 container mx-auto px-4 sm:px-6 py-8 sm:py-12 flex flex-col lg:flex-row items-center justify-center gap-8 sm:gap-12">
        <div className="flex-1 max-w-lg hidden sm:block">
          <div className="space-y-6">
            <div className="space-y-2">
              <h1 className="text-3xl font-semibold tracking-tight text-foreground">
                Secure SSH Access
              </h1>
              <p className="text-lg text-muted-foreground">
                Connect to your servers securely from anywhere with KeyleSSH Web Console
              </p>
            </div>

            <div className="space-y-4">
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <Shield className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-medium text-foreground">OIDC Authentication</h3>
                  <p className="text-sm text-muted-foreground">
                    Secure single sign-on with Tidecloak identity provider
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <Server className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-medium text-foreground">Multi-Server Access</h3>
                  <p className="text-sm text-muted-foreground">
                    Connect to multiple servers with role-based permissions
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <Key className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-medium text-foreground">Keyless SSH</h3>
                  <p className="text-sm text-muted-foreground">
                    No SSH keys to manage - authenticate with your identity provider
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="w-full max-w-md">
          <Card className="border-border">
            <CardHeader className="space-y-1 pb-4">
              <CardTitle className="text-xl">Sign in to KeyleSSH</CardTitle>
              <CardDescription>
                Authenticate with your organization's identity provider
              </CardDescription>
              {sessionExpired && (
                <p className="text-sm text-destructive mt-2">
                  Your session has expired. Please sign in again.
                </p>
              )}
              {accountDisabled && (
                <p className="text-sm text-destructive mt-2">
                  Your account has been disabled. Please contact an administrator to regain access.
                </p>
              )}
              {authError && !accountDisabled && !sessionExpired && (
                <p className="text-sm text-destructive mt-2">
                  Authentication failed: {authError}
                </p>
              )}
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                onClick={login}
                className="w-full gap-2"
                size="lg"
                data-testid="login-button"
              >
                Sign in with Tidecloak
                <ArrowRight className="h-4 w-4" />
              </Button>

              <div className="text-center">
                <p className="text-xs text-muted-foreground">
                  By signing in, you agree to your organization's security policies
                </p>
              </div>

              <div className="pt-4 border-t border-border">
                <div className="flex items-center justify-center gap-2 mb-4">
                  <Building2 className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">New to KeyleSSH?</span>
                  <Link href="/onboarding" className="text-sm text-primary hover:underline font-medium">
                    Register your organization
                  </Link>
                </div>
              </div>

              <div className="pt-4 border-t border-border">
                <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
                  <span className="h-2 w-2 rounded-full bg-chart-2" />
                  <span>System operational</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>

      <footer className="border-t border-border py-4 sm:py-6">
        <div className="container mx-auto px-4 sm:px-6 text-center text-xs sm:text-sm text-muted-foreground">
          <p>Powered by KeyleSSH &middot; Tide Foundation</p>
        </div>
      </footer>
    </div>
  );
}
