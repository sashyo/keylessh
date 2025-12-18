import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Terminal, Shield, Server, Key, ArrowRight } from "lucide-react";
import { useEffect } from "react";
import { useLocation } from "wouter";

export default function Login() {
  const { login, isAuthenticated, isLoading } = useAuth();
  const [, setLocation] = useLocation();

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
        <div className="container mx-auto px-6 py-4 flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary">
            <Terminal className="h-5 w-5 text-primary-foreground" />
          </div>
          <span className="font-semibold text-lg">KeyleSSH</span>
        </div>
      </header>

      <main className="flex-1 container mx-auto px-6 py-12 flex flex-col lg:flex-row items-center justify-center gap-12">
        <div className="flex-1 max-w-lg">
          <div className="space-y-6">
            <div className="space-y-2">
              <h1 className="text-3xl font-semibold tracking-tight">
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
                  <h3 className="font-medium">OIDC Authentication</h3>
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
                  <h3 className="font-medium">Multi-Server Access</h3>
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
                  <h3 className="font-medium">Passwordless SSH</h3>
                  <p className="text-sm text-muted-foreground">
                    KeyleSSH handles authentication - no SSH keys needed
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
                <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
                  <span className="h-2 w-2 rounded-full bg-chart-2" />
                  <span>System operational</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>

      <footer className="border-t border-border py-6">
        <div className="container mx-auto px-6 text-center text-sm text-muted-foreground">
          <p>Powered by KeyleSSH &middot; Tide Foundation</p>
        </div>
      </footer>
    </div>
  );
}
