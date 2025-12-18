import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Terminal, ArrowLeft, Home } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-6">
      <div className="flex flex-col items-center text-center max-w-md space-y-6">
        <div className="flex h-16 w-16 items-center justify-center rounded-xl bg-primary/10">
          <Terminal className="h-8 w-8 text-primary" />
        </div>
        
        <div className="space-y-2">
          <h1 className="text-4xl font-semibold tracking-tight">404</h1>
          <h2 className="text-xl font-medium text-muted-foreground">Page Not Found</h2>
          <p className="text-sm text-muted-foreground">
            The page you're looking for doesn't exist or has been moved.
          </p>
        </div>
        
        <div className="flex flex-wrap gap-3 justify-center">
          <Link href="/app">
            <Button data-testid="go-home-button">
              <Home className="h-4 w-4 mr-2" />
              Go to Dashboard
            </Button>
          </Link>
          <Button variant="outline" onClick={() => window.history.back()} data-testid="go-back-button">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Go Back
          </Button>
        </div>
      </div>
    </div>
  );
}
