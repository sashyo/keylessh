import { Link, useLocation } from "wouter";
import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Server, Users, Activity, LogOut, Shield, ChevronDown, Layers, ScrollText, KeyRound, CheckSquare, RefreshCw, FileCode, CreditCard, Video, Zap } from "lucide-react";

function KeyleSSHLogo({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 36 36" className={className} xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#ffffff"/>
          <stop offset="100%" stopColor="#a0a0a8"/>
        </linearGradient>
        <filter id="logoGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      <rect width="36" height="36" rx="8" fill="hsl(120 15% 8%)"/>
      <g filter="url(#logoGlow)">
        <path d="M10 8 L10 28" stroke="url(#logoGrad)" strokeWidth="3" strokeLinecap="round" fill="none"/>
        <path d="M11 18 L21 8" stroke="#ffffff" strokeWidth="3" strokeLinecap="round" fill="none"/>
        <path d="M11 18 L21 28" stroke="#a0a0a8" strokeWidth="3" strokeLinecap="round" fill="none"/>
      </g>
      <rect x="25" y="21" width="5" height="7" rx="1" fill="#e0e0e0"/>
    </svg>
  );
}
import { useEffect, useState, useMemo, type ReactNode } from "react";
import { useToast } from "@/hooks/use-toast";
import { queryClient } from "@/lib/queryClient";
import { useQuery } from "@tanstack/react-query";
import { api, type PricingInfo } from "@/lib/api";

interface AppLayoutProps {
  children: ReactNode;
}

const userNavItems = [
  { title: "Dashboard", url: "/app", icon: Zap },
  { title: "Console", url: "/app/console", icon: Zap },
];

// Admin nav organized by logical groups for better UX
const adminNavGroups = [
  {
    label: "Infrastructure",
    items: [
      { title: "Overview", url: "/admin", icon: Shield },
      { title: "Servers", url: "/admin/servers", icon: Server },
      { title: "Sessions", url: "/admin/sessions", icon: Activity },
    ],
  },
  {
    label: "Identity & Access",
    items: [
      { title: "Users", url: "/admin/users", icon: Users },
      { title: "Roles", url: "/admin/roles", icon: KeyRound },
      { title: "Policies", url: "/admin/policy-templates", icon: FileCode },
    ],
  },
  {
    label: "Security",
    items: [
      { title: "Approvals", url: "/admin/approvals", icon: CheckSquare },
      { title: "Recordings", url: "/admin/recordings", icon: Video },
      { title: "Audit Logs", url: "/admin/logs", icon: ScrollText },
    ],
  },
  {
    label: "Settings",
    items: [
      { title: "License", url: "/admin/license", icon: CreditCard },
    ],
  },
];

export function AppLayout({ children }: AppLayoutProps) {
  const { user, logout, hasRole, refreshToken } = useAuth();
  const { toast } = useToast();
  const [location] = useLocation();
  const isAdmin = hasRole("admin");
  const [isBrowserOnline, setIsBrowserOnline] = useState(() => navigator.onLine);

  // Check if Stripe is configured to determine if License page should be shown
  const { data: pricingInfo } = useQuery<PricingInfo>({
    queryKey: ["/api/admin/license/prices"],
    queryFn: api.admin.license.getPrices,
    enabled: isAdmin,
    staleTime: Infinity, // Only fetch once per session
  });

  // Filter out Settings group if Stripe is not configured
  const filteredAdminNavGroups = useMemo(() => {
    if (pricingInfo?.stripeConfigured === false) {
      return adminNavGroups.filter(group => group.label !== "Settings");
    }
    return adminNavGroups;
  }, [pricingInfo?.stripeConfigured]);

  // Refresh data when navigating between sections (React Query cache uses long-lived freshness by default).
  useEffect(() => {
    void queryClient.invalidateQueries();
  }, [location]);

  useEffect(() => {
    const onOnline = () => setIsBrowserOnline(true);
    const onOffline = () => setIsBrowserOnline(false);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, []);

  // Force dark mode for cyberpunk theme
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  const style = {
    "--sidebar-width": "16rem",
    "--sidebar-width-icon": "3rem",
  };

  return (
    <SidebarProvider style={style as React.CSSProperties}>
      <div className="flex h-screen w-full bg-background">
        <Sidebar className="border-r border-sidebar-border iso-surface">
          <SidebarHeader className="p-4 border-b border-sidebar-border">
            <Link href="/app" className="flex items-center gap-3 group">
              <div className="relative">
                <KeyleSSHLogo className="h-9 w-9 transition-transform group-hover:scale-105" />
              </div>
              <div className="flex flex-col">
                <span className="font-semibold text-[hsl(0_0%_90%)] drop-shadow-[0_0_8px_rgba(255,255,255,0.4)]">
                  KeyleSSH
                </span>
                <span className="text-xs text-muted-foreground">Secure Shell</span>
              </div>
            </Link>
          </SidebarHeader>

          <SidebarContent className="p-2">
            <SidebarGroup>
              <SidebarGroupLabel className="text-xs font-medium uppercase tracking-wide text-muted-foreground px-2 py-2">
                Navigation
              </SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {userNavItems.map((item) => (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton
                        asChild
                        isActive={location === item.url || (item.url !== "/app" && location.startsWith(item.url))}
                        data-testid={`nav-${item.title.toLowerCase().replace(/\s+/g, "-")}`}
                      >
                        <Link href={item.url}>
                          <item.icon className="h-4 w-4" />
                          <span>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>

            {isAdmin && (
              <div className="my-3 mx-2 border-t border-sidebar-border" />
            )}

            {isAdmin && filteredAdminNavGroups.map((group) => (
              <SidebarGroup key={group.label} className="mt-2">
                <SidebarGroupLabel className="text-xs font-medium uppercase tracking-wide text-muted-foreground px-2 py-1.5">
                  {group.label}
                </SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {group.items.map((item) => (
                      <SidebarMenuItem key={item.title}>
                        <SidebarMenuButton
                          asChild
                          isActive={location === item.url || (item.url !== "/admin" && location.startsWith(item.url))}
                          data-testid={`nav-${item.title.toLowerCase().replace(/\s+/g, "-")}`}
                        >
                          <Link href={item.url}>
                            <item.icon className="h-4 w-4" />
                            <span>{item.title}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    ))}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            ))}
          </SidebarContent>

          <SidebarFooter className="p-4 border-t border-sidebar-border">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="w-full justify-start gap-3 px-2" data-testid="user-menu-trigger">
                  <Avatar className="h-8 w-8">
                    <AvatarFallback className="bg-primary/10 text-primary text-sm font-medium">
                      {user?.username?.slice(0, 2).toUpperCase() || "U"}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex flex-1 flex-col items-start text-left">
                    <span className="text-sm font-medium truncate max-w-[120px]">{user?.username}</span>
                    <span className="text-xs text-muted-foreground truncate max-w-[120px]">{user?.email}</span>
                  </div>
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <div className="px-2 py-2">
                  <p className="text-sm font-medium">{user?.username}</p>
                  <p className="text-xs text-muted-foreground">{user?.email}</p>
                  <Badge variant="secondary" className="mt-2 text-xs">
                    {user?.role === "admin" ? "Administrator" : "User"}
                  </Badge>
                </div>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={() => {
                    void (async () => {
                      const ok = await refreshToken();
                      toast({
                        title: ok ? "Token refreshed" : "Token refresh unavailable",
                        description: ok
                          ? "Your roles/claims have been updated for this session."
                          : "If your roles just changed, try a full page reload.",
                        variant: ok ? "default" : "destructive",
                      });
                    })();
                  }}
                  data-testid="refresh-token-button"
                >
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Refresh token
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={logout} className="text-destructive focus:text-destructive" data-testid="logout-button">
                  <LogOut className="mr-2 h-4 w-4" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarFooter>
        </Sidebar>

        <div className="flex flex-1 flex-col overflow-hidden">
          <header className="flex h-14 items-center justify-between gap-4 border-b border-border bg-background px-4">
            <div className="flex items-center gap-4">
              <SidebarTrigger data-testid="sidebar-trigger" />
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium text-muted-foreground">
                  {location.split("/").filter(Boolean).map((s, i) => (
                    <span key={i}>
                      {i > 0 && " / "}
                      <span className={i === location.split("/").filter(Boolean).length - 1 ? "text-foreground" : ""}>
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </span>
                    </span>
                  ))}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <Badge
                variant="outline"
                className={`hidden sm:flex gap-1.5 items-center ${isBrowserOnline ? "label-success" : "label-danger"}`}
              >
                <span
                  className={`h-2 w-2 rounded-full ${isBrowserOnline ? "bg-[hsl(var(--neon-green))] neon-pulse" : "bg-destructive"}`}
                />
                {isBrowserOnline ? "Online" : "Offline"}
              </Badge>
            </div>
          </header>

          <main className="flex-1 overflow-auto bg-background iso-canvas">
            {children}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
