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
import { Terminal, Server, Users, Activity, LogOut, Shield, ChevronDown, Layers, ScrollText, KeyRound, CheckSquare } from "lucide-react";
import type { ReactNode } from "react";

interface AppLayoutProps {
  children: ReactNode;
}

const userNavItems = [
  { title: "Dashboard", url: "/app", icon: Terminal },
];

const adminNavItems = [
  { title: "Admin Dashboard", url: "/admin", icon: Shield },
  { title: "Manage Servers", url: "/admin/servers", icon: Server },
  { title: "Manage Users", url: "/admin/users", icon: Users },
  { title: "Manage Roles", url: "/admin/roles", icon: KeyRound },
  { title: "Approvals", url: "/admin/approvals", icon: CheckSquare },
  { title: "All Sessions", url: "/admin/sessions", icon: Activity },
  { title: "Access Logs", url: "/admin/logs", icon: ScrollText },
];

export function AppLayout({ children }: AppLayoutProps) {
  const { user, logout, hasRole } = useAuth();
  const [location] = useLocation();
  const isAdmin = hasRole("admin");

  const style = {
    "--sidebar-width": "16rem",
    "--sidebar-width-icon": "3rem",
  };

  return (
    <SidebarProvider style={style as React.CSSProperties}>
      <div className="flex h-screen w-full bg-background">
        <Sidebar className="border-r border-sidebar-border">
          <SidebarHeader className="p-4 border-b border-sidebar-border">
            <Link href="/app" className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary">
                <Terminal className="h-5 w-5 text-primary-foreground" />
              </div>
              <div className="flex flex-col">
                <span className="font-semibold text-sidebar-foreground">KeyleSSH</span>
                <span className="text-xs text-muted-foreground">Web Console</span>
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
              <SidebarGroup className="mt-4">
                <SidebarGroupLabel className="text-xs font-medium uppercase tracking-wide text-muted-foreground px-2 py-2">
                  Administration
                </SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {adminNavItems.map((item) => (
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
            )}
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
              <Badge variant="outline" className="hidden sm:flex gap-1.5 items-center">
                <span className="h-2 w-2 rounded-full bg-chart-2 animate-pulse" />
                Online
              </Badge>
            </div>
          </header>

          <main className="flex-1 overflow-auto bg-background">
            {children}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
