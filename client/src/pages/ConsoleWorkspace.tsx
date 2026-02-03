import { useEffect, useMemo, useState } from "react";
import { useLocation, useSearch } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ServerWithAccess } from "@shared/schema";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Plus, Terminal, X } from "lucide-react";
import { TerminalSession } from "@/components/TerminalSession";

type ConsoleTab = { id: string; serverId: string; sshUser: string };

function newId() {
  // Prefer crypto.randomUUID when available; fallback to timestamp+random.
  return (globalThis.crypto && "randomUUID" in globalThis.crypto)
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

const STORAGE_KEY = "keylessh.consoleWorkspaceTabs.v1";

export default function ConsoleWorkspace() {
  const [, setLocation] = useLocation();
  const search = useSearch();
  const searchParams = useMemo(() => new URLSearchParams(search), [search]);
  const queryClient = useQueryClient();

  const { data: servers } = useQuery<ServerWithAccess[]>({
    queryKey: ["/api/servers"],
  });

  const serversById = useMemo(() => {
    const map = new Map<string, ServerWithAccess>();
    for (const s of servers || []) map.set(s.id, s);
    return map;
  }, [servers]);

  const [tabs, setTabs] = useState<ConsoleTab[]>(() => {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw) as ConsoleTab[];
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((t) => t && typeof t.id === "string" && typeof t.serverId === "string" && typeof t.sshUser === "string");
    } catch {
      return [];
    }
  });

  const [activeTabId, setActiveTabId] = useState<string>(() => tabs[0]?.id || "");

  useEffect(() => {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(tabs));
    } catch {
      // ignore
    }
    if (!activeTabId && tabs.length > 0) {
      setActiveTabId(tabs[0].id);
    }
    if (tabs.length === 0 && activeTabId) {
      setActiveTabId("");
    }
  }, [activeTabId, tabs]);

  // Show browser "Leave site?" confirmation when there are open terminal tabs.
  // Ctrl+W (close tab) is a browser-level action that JavaScript cannot block,
  // but beforeunload at least gives the user a chance to cancel.
  useEffect(() => {
    if (tabs.length === 0) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [tabs.length]);

  const addTab = (serverId: string, sshUser: string) => {
    const id = newId();
    const next: ConsoleTab = { id, serverId, sshUser };
    setTabs((prev) => [...prev, next]);
    setActiveTabId(id);
  };

  const closeTab = (tabId: string) => {
    setTabs((prev) => {
      const next = prev.filter((t) => t.id !== tabId);
      if (activeTabId === tabId) {
        setActiveTabId(next[0]?.id || "");
      }
      return next;
    });
  };

  // Support opening a new tab via URL query: /app/console?serverId=...&user=...
  useEffect(() => {
    const serverId = searchParams.get("serverId");
    const sshUser = searchParams.get("user");
    if (!serverId || !sshUser) return;

    addTab(serverId, sshUser);
    setLocation("/app/console");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, setLocation]);

  // New tab dialog state
  const [newTabOpen, setNewTabOpen] = useState(false);
  const [selectedServerId, setSelectedServerId] = useState<string>("");
  const selectedServer = selectedServerId ? serversById.get(selectedServerId) : undefined;
  const [selectedSshUser, setSelectedSshUser] = useState<string>("");

  useEffect(() => {
    if (!selectedServer) return;
    const firstAllowed = selectedServer.allowedSshUsers[0] || "";
    setSelectedSshUser(firstAllowed);
  }, [selectedServerId]); // intentionally only when server selection changes

  const openNewTab = () => {
    if (!selectedServerId || !selectedSshUser) return;
    addTab(selectedServerId, selectedSshUser);
    setNewTabOpen(false);
  };

  const activeTab = tabs.find((t) => t.id === activeTabId) || null;

  return (
    <div className="h-full p-2 sm:p-4 flex flex-col gap-2 sm:gap-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Terminal className="h-5 w-5 text-[hsl(var(--neon-cyan))] shrink-0" />
          <h1 className="text-base sm:text-lg font-semibold truncate">Terminal Workspace</h1>
        </div>
        <Button variant="neon" onClick={() => setNewTabOpen(true)} data-testid="new-terminal-tab" className="shrink-0" title="New tab">
          <Plus className="h-4 w-4 sm:mr-2" />
          <span className="hidden sm:inline">New tab</span>
        </Button>
      </div>

      {tabs.length === 0 ? (
        <div className="flex-1 min-h-[420px] flex items-center justify-center rounded-xl border border-[hsl(var(--neon-cyan)/0.2)] bg-[hsl(var(--bg-surface))] relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-[hsl(var(--neon-cyan)/0.05)] to-transparent pointer-events-none" />
          <div className="text-center space-y-3 max-w-md px-4 relative z-10">
            <div className="w-16 h-16 mx-auto rounded-xl bg-[hsl(var(--neon-cyan)/0.1)] border border-[hsl(var(--neon-cyan)/0.3)] flex items-center justify-center mb-4">
              <Terminal className="h-8 w-8 text-[hsl(var(--neon-cyan))]" />
            </div>
            <h2 className="text-base font-medium text-[hsl(var(--neon-cyan))]">No terminal tabs open</h2>
            <p className="text-sm text-muted-foreground">
              Click <span className="font-medium text-[hsl(var(--neon-cyan))]">New tab</span>, or open a server from the dashboard to start a terminal session.
            </p>
          </div>
        </div>
      ) : (
        <Tabs
          value={activeTabId}
          onValueChange={(nextId) => {
            setActiveTabId(nextId);
            const tab = tabs.find((t) => t.id === nextId);
            if (!tab) return;
            void queryClient.refetchQueries({ queryKey: ["/api/servers"] });
            void queryClient.refetchQueries({ queryKey: ["/api/servers", tab.serverId] });
          }}
          className="flex-1 min-h-0 flex flex-col"
        >
          <TabsList className="w-full justify-start overflow-x-auto">
            {tabs.map((tab) => {
              const s = serversById.get(tab.serverId);
              const label = s ? `${s.name} · ${tab.sshUser}` : `${tab.serverId} · ${tab.sshUser}`;
              return (
                <TabsTrigger key={tab.id} value={tab.id} className="gap-2">
                  <span className="max-w-[220px] truncate">{label}</span>
                  <span
                    role="button"
                    tabIndex={0}
                    className="inline-flex h-5 w-5 items-center justify-center rounded hover:bg-muted"
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      closeTab(tab.id);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        e.stopPropagation();
                        closeTab(tab.id);
                      }
                    }}
                    aria-label="Close tab"
                    title="Close tab"
                  >
                    <X className="h-3.5 w-3.5" />
                  </span>
                </TabsTrigger>
              );
            })}
          </TabsList>

          {tabs.map((tab) => (
            <TabsContent
              key={tab.id}
              value={tab.id}
              forceMount
              className="flex-1 min-h-0 mt-4 data-[state=inactive]:hidden"
            >
              <TerminalSession
                serverId={tab.serverId}
                sshUser={tab.sshUser}
                isActive={activeTabId === tab.id}
                onCloseTab={() => closeTab(tab.id)}
              />
            </TabsContent>
          ))}
        </Tabs>
      )}

      <Dialog open={newTabOpen} onOpenChange={setNewTabOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New terminal tab</DialogTitle>
            <DialogDescription>Select a server and SSH user to open a new terminal session.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>Server</Label>
              <Select value={selectedServerId} onValueChange={setSelectedServerId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select server" />
                </SelectTrigger>
                <SelectContent>
                  {(servers || []).map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>SSH User</Label>
              <Select
                value={selectedSshUser}
                onValueChange={setSelectedSshUser}
                disabled={!selectedServer || selectedServer.allowedSshUsers.length === 0}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select SSH user" />
                </SelectTrigger>
                <SelectContent>
                  {(selectedServer?.allowedSshUsers || []).map((u) => (
                    <SelectItem key={u} value={u}>
                      {u}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setNewTabOpen(false)}>
              Cancel
            </Button>
            <Button onClick={openNewTab} disabled={!selectedServerId || !selectedSshUser}>
              Open tab
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
