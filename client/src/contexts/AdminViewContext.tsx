import { createContext, useContext, useState, useEffect, type ReactNode } from "react";
import { useSearch } from "wouter";

type AdminView = "users" | "roles" | "servers" | "sessions" | "approvals" | "logs";
type LogsTab = "access";

interface AdminViewContextType {
  view: AdminView;
  setView: (view: AdminView) => void;
  logsTab: LogsTab;
  setLogsTab: (tab: LogsTab) => void;
}

const AdminViewContext = createContext<AdminViewContextType | undefined>(undefined);

export function AdminViewProvider({ children }: { children: ReactNode }) {
  const searchString = useSearch();
  const [view, setView] = useState<AdminView>("users");
  const [logsTab, setLogsTab] = useState<LogsTab>("access");

  // Handle URL parameters for initial view
  useEffect(() => {
    const params = new URLSearchParams(searchString);
    const tabParam = params.get("tab");
    const logsTabParam = params.get("logsTab");

    if (
      tabParam === "users" ||
      tabParam === "roles" ||
      tabParam === "servers" ||
      tabParam === "sessions" ||
      tabParam === "approvals" ||
      tabParam === "logs"
    ) {
      setView(tabParam as AdminView);
    }

    if (logsTabParam === "access") {
      setLogsTab(logsTabParam as LogsTab);
    }
  }, [searchString]);

  return (
    <AdminViewContext.Provider value={{ view, setView, logsTab, setLogsTab }}>
      {children}
    </AdminViewContext.Provider>
  );
}

export function useAdminView() {
  const context = useContext(AdminViewContext);
  if (context === undefined) {
    throw new Error("useAdminView must be used within an AdminViewProvider");
  }
  return context;
}
