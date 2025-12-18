import type { Server, Session, User, ServerWithAccess, ActiveSession } from "@shared/schema";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
const WS_BASE = import.meta.env.VITE_WS_BASE_URL || "";
const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem("access_token");
  
  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(token && { Authorization: `Bearer ${token}` }),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: "Request failed" }));
    throw new Error(error.message || `HTTP ${response.status}`);
  }

  return response.json();
}

export const api = {
  servers: {
    list: () => apiRequest<ServerWithAccess[]>("/api/servers"),
    get: (id: string) => apiRequest<ServerWithAccess>(`/api/servers/${id}`),
  },
  sessions: {
    list: () => apiRequest<ActiveSession[]>("/api/sessions"),
    create: (data: { serverId: string; sshUser: string }) =>
      apiRequest<Session>("/api/sessions", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    end: (id: string) =>
      apiRequest<void>(`/api/sessions/${id}`, { method: "DELETE" }),
  },
  admin: {
    servers: {
      list: () => apiRequest<Server[]>("/api/admin/servers"),
      create: (data: Partial<Server>) =>
        apiRequest<Server>("/api/admin/servers", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      update: (id: string, data: Partial<Server>) =>
        apiRequest<Server>(`/api/admin/servers/${id}`, {
          method: "PATCH",
          body: JSON.stringify(data),
        }),
      delete: (id: string) =>
        apiRequest<void>(`/api/admin/servers/${id}`, { method: "DELETE" }),
    },
    users: {
      list: () => apiRequest<User[]>("/api/admin/users"),
      update: (id: string, data: Partial<User>) =>
        apiRequest<User>(`/api/admin/users/${id}`, {
          method: "PATCH",
          body: JSON.stringify(data),
        }),
    },
    sessions: {
      list: () => apiRequest<ActiveSession[]>("/api/admin/sessions"),
    },
  },
};

export function getWebSocketUrl(sessionId: string): string {
  const token = localStorage.getItem("access_token");
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = WS_BASE || window.location.host;
  return `${protocol}//${host}/ws?session=${sessionId}&token=${token}`;
}

export { USE_MOCK };
