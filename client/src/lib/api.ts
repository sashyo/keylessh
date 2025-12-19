import type {
  Server,
  Session,
  ServerWithAccess,
  ActiveSession,
  AdminUser,
  AdminRole,
} from "@shared/schema";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

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
      list: () => apiRequest<AdminUser[]>("/api/admin/users"),
      add: (data: { username: string; firstName: string; lastName: string; email: string }) =>
        apiRequest<{ message: string }>("/api/admin/users/add", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      updateProfile: (data: { id: string; firstName: string; lastName: string; email: string }) =>
        apiRequest<{ message: string }>("/api/admin/users", {
          method: "PUT",
          body: JSON.stringify(data),
        }),
      updateRoles: (data: { id: string; rolesToAdd?: string[]; rolesToRemove?: string[] }) =>
        apiRequest<{ message: string }>("/api/admin/users", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      delete: (userId: string) =>
        apiRequest<{ success: boolean }>(`/api/admin/users?userId=${userId}`, {
          method: "DELETE",
        }),
      getTideLinkUrl: (userId: string, redirectUri?: string) =>
        apiRequest<{ linkUrl: string }>(
          `/api/admin/users/tide?userId=${userId}${redirectUri ? `&redirect_uri=${encodeURIComponent(redirectUri)}` : ""}`
        ),
    },
    roles: {
      list: () => apiRequest<{ roles: AdminRole[] }>("/api/admin/roles"),
      listAll: () => apiRequest<{ roles: AdminRole[] }>("/api/admin/roles/all"),
      create: (data: { name: string; description?: string }) =>
        apiRequest<{ success: string }>("/api/admin/roles", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      update: (data: { name: string; description?: string }) =>
        apiRequest<{ success: string }>("/api/admin/roles", {
          method: "PUT",
          body: JSON.stringify(data),
        }),
      delete: (roleName: string) =>
        apiRequest<{ success: string }>(`/api/admin/roles?roleName=${roleName}`, {
          method: "DELETE",
        }),
    },
    sessions: {
      list: () => apiRequest<ActiveSession[]>("/api/admin/sessions"),
    },
    approvals: {
      list: () => apiRequest<PendingApproval[]>("/api/admin/approvals"),
      create: (data: {
        type: ApprovalType;
        data: any;
        targetUserId?: string;
        targetUserEmail?: string;
      }) =>
        apiRequest<{ message: string; id: string }>("/api/admin/approvals", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      addDecision: (approvalId: string, decision: boolean) =>
        apiRequest<{ message: string }>("/api/admin/approvals", {
          method: "POST",
          body: JSON.stringify({ approvalId, decision }),
        }),
      commit: (id: string) =>
        apiRequest<{ message: string }>(`/api/admin/approvals/${id}/commit`, {
          method: "PUT",
        }),
      cancel: (id: string) =>
        apiRequest<{ message: string }>(`/api/admin/approvals/${id}/cancel`, {
          method: "PUT",
        }),
      delete: (id: string) =>
        apiRequest<{ message: string }>(`/api/admin/approvals?id=${id}`, {
          method: "DELETE",
        }),
    },
    logs: {
      access: (limit?: number, offset?: number) =>
        apiRequest<AccessChangeLog[]>(
          `/api/admin/logs/access?limit=${limit || 100}&offset=${offset || 0}`
        ),
    },
    accessApprovals: {
      list: () => apiRequest<AccessApproval[]>("/api/admin/access-approvals"),
      getRaw: (changeSet: ChangeSetRequest) =>
        apiRequest<{ rawRequest: string }>("/api/admin/access-approvals/raw", {
          method: "POST",
          body: JSON.stringify({ changeSet }),
        }),
      approve: (changeSet: ChangeSetRequest, signedRequest?: string) =>
        apiRequest<{ message: string }>("/api/admin/access-approvals/approve", {
          method: "POST",
          body: JSON.stringify({ changeSet, signedRequest }),
        }),
      reject: (changeSet: ChangeSetRequest) =>
        apiRequest<{ message: string }>("/api/admin/access-approvals/reject", {
          method: "POST",
          body: JSON.stringify({ changeSet }),
        }),
      commit: (changeSet: ChangeSetRequest) =>
        apiRequest<{ message: string }>("/api/admin/access-approvals/commit", {
          method: "POST",
          body: JSON.stringify({ changeSet }),
        }),
      cancel: (changeSet: ChangeSetRequest) =>
        apiRequest<{ message: string }>("/api/admin/access-approvals/cancel", {
          method: "POST",
          body: JSON.stringify({ changeSet }),
        }),
    },
  },
};

// Approval types
export type ApprovalType = 'user_create' | 'user_update' | 'user_delete' | 'role_assign' | 'role_remove';
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'committed' | 'cancelled';

export interface PendingApproval {
  id: string;
  type: ApprovalType;
  requestedBy: string;
  targetUserId?: string;
  targetUserEmail?: string;
  data: string;
  status: ApprovalStatus;
  createdAt: number;
  updatedAt?: number;
  approvedBy?: string[];
  deniedBy?: string[];
}

export interface AccessChangeLog {
  id: number;
  timestamp: number;
  type: string;
  approvalId: string;
  userEmail: string;
  targetUser?: string;
  details?: string;
}

// TideCloak Change Set Types
export interface ChangeSetRequest {
  changeSetId: string;
  changeSetType: string;
  actionType: string;
}

export interface AccessApproval {
  id: string;
  timestamp: string;
  username: string;
  role: string;
  clientId: string;
  commitReady: boolean;
  decisionMade: boolean;
  rejectionFound: boolean;
  retrievalInfo: ChangeSetRequest;
  data: any;
}

// SSH connections are now handled via Socket.IO to KeyleSSH
// See Console.tsx for the Socket.IO implementation
