import type {
  Server,
  Session,
  ServerWithAccess,
  ActiveSession,
  AdminUser,
  AdminRole,
  PolicyTemplate,
  InsertPolicyTemplate,
  TemplateParameter,
  Bridge,
  InsertBridge,
  SignalServer,
  InsertSignalServer,
} from "@shared/schema";

import { IAMService } from "@tidecloak/js";
import { appFetch } from "./appFetch";
import * as tc from "./tidecloakAdmin";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

function toAbsoluteUrl(path: string): string {
  if (path.startsWith("http://") || path.startsWith("https://")) return path;
  return `${window.location.origin}${path}`;
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  // Use the managed token so secureFetch recognises it and attaches DPoP.
  // localStorage may hold a stale token after a refresh, causing a mismatch.
  const token = await IAMService.getToken();

  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(token && { Authorization: `Bearer ${token}` }),
    ...options.headers,
  };

  const response = await appFetch(toAbsoluteUrl(`${API_BASE}${endpoint}`), {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: "Request failed" }));
    throw new Error(error.message || `HTTP ${response.status}`);
  }

  // Handle 204 No Content (common for DELETE)
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

// Forseti contract ID computation result
export interface ForsetiCompileResult {
  success: boolean;
  contractId?: string;
  error?: string;
}

// Committed policy result
export interface CommittedPolicyResult {
  roleId: string;
  policyData: string; // Base64 encoded policy bytes
}

export const api = {
  // Forseti contract operations
  forseti: {
    /**
     * Computes the contract ID (SHA512 hash) from source code.
     */
    compile: (source: string) =>
      apiRequest<ForsetiCompileResult>("/api/forseti/compile", {
        method: "POST",
        body: JSON.stringify({ source }),
      }),
  },
  // SSH policy operations
  sshPolicies: {
    /**
     * Gets the committed policy for an SSH user.
     * Role format is ssh:<sshUser>, e.g. ssh:root, ssh:ubuntu
     * Used to attach policy to SSH signing requests.
     */
    getForSshUser: (sshUser: string) =>
      apiRequest<CommittedPolicyResult>(`/api/ssh-policies/for-ssh-user/${encodeURIComponent(sshUser)}`),

    /**
     * Gets the committed policy for a specific role.
     */
    getByRole: (roleId: string) =>
      apiRequest<CommittedPolicyResult>(`/api/ssh-policies/committed/${encodeURIComponent(roleId)}`),
  },
  ssh: {
    getAccessStatus: async () => {
      let enabledUsers = 0;
      try {
        const users = await tc.getUsers();
        enabledUsers = users.filter(u => u.enabled !== false).length;
      } catch { /* TideCloak unavailable, pass 0 */ }
      return apiRequest<{ blocked: boolean; reason?: string }>(`/api/ssh/access-status?enabledUsers=${enabledUsers}`);
    },
  },
  servers: {
    list: () => apiRequest<ServerWithAccess[]>("/api/servers"),
    get: (id: string) => apiRequest<ServerWithAccess>(`/api/servers/${id}`),
  },
  gatewayEndpoints: {
    list: () => apiRequest<GatewayEndpoint[]>("/api/gateway-endpoints"),
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
    bridges: {
      list: () => apiRequest<Bridge[]>("/api/admin/bridges"),
      get: (id: string) => apiRequest<Bridge>(`/api/admin/bridges/${id}`),
      create: (data: InsertBridge) =>
        apiRequest<Bridge>("/api/admin/bridges", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      update: (id: string, data: Partial<InsertBridge>) =>
        apiRequest<Bridge>(`/api/admin/bridges/${id}`, {
          method: "PUT",
          body: JSON.stringify(data),
        }),
      delete: (id: string) =>
        apiRequest<void>(`/api/admin/bridges/${id}`, { method: "DELETE" }),
    },
    signalServers: {
      list: () => apiRequest<SignalServer[]>("/api/admin/signal-servers"),
      get: (id: string) => apiRequest<SignalServer>(`/api/admin/signal-servers/${id}`),
      create: (data: InsertSignalServer) =>
        apiRequest<SignalServer>("/api/admin/signal-servers", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      update: (id: string, data: Partial<InsertSignalServer>) =>
        apiRequest<SignalServer>(`/api/admin/signal-servers/${id}`, {
          method: "PUT",
          body: JSON.stringify(data),
        }),
      delete: (id: string) =>
        apiRequest<void>(`/api/admin/signal-servers/${id}`, { method: "DELETE" }),
    },
    users: {
      list: async (): Promise<AdminUser[]> => {
        const usersWithRoles = await tc.getUsersWithRoles();
        return usersWithRoles.map((u: any) => ({
          id: u.id ?? "",
          firstName: u.firstName ?? "",
          lastName: u.lastName ?? "",
          email: u.email ?? "",
          username: u.username,
          role: u.clientRoles || [],
          linked: !!(u.attributes as any)?.vuid?.[0],
          enabled: u.enabled !== false,
          isAdmin: (u.clientRoles || []).includes("tide-realm-admin"),
        } as AdminUser));
      },
      add: async (data: { username: string; firstName: string; lastName: string; email: string }) => {
        await tc.addUser(data);
        return { message: "User added" };
      },
      updateProfile: async (data: { id: string; firstName: string; lastName: string; email: string }) => {
        await tc.updateUser(data.id, { firstName: data.firstName, lastName: data.lastName, email: data.email });
        return { message: "User updated" };
      },
      updateRoles: async (data: { id: string; rolesToAdd?: string[]; rolesToRemove?: string[] }) => {
        await Promise.all([
          ...(data.rolesToAdd || []).map(role => tc.grantUserRole(data.id, role)),
          ...(data.rolesToRemove || []).map(role => tc.removeUserRole(data.id, role)),
        ]);
        return { message: "Roles updated" };
      },
      delete: async (userId: string) => {
        await tc.deleteUser(userId);
        return { success: true };
      },
      getTideLinkUrl: async (userId: string, redirectUri?: string) => {
        const linkUrl = await tc.getTideLinkUrl(userId, redirectUri || window.location.origin);
        return { linkUrl };
      },
      getRoles: async (userId: string): Promise<string[]> => {
        // Fetch from both app client and realm-management client
        const [clientRoles, adminRoles] = await Promise.all([
          tc.getUserClientRoleMappings(userId),
          tc.getUserRealmManagementRoleMappings(userId),
        ]);
        const roles = clientRoles.map(r => r.name).filter((n): n is string => !!n);
        const admin = adminRoles.map(r => r.name).filter((n): n is string => !!n);
        return [...roles, ...admin];
      },
      setEnabled: async (userId: string, enabled: boolean) => {
        await tc.setUserEnabled(userId, enabled);
        return { success: true, enabled };
      },
    },
    roles: {
      list: async () => {
        const roles = await tc.getClientRoles();
        return { roles: roles as unknown as AdminRole[] };
      },
      listAll: async () => {
        const roles = await tc.getAllRoles();
        return { roles: roles as unknown as AdminRole[] };
      },
      create: async (data: { name: string; description?: string; policy?: SshPolicyConfig }) => {
        await tc.createRole({ name: data.name, description: data.description });
        return { success: "Role created" };
      },
      update: async (data: { name: string; description?: string }) => {
        await tc.updateRole(data);
        return { success: "Role updated" };
      },
      delete: async (roleName: string) => {
        const result = await tc.deleteRole(roleName);
        return { success: "Role deleted", approvalCreated: result.approvalCreated };
      },
      policies: {
        list: () => apiRequest<{ policies: SshPolicyResponse[] }>("/api/admin/roles/policies"),
        get: (roleName: string) =>
          apiRequest<{ policy: SshPolicyResponse }>(`/api/admin/roles/${encodeURIComponent(roleName)}/policy`),
      },
    },
    sessions: {
      list: () => apiRequest<ActiveSession[]>("/api/admin/sessions"),
      terminate: (id: string) =>
        apiRequest<{ success: boolean; terminated: boolean }>(
          `/api/admin/sessions/${id}/terminate`,
          { method: "POST" }
        ),
      getFileOperations: (sessionId: string) =>
        apiRequest<{ operations: FileOperationLog[] }>(
          `/api/admin/sessions/${sessionId}/file-operations`
        ),
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
      access: async (limit?: number, offset?: number) => {
        const events = await tc.getClientEvents(offset || 0, limit || 100);
        return events as unknown as TidecloakEvent[];
      },
      fileOperations: (limit?: number, offset?: number) =>
        apiRequest<{ operations: FileOperationLog[]; total: number }>(
          `/api/admin/logs/file-operations?limit=${limit || 100}&offset=${offset || 0}`
        ),
    },
    accessApprovals: {
      list: async (): Promise<AccessApproval[]> => {
        const data = await tc.getUserChangeRequests();
        return data.map((item) => {
          const firstUserRecord =
            item.data.userRecord && item.data.userRecord.length > 0
              ? item.data.userRecord[0]
              : null;
          return {
            id: item.data.draftRecordId,
            timestamp: new Date().toISOString(),
            username: firstUserRecord?.username || "Unknown",
            role: item.data.role || "Unknown",
            clientId: item.data.clientId || "Unknown",
            commitReady: item.data.status === "APPROVED" || item.data.deleteStatus === "APPROVED" || false,
            decisionMade: false,
            rejectionFound: false,
            retrievalInfo: item.retrievalInfo,
            data: item.data,
          } as AccessApproval;
        });
      },
      getRaw: async (changeSet: ChangeSetRequest) => {
        const rawRequests = await tc.getRawChangeSetRequest(changeSet);
        return { rawRequests };
      },
      approve: async (changeSet: ChangeSetRequest, signedRequest?: string) => {
        if (signedRequest) {
          await tc.addApprovalWithSignedRequest(changeSet, signedRequest);
        } else {
          await tc.addApprovalToChangeRequest(changeSet);
        }
        return { message: "Approval added" };
      },
      approveWithId: async (changeSetId: string, actionType: string, changeSetType: string, signedRequest: string) => {
        await tc.addApprovalWithSignedRequest({ changeSetId, actionType, changeSetType }, signedRequest);
        return { message: "Approval added" };
      },
      reject: async (changeSet: ChangeSetRequest) => {
        await tc.addRejectionToChangeRequest(changeSet);
        return { message: "Rejection added" };
      },
      commit: async (changeSet: ChangeSetRequest) => {
        await tc.commitChangeRequest(changeSet);
        return { message: "Change committed" };
      },
      cancel: async (changeSet: ChangeSetRequest) => {
        await tc.cancelChangeRequest(changeSet);
        return { message: "Change cancelled" };
      },
    },
    roleApprovals: {
      list: async (): Promise<RoleApproval[]> => {
        const requests = await tc.getRoleChangeRequests();
        return requests.map((req) => ({
          id: req.retrievalInfo.changeSetId,
          requestType: req.data.actionType || req.data.action,
          status: (req.data.actionType === "DELETE" ? req.data.deleteStatus : req.data.status) || "PENDING",
          requestedBy: req.data.userRecord?.[0]?.username || "Unknown",
          requestedAt: req.data.createdAt || new Date().toISOString(),
          role: req.data.role,
          compositeRole: req.data.compositeRole,
          clientId: req.data.clientId,
          changeSetType: req.data.changeSetType,
          userRecords: req.data.userRecord || [],
          retrievalInfo: req.retrievalInfo,
        })) as RoleApproval[];
      },
      getRaw: async (changeSet: ChangeSetRequest) => {
        const rawRequests = await tc.getRawChangeSetRequest(changeSet);
        return { rawRequests };
      },
      approve: async (changeSet: ChangeSetRequest, signedRequest?: string) => {
        if (signedRequest) {
          await tc.addApprovalWithSignedRequest(changeSet, signedRequest);
        } else {
          await tc.addApprovalToChangeRequest(changeSet);
        }
        return { message: "Approval added" };
      },
      approveWithId: async (changeSetId: string, actionType: string, changeSetType: string, signedRequest: string) => {
        await tc.addApprovalWithSignedRequest({ changeSetId, actionType, changeSetType }, signedRequest);
        return { message: "Approval added" };
      },
      reject: async (changeSet: ChangeSetRequest) => {
        await tc.addRejectionToChangeRequest(changeSet);
        return { message: "Rejection added" };
      },
      commit: async (changeSet: ChangeSetRequest) => {
        await tc.commitChangeRequest(changeSet);
        return { message: "Change committed" };
      },
      cancel: async (changeSet: ChangeSetRequest) => {
        await tc.cancelChangeRequest(changeSet);
        return { message: "Change cancelled" };
      },
    },
    sshPolicies: {
      listPending: () =>
        apiRequest<{ policies: PendingSshPolicy[] }>("/api/admin/ssh-policies/pending"),
      getPending: (id: string) =>
        apiRequest<{ policy: PendingSshPolicy; decisions: SshPolicyDecision[] }>(
          `/api/admin/ssh-policies/pending/${id}`
        ),
      create: (data: { policyRequest: string; roleName: string }) =>
        apiRequest<{ message: string; id: string }>("/api/admin/ssh-policies/pending", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      // Swarm-style approval: accepts full signed policyRequest, extracts ID from request
      approve: (policyRequest: string, rejected: boolean = false) =>
        apiRequest<{ message: string }>("/api/admin/ssh-policies/pending/approve", {
          method: "POST",
          body: JSON.stringify({ policyRequest, decision: { rejected } }),
        }),
      commit: async (id: string, signature?: string) => {
        const result = await apiRequest<{ success: boolean; syncData?: any }>(`/api/admin/ssh-policies/pending/${id}/commit`, {
          method: "POST",
          body: JSON.stringify({ signature }),
        });
        // Sync policy to TideCloak directly via DPoP
        if (result.syncData) {
          try {
            await tc.syncPolicyToTideCloak(result.syncData);
          } catch (e) {
            console.warn("Failed to sync policy to TideCloak:", e);
          }
        }
        return result;
      },
      cancel: (id: string) =>
        apiRequest<{ message: string }>(`/api/admin/ssh-policies/pending/${id}/cancel`, {
          method: "POST",
        }),
      revoke: (id: string) =>
        apiRequest<{ message: string }>(`/api/admin/ssh-policies/pending/${id}/revoke`, {
          method: "POST",
        }),
      getLogs: (limit?: number, offset?: number) =>
        apiRequest<{ logs: SshPolicyLog[] }>(
          `/api/admin/ssh-policies/logs?limit=${limit || 100}&offset=${offset || 0}`
        ),
    },
    policyTemplates: {
      list: () =>
        apiRequest<{ templates: PolicyTemplate[] }>("/api/admin/policy-templates"),
      get: (id: string) =>
        apiRequest<{ template: PolicyTemplate }>(`/api/admin/policy-templates/${id}`),
      create: (data: Omit<InsertPolicyTemplate, "createdBy">) =>
        apiRequest<{ template: PolicyTemplate }>("/api/admin/policy-templates", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      update: (id: string, data: Partial<Omit<InsertPolicyTemplate, "createdBy">>) =>
        apiRequest<{ template: PolicyTemplate }>(`/api/admin/policy-templates/${id}`, {
          method: "PUT",
          body: JSON.stringify(data),
        }),
      delete: (id: string) =>
        apiRequest<{ success: boolean }>(`/api/admin/policy-templates/${id}`, {
          method: "DELETE",
        }),
      preview: (id: string, params: Record<string, any>) =>
        apiRequest<{ code: string }>(`/api/admin/policy-templates/${id}/preview`, {
          method: "POST",
          body: JSON.stringify({ params }),
        }),
    },
    recordings: {
      list: (params?: { limit?: number; offset?: number; serverId?: string; userId?: string; search?: string }) => {
        const searchParams = new URLSearchParams();
        if (params?.limit) searchParams.set("limit", String(params.limit));
        if (params?.offset) searchParams.set("offset", String(params.offset));
        if (params?.serverId) searchParams.set("serverId", params.serverId);
        if (params?.userId) searchParams.set("userId", params.userId);
        if (params?.search) searchParams.set("search", params.search);
        const query = searchParams.toString();
        return apiRequest<RecordingsListResponse>(`/api/admin/recordings${query ? `?${query}` : ""}`);
      },
      get: (id: string) => apiRequest<RecordingDetails>(`/api/admin/recordings/${id}`),
      getStats: () => apiRequest<RecordingStats>("/api/admin/recordings/stats"),
      search: (id: string, query: string) =>
        apiRequest<{ matches: { index: number; context: string }[]; total: number }>(
          `/api/admin/recordings/${id}/search?q=${encodeURIComponent(query)}`
        ),
      delete: (id: string) =>
        apiRequest<{ success: boolean }>(`/api/admin/recordings/${id}`, { method: "DELETE" }),
      getDownloadUrl: (id: string) => `/api/admin/recordings/${id}/download`,
    },
    license: {
      get: async () => {
        let totalUsers = 0, enabledUsers = 0;
        try {
          const users = await tc.getUsers();
          totalUsers = users.length;
          enabledUsers = users.filter(u => u.enabled !== false).length;
        } catch { /* TideCloak unavailable, pass 0 */ }
        return apiRequest<LicenseInfo>(`/api/admin/license?totalUsers=${totalUsers}&enabledUsers=${enabledUsers}`);
      },
      checkLimit: async (resource: "user" | "server") => {
        let count = 0;
        if (resource === "user") {
          try {
            const users = await tc.getUsers();
            count = users.length;
          } catch { /* pass 0 */ }
        }
        return apiRequest<LimitCheck>(`/api/admin/license/check/${resource}${resource === "user" ? `?count=${count}` : ""}`);
      },
      createCheckout: (priceId: string) =>
        apiRequest<{ url: string }>("/api/admin/license/checkout", {
          method: "POST",
          body: JSON.stringify({ priceId }),
        }),
      syncCheckout: (sessionId: string) =>
        apiRequest<{ success: boolean; tier?: SubscriptionTier }>("/api/admin/license/sync", {
          method: "POST",
          body: JSON.stringify({ sessionId }),
        }),
      createPortal: () =>
        apiRequest<{ url: string }>("/api/admin/license/portal", {
          method: "POST",
        }),
      getBillingHistory: () => apiRequest<BillingHistoryItem[]>("/api/admin/license/billing"),
      getPrices: () => apiRequest<PricingInfo>("/api/admin/license/prices"),
      syncManual: (params: { subscriptionId?: string; customerId?: string }) =>
        apiRequest<{ success: boolean; tier: SubscriptionTier; status: string }>("/api/admin/license/sync-manual", {
          method: "POST",
          body: JSON.stringify(params),
        }),
    },
    gatewayConfigs: {
      list: () => apiRequest<GatewayConfigSummary[]>("/api/admin/gateway-configs"),
      get: (id: string) => apiRequest<GatewayConfigSummary>(`/api/admin/gateway-configs/${id}`),
      create: (data: any) => apiRequest<GatewayConfigSummary>("/api/admin/gateway-configs", { method: "POST", body: JSON.stringify(data) }),
      update: (id: string, data: any) => apiRequest<GatewayConfigSummary>(`/api/admin/gateway-configs/${id}`, { method: "PUT", body: JSON.stringify(data) }),
      delete: (id: string) => apiRequest<void>(`/api/admin/gateway-configs/${id}`, { method: "DELETE" }),
      downloadUrl: (id: string) => `/api/admin/gateway-configs/${id}/download`,
      vpnConfigUrl: (id: string) => `/api/admin/gateway-configs/${id}/vpn-config`,
      tidecloakConfigUrl: (id: string) => `/api/admin/gateway-configs/${id}/tidecloak-config`,
    },
  },
};

// Gateway config (managed from admin UI)
export interface GatewayConfigSummary {
  id: string;
  gatewayId: string;
  displayName: string | null;
  stunServerUrl: string | null;
  apiSecret: string | null;
  iceServers: string | null;
  turnServer: string | null;
  turnSecret: string | null;
  backends: string | null;
  tidecloakConfigB64: string | null;
  authServerPublicUrl: string | null;
  serverUrl: string | null;
  vpnEnabled: boolean;
  vpnSubnet: string;
  listenPort: number;
  healthPort: number;
  https: boolean;
  tlsHostname: string;
  extraConfig: string | null;
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
}

// Gateway endpoint from signal server aggregation
export interface GatewayEndpoint {
  id: string;
  displayName: string;
  description: string;
  backends: { name: string; protocol?: string; auth?: string; rdpUsernames?: string[]; sshUsernames?: string[]; accessible: boolean }[];
  online: boolean;
  clientCount: number;
  signalServerId: string;
  signalServerName: string;
  signalServerUrl: string;
  directUrl?: string;
}

// Re-export types for convenience
export type { PolicyTemplate, InsertPolicyTemplate, TemplateParameter, Bridge, InsertBridge, SignalServer, InsertSignalServer };

// SSH Policy Configuration for role creation
export interface SshPolicyConfig {
  enabled: boolean;
  contractType: string;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  threshold: number;
}

// SSH Policy response from server
export interface SshPolicyResponse {
  roleId: string;
  contractType: string;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  threshold: number;
  createdAt: number;
  updatedAt?: number;
}

// Pending SSH Policy types
export type SshPolicyStatus = "pending" | "approved" | "committed" | "cancelled";

export interface PendingSshPolicy {
  id: string;
  roleId: string;
  requestedBy: string;
  requestedByEmail?: string;
  policyRequestData: string;
  contractCode?: string;
  status: SshPolicyStatus;
  threshold: number;
  createdAt: number;
  approvalCount?: number;
  rejectionCount?: number;
  approvedBy?: string[];
  deniedBy?: string[];
  commitReady?: boolean;
}

export interface SshPolicyDecision {
  id: string;
  policyId: string;
  decidedBy: string;
  decidedByEmail?: string;
  decision: "approved" | "rejected";
  createdAt: number;
}

export interface SshPolicyLog {
  id: string;
  policyId: string;
  roleId: string;
  action: string;
  performedBy: string;
  performedByEmail?: string;
  details?: string;
  createdAt: number;
  policyStatus?: string;
  policyThreshold?: number;
  policyCreatedAt?: number;
  policyRequestedBy?: string;
  approvalCount?: number;
  rejectionCount?: number;
}

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

export interface TidecloakEvent {
  id: string;
  time: number;
  type: string;
  clientId?: string;
  userId?: string;
  ipAddress?: string;
  details?: Record<string, any>;
}

export interface FileOperationLog {
  id: string;
  sessionId: string;
  serverId: string;
  serverName: string;
  serverHost: string;
  userId: string;
  userEmail: string | null;
  sshUser: string;
  operation: "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod";
  path: string;
  targetPath: string | null;
  fileSize: number | null;
  mode: "sftp" | "scp";
  status: "success" | "error";
  errorMessage: string | null;
  timestamp: string; // ISO date string
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

export interface RoleApproval {
  id: string;
  requestType: string;
  status: string;
  requestedBy: string;
  requestedAt: string;
  role: string;
  compositeRole?: string;
  clientId: string;
  changeSetType: string;
  userRecords: Array<{
    username: string;
    proofDetailId?: string;
    clientId?: string;
    accessDraft?: string;
  }>;
  retrievalInfo: ChangeSetRequest;
}

// SSH connections are now handled via Socket.IO to KeyleSSH
// See Console.tsx for the Socket.IO implementation

// License/Subscription types
export type SubscriptionTier = "free" | "pro" | "enterprise";
export type SubscriptionStatus = "active" | "canceled" | "past_due" | "trialing";

export interface Subscription {
  id: string;
  tier: SubscriptionTier;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  stripePriceId?: string;
  status: string;
  currentPeriodEnd?: number;
  cancelAtPeriodEnd?: boolean;
  createdAt: number;
  updatedAt?: number;
}

export interface OverLimitStatus {
  users: {
    isOverLimit: boolean;
    enabled: number;
    total: number;
    limit: number;
    overBy: number;
  };
  servers: {
    isOverLimit: boolean;
    enabled: number;
    total: number;
    limit: number;
    overBy: number;
  };
}

export interface LicenseInfo {
  subscription: Subscription | null;
  usage: { users: number; servers: number };
  limits: { maxUsers: number; maxServers: number };
  tier: SubscriptionTier;
  tierName: string;
  overLimit?: OverLimitStatus;
  stripeConfigured?: boolean;
}

export interface LimitCheck {
  allowed: boolean;
  current: number;
  limit: number;
  tier: SubscriptionTier;
  tierName: string;
}

export interface BillingHistoryItem {
  id: string;
  subscriptionId: string;
  stripeInvoiceId?: string;
  amount: number;
  currency: string;
  status: string;
  invoicePdf?: string;
  description?: string;
  createdAt: number;
}

export interface TierInfo {
  name: string;
  maxUsers: number;
  maxServers: number;
  priceId: string | null;
}

export interface PricingInfo {
  tiers: {
    free: TierInfo;
    pro: TierInfo;
    enterprise: TierInfo;
  };
  stripeConfigured: boolean;
}

// Recording types
export interface RecordingSummary {
  id: string;
  sessionId: string;
  serverId: string;
  serverName: string;
  userId: string;
  userEmail: string;
  sshUser: string;
  startedAt: string;
  endedAt: string | null;
  duration: number | null;
  terminalWidth: number;
  terminalHeight: number;
  fileSize: number;
  recordingType?: "ssh" | "rdp";
  backendName?: string | null;
  gatewayId?: string | null;
}

export interface RecordingDetails extends RecordingSummary {
  data: string; // Full recording data (asciicast for SSH, PDU JSON lines for RDP)
}

export interface RecordingsListResponse {
  recordings: RecordingSummary[];
  totalCount: number;
  totalStorage: number;
}

export interface RecordingStats {
  totalCount: number;
  totalStorage: number;
  totalStorageFormatted: string;
}

/**
 * Test SSH server connectivity through a bridge.
 * This is a client-side test that connects via WebSocket to verify reachability.
 */
export async function testBridgeConnection(
  bridgeUrl: string,
  host: string,
  port: number,
  timeoutMs = 5000
): Promise<{ success: boolean; message: string }> {
  return new Promise((resolve) => {
    const token = localStorage.getItem("access_token") || "";

    const params = new URLSearchParams({
      host,
      port: port.toString(),
      serverId: "test",
      token,
      sessionId: "test-connection",
    });

    const wsUrl = `${bridgeUrl}?${params.toString()}`;
    let ws: WebSocket | null = null;
    let settled = false;

    const finish = (success: boolean, message: string) => {
      if (settled) return;
      settled = true;
      if (ws) {
        try {
          ws.close();
        } catch {
          // ignore
        }
      }
      resolve({ success, message });
    };

    const timeout = setTimeout(() => {
      finish(false, "Connection timeout");
    }, timeoutMs);

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        // WebSocket connected to bridge, now waiting for TCP connection
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "connected") {
            clearTimeout(timeout);
            finish(true, "Connection successful");
          } else if (data.type === "error") {
            clearTimeout(timeout);
            finish(false, data.message || "Connection failed");
          }
        } catch {
          // Binary data or non-JSON - ignore for test
        }
      };

      ws.onerror = () => {
        clearTimeout(timeout);
        finish(false, "Bridge connection failed");
      };

      ws.onclose = (event) => {
        clearTimeout(timeout);
        if (!settled) {
          finish(false, event.reason || "Connection closed");
        }
      };
    } catch (err) {
      clearTimeout(timeout);
      finish(false, err instanceof Error ? err.message : "Connection failed");
    }
  });
}

/**
 * Build the WebSocket URL for a bridge (or embedded bridge).
 */
export function getBridgeWebSocketUrl(bridgeUrl?: string | null): string {
  if (bridgeUrl) {
    // Convert HTTP URL to WebSocket URL and add SSH path if missing
    let url = bridgeUrl;
    if (url.startsWith("https://")) {
      url = "wss://" + url.slice(8);
    } else if (url.startsWith("http://")) {
      url = "ws://" + url.slice(7);
    }
    // Add /ws/ssh path for gateway bridges (if URL doesn't already have a path)
    if (!url.includes("/ws/")) {
      url = url.replace(/\/?$/, "/ws/ssh");
    }
    return url;
  }
  // Local development: use embedded /ws/tcp endpoint
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  return `${protocol}//${host}/ws/tcp`;
}
