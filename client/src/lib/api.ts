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

// Forseti contract compilation result
export interface ForsetiCompileResult {
  success: boolean;
  contractId?: string;
  sdkVersion?: string;
  error?: string;
  validated?: boolean;
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
     * Compiles a Forseti contract and returns its hash (contractId).
     * The contractId is the SHA512 hash of the compiled DLL.
     */
    compile: (source: string, options?: { validate?: boolean; entryType?: string }) =>
      apiRequest<ForsetiCompileResult>("/api/forseti/compile", {
        method: "POST",
        body: JSON.stringify({ source, ...options }),
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
    /**
     * Check if SSH access is blocked due to over-limit
     */
    getAccessStatus: () =>
      apiRequest<{ blocked: boolean; reason?: string }>("/api/ssh/access-status"),
  },
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
      setEnabled: (userId: string, enabled: boolean) =>
        apiRequest<{ success: boolean; enabled: boolean }>(`/api/admin/users/${userId}/enabled`, {
          method: "PUT",
          body: JSON.stringify({ enabled }),
        }),
    },
    roles: {
      list: () => apiRequest<{ roles: AdminRole[] }>("/api/admin/roles"),
      listAll: () => apiRequest<{ roles: AdminRole[] }>("/api/admin/roles/all"),
      create: (data: { name: string; description?: string; policy?: SshPolicyConfig }) =>
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
      access: (limit?: number, offset?: number) =>
        apiRequest<TidecloakEvent[]>(
          `/api/admin/logs/access?limit=${limit || 100}&offset=${offset || 0}`
        ),
      fileOperations: (limit?: number, offset?: number) =>
        apiRequest<{ operations: FileOperationLog[]; total: number }>(
          `/api/admin/logs/file-operations?limit=${limit || 100}&offset=${offset || 0}`
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
      commit: (id: string, signature?: string) =>
        apiRequest<{ message: string }>(`/api/admin/ssh-policies/pending/${id}/commit`, {
          method: "POST",
          body: JSON.stringify({ signature }),
        }),
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
      get: () => apiRequest<LicenseInfo>("/api/admin/license"),
      checkLimit: (resource: "user" | "server") =>
        apiRequest<LimitCheck>(`/api/admin/license/check/${resource}`),
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
  },
};

// Re-export template types for convenience
export type { PolicyTemplate, InsertPolicyTemplate, TemplateParameter };

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
}

export interface RecordingDetails extends RecordingSummary {
  data: string; // Full asciicast data for playback
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
