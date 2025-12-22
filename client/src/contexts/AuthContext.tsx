import { createContext, useContext, useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import { TideCloakContextProvider, useTideCloak } from "@tidecloak/react";
import { IAMService } from "@tidecloak/js";
import type { OIDCUser, UserRole, AuthState } from "@shared/schema";
import adapter from "../tidecloakAdapter.json";

export enum ApprovalStatus {
  approved = "approved",
  denied = "denied",
  pending = "pending",
}

interface TideApprovalRequest {
  id: string;
  request: Uint8Array;
}

interface TideApprovalResponse {
  id: string;
  approved?: {
    request: Uint8Array;
  };
  denied?: boolean;
  pending?: boolean;
}

interface AuthContextValue extends AuthState {
  login: () => void;
  logout: () => void;
  refreshToken: () => Promise<boolean>;
  getToken: () => string | null;
  hasRole: (role: UserRole) => boolean;
  canManageTemplates: () => boolean;
  vuid: string;
  approveTideRequests: (requests: TideApprovalRequest[]) => Promise<TideApprovalResponse[]>;
  initializeTideRequest: <T extends { encode: () => Uint8Array }>(request: T) => Promise<T>;
  executeTideRequest: (request: Uint8Array) => Promise<Uint8Array[]>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const tidecloakConfig = {
  ...adapter,
  redirectUri: `${window.location.origin}/auth/redirect`,
};

function TideCloakAuthBridge({ children }: { children: ReactNode }) {
  const tidecloak = useTideCloak();
  const [state, setState] = useState<AuthState>({
    user: null,
    accessToken: null,
    isAuthenticated: false,
    isLoading: true,
  });
  const [vuid, setVuid] = useState<string>("");
  const [initError, setInitError] = useState<Error | null>(null);
  const hasSynced = useRef(false);

  // Sync auth state from TideCloak - only runs once after initialization
  useEffect(() => {
    if (tidecloak.isInitializing) {
      return;
    }

    // Only sync once after initialization
    if (hasSynced.current) {
      return;
    }
    hasSynced.current = true;

    // Signal that we've completed initialization (for global timeout)
    window.__KEYLESSH_READY__ = true;

    try {
      if (tidecloak.authenticated) {
        const user: OIDCUser = {
          id: tidecloak.getValueFromIdToken("sub") || "",
          username:
            tidecloak.getValueFromIdToken("preferred_username") ||
            tidecloak.getValueFromIdToken("name") ||
            "",
          email: tidecloak.getValueFromIdToken("email") || "",
          role: tidecloak.hasClientRole("tide-realm-admin", "realm-management") ? "admin" : "user",
          allowedServers: (tidecloak.getValueFromIdToken("allowed_servers") as string[]) || [],
        };

        if (tidecloak.token) {
          localStorage.setItem("access_token", tidecloak.token);
        }

        const tokenVuid = tidecloak.getValueFromIdToken("vuid") || "";
        setVuid(tokenVuid);

        setState({
          user,
          accessToken: tidecloak.token || null,
          isAuthenticated: true,
          isLoading: false,
        });
        return;
      }

      localStorage.removeItem("access_token");
      setVuid("");
      setState({
        user: null,
        accessToken: null,
        isAuthenticated: false,
        isLoading: false,
      });
    } catch (err) {
      console.error("Auth sync error:", err);
      setInitError(err instanceof Error ? err : new Error(String(err)));
      localStorage.removeItem("access_token");
      setState({
        user: null,
        accessToken: null,
        isAuthenticated: false,
        isLoading: false,
      });
    }
  }, [tidecloak.isInitializing, tidecloak.authenticated, tidecloak.token, tidecloak]);

  // Set up IAMService event listeners for automatic token refresh
  useEffect(() => {
    // Set up event handlers for token management (chain like ideed-swarm)
    IAMService
      .on("tokenExpired", async () => {
        console.log("[AuthContext] Token expired, refreshing...");
        try {
          await IAMService.updateIAMToken();
        } catch (error) {
          console.error("[AuthContext] Failed to refresh expired token:", error);
          setState(prev => ({ ...prev, isAuthenticated: false }));
        }
      })
      .on("authRefreshError", (_event: string, error: unknown) => {
        console.error("[AuthContext] Token refresh failed:", error);
        setState(prev => ({ ...prev, isAuthenticated: false }));
      })
      .on("authRefreshSuccess", () => {
        console.log("[AuthContext] Token refreshed successfully");
        // Update token in localStorage from tidecloak
        if (tidecloak.token) {
          localStorage.setItem("access_token", tidecloak.token);
          setState(prev => ({ ...prev, accessToken: tidecloak.token }));
        }
      });

    // Proactive refresh: check every 60 seconds and refresh if token expires within 5 minutes
    const refreshInterval = setInterval(async () => {
      if (IAMService.isLoggedIn()) {
        try {
          const expiresIn = IAMService.getTokenExp();
          if (expiresIn < 300) {
            console.log("[AuthContext] Token expiring soon, refreshing...");
            await IAMService.updateIAMToken();
          }
        } catch (error) {
          console.error("[AuthContext] Error checking/refreshing token:", error);
        }
      }
    }, 60000);

    return () => {
      clearInterval(refreshInterval);
    };
  }, [tidecloak.token]);

  // If there was an init error, throw it to be caught by ErrorBoundary
  if (initError) {
    throw initError;
  }

  const login = useCallback(() => {
    tidecloak.login();
  }, [tidecloak]);

  const logout = useCallback(() => {
    localStorage.removeItem("access_token");
    tidecloak.logout();
  }, [tidecloak]);

  const refreshToken = useCallback(async (): Promise<boolean> => {
    if (!tidecloak.authenticated) return false;

    try {
      const updater = (tidecloak as any).updateToken as undefined | ((minValidity: number) => Promise<boolean>);
      if (typeof updater !== "function") {
        // Fallback: force a reload so the user can get an updated token from the IdP.
        window.location.reload();
        return false;
      }

      await updater(0);
      // Reload to pick up new token
      window.location.reload();
      return true;
    } catch (err) {
      console.error("Failed to refresh token:", err);
      return false;
    }
  }, [tidecloak]);

  const getToken = useCallback(() => {
    return tidecloak.token || null;
  }, [tidecloak]);

  const hasRole = useCallback(
    (role: UserRole) => {
      if (role === "admin") {
        return tidecloak.hasClientRole("tide-realm-admin", "realm-management");
      }
      return state.isAuthenticated;
    },
    [tidecloak, state.isAuthenticated]
  );

  // Check if user can manage policy templates
  // Requires: tide-realm-admin, realm-admin, or policy-creator role
  const canManageTemplates = useCallback(() => {
    // Check realm-management client roles
    if (tidecloak.hasClientRole("tide-realm-admin", "realm-management")) {
      return true;
    }
    if (tidecloak.hasClientRole("realm-admin", "realm-management")) {
      return true;
    }
    // Check realm roles
    if (tidecloak.hasRealmRole("tide-realm-admin")) {
      return true;
    }
    if (tidecloak.hasRealmRole("realm-admin")) {
      return true;
    }
    // Check for policy-creator role on the current client
    if (tidecloak.hasRealmRole("policy-creator")) {
      return true;
    }
    return false;
  }, [tidecloak]);

  // Initialize a Tide request with the user's credentials
  // This signs the request so it can be submitted for processing
  const initializeTideRequest = useCallback(
    async <T extends { encode: () => Uint8Array }>(request: T): Promise<T> => {
      const tc = (IAMService as any)._tc;

      if (!tc?.createTideRequest) {
        throw new Error("TideCloak createTideRequest not available");
      }

      const encodedRequest = request.encode();
      const initializedBytes = await tc.createTideRequest(encodedRequest);

      // The request type should have a static decode method
      const RequestClass = (request as any).constructor;
      if (typeof RequestClass.decode === "function") {
        return RequestClass.decode(initializedBytes) as T;
      }

      // If no decode method, return original with initialized bytes attached
      return request;
    },
    []
  );

  // Tide enclave approval function - opens popup for cryptographic signing
  // Uses IAMService._tc from @tidecloak/js
  const approveTideRequests = useCallback(
    async (requests: TideApprovalRequest[]): Promise<TideApprovalResponse[]> => {
      // Access the underlying TideCloak instance via IAMService._tc
      const tc = (IAMService as any)._tc;

      if (!tc?.requestTideOperatorApproval) {
        console.error("TideCloak requestTideOperatorApproval not available on IAMService._tc");
        // Return pending status for all requests if method not available
        return requests.map((req) => ({
          id: req.id,
          pending: true,
        }));
      }

      try {
        const response = await tc.requestTideOperatorApproval(requests);
        return response.map((res: any) => {
          if (res.status === ApprovalStatus.approved) {
            return {
              id: res.id,
              approved: {
                request: res.request,
              },
            };
          } else if (res.status === ApprovalStatus.denied) {
            return {
              id: res.id,
              denied: true,
            };
          } else {
            return {
              id: res.id,
              pending: true,
            };
          }
        });
      } catch (error) {
        console.error("Error in approveTideRequests:", error);
        return requests.map((req) => ({
          id: req.id,
          pending: true,
        }));
      }
    },
    []
  );

  // Execute a Tide request to get the final signature
  // This is called after the request has been approved
  const executeTideRequest = useCallback(
    async (request: Uint8Array): Promise<Uint8Array[]> => {
      const tc = (IAMService as any)._tc;

      if (!tc?.executeSignRequest) {
        throw new Error("TideCloak executeSignRequest not available");
      }

      return await tc.executeSignRequest(request);
    },
    []
  );

  return (
    <AuthContext.Provider value={{ ...state, login, logout, refreshToken, getToken, hasRole, canManageTemplates, vuid, approveTideRequests, initializeTideRequest, executeTideRequest }}>
      {children}
    </AuthContext.Provider>
  );
}

function AuthProviderWithTimeout({ children }: { children: ReactNode }) {
  return (
    <TideCloakContextProvider config={tidecloakConfig}>
      <TideCloakAuthBridge>{children}</TideCloakAuthBridge>
    </TideCloakContextProvider>
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  // Clear any corrupted localStorage on mount if it looks invalid
  useEffect(() => {
    try {
      const token = localStorage.getItem("access_token");
      if (token) {
        // Basic JWT format check
        const parts = token.split(".");
        if (parts.length !== 3) {
          console.warn("Invalid token format in localStorage, clearing");
          localStorage.removeItem("access_token");
        }
      }
    } catch (e) {
      console.error("Error checking localStorage:", e);
      localStorage.removeItem("access_token");
    }
  }, []);

  return <AuthProviderWithTimeout>{children}</AuthProviderWithTimeout>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

export { useTideCloak };
