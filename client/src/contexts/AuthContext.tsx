import { createContext, useContext, useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import { TideCloakContextProvider, useTideCloak } from "@tidecloak/react";
import { IAMService } from "@tidecloak/js";
import type { OIDCUser, UserRole, AuthState } from "@shared/schema";

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

interface TidecloakConfig {
  realm: string;
  "auth-server-url": string;
  "ssl-required": string;
  resource: string;
  "public-client": boolean;
  "confidential-port": number;
  jwk: {
    keys: Array<{
      kid: string;
      kty: string;
      alg: string;
      use: string;
      crv: string;
      x: string;
    }>;
  };
  vendorId: string;
  homeOrkUrl: string;
  [key: string]: any;
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
  authConfig: TidecloakConfig | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function TideCloakAuthBridge({ children, authConfig }: { children: ReactNode; authConfig: TidecloakConfig }) {
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

  // Initialize the request enclave on every user click after login.
  // initRequestEnclave opens an iframe/popup that browsers block unless
  // triggered by a user gesture, so we capture clicks to provide that gesture.
  useEffect(() => {
    if (!state.isAuthenticated) return;

    const handler = () => {
      try {
        (IAMService as any)._tc?.initRequestEnclave();
      } catch (e) {
        console.error("[AuthProvider] Failed to init request enclave:", e);
      }
    };

    document.addEventListener("click", handler);
    return () => document.removeEventListener("click", handler);
  }, [state.isAuthenticated]);

  // Set up IAMService event listeners for automatic token refresh
  useEffect(() => {
    // Helper to update token in localStorage and state from IAMService
    const updateTokenFromIAM = async () => {
      try {
        const newToken = await IAMService.getToken();
        if (newToken) {
          console.log("[AuthContext] Updating localStorage with new token");
          localStorage.setItem("access_token", newToken);
          setState(prev => ({ ...prev, accessToken: newToken }));
        }
      } catch (err) {
        console.error("[AuthContext] Failed to get token from IAMService:", err);
      }
    };

    // Set up event handlers for token management (chain like ideed-swarm)
    IAMService
      .on("tokenExpired", async () => {
        console.log("[AuthContext] Token expired, refreshing...");
        try {
          await IAMService.updateIAMToken();
          await updateTokenFromIAM();
        } catch (error) {
          console.error("[AuthContext] Failed to refresh expired token:", error);
          setState(prev => ({ ...prev, isAuthenticated: false }));
        }
      })
      .on("authRefreshError", (_event: string, error: unknown) => {
        console.error("[AuthContext] Token refresh failed:", error);
        setState(prev => ({ ...prev, isAuthenticated: false }));
      })
      .on("authRefreshSuccess", async () => {
        console.log("[AuthContext] Token refreshed successfully");
        await updateTokenFromIAM();
      });

    // Proactive refresh: check every 60 seconds and refresh if token expires within 5 minutes
    const refreshInterval = setInterval(async () => {
      if (IAMService.isLoggedIn()) {
        try {
          const expiresIn = IAMService.getTokenExp();
          if (expiresIn < 300) {
            console.log("[AuthContext] Token expiring soon, refreshing...");
            await IAMService.updateIAMToken();
            await updateTokenFromIAM();
          }
        } catch (error) {
          console.error("[AuthContext] Error checking/refreshing token:", error);
        }
      }
    }, 60000);

    return () => {
      clearInterval(refreshInterval);
    };
  }, []);

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

      let intervalId: number | undefined;

      try {
        // If the user closes the popup enclave, the underlying promise can hang indefinitely.
        // Race with a popup-closed poll + timeout so the UI can recover.
        const pendingFallback = requests.map((req) => ({ id: req.id, pending: true as const }));

        let cancelledResolved = false;

        const cancelled = new Promise<null>((resolve) => {
          const finish = () => {
            if (cancelledResolved) return;
            cancelledResolved = true;
            resolve(null);
          };

          intervalId = window.setInterval(() => {
            try {
              const enclave = (tc as any).approvalEnclave;
              if (enclave && typeof enclave.enclaveClosed === "function" && enclave.enclaveClosed()) {
                finish();
              }
            } catch {
              // ignore
            }
          }, 250);
        });

        const raw = await Promise.race([tc.requestTideOperatorApproval(requests), cancelled]);

        if (!raw) {
          try {
            (tc as any).approvalEnclave?.close?.();
          } catch {
            // ignore
          }
          return pendingFallback;
        }

        const response = raw;

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
      } finally {
        // Always clear timers so the page doesn't stay "stuck" if the popup is closed.
        if (typeof intervalId === "number") window.clearInterval(intervalId);
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

      return await tc.executeSignRequest(request, true);
    },
    []
  );

  return (
    <AuthContext.Provider value={{ ...state, login, logout, refreshToken, getToken, hasRole, canManageTemplates, vuid, approveTideRequests, initializeTideRequest, executeTideRequest, authConfig }}>
      {children}
    </AuthContext.Provider>
  );
}

function AuthProviderWithTimeout({ children, authConfig }: { children: ReactNode; authConfig: TidecloakConfig }) {
  const tidecloakConfig = {
    ...authConfig,
    redirectUri: `${window.location.origin}/auth/redirect`,
  };

  return (
    <TideCloakContextProvider config={tidecloakConfig}>
      <TideCloakAuthBridge authConfig={authConfig}>{children}</TideCloakAuthBridge>
    </TideCloakContextProvider>
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authConfig, setAuthConfig] = useState<TidecloakConfig | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);

  // Fetch auth config from server
  useEffect(() => {
    async function loadConfig() {
      try {
        const response = await fetch("/api/auth/config");
        if (!response.ok) {
          throw new Error(`Failed to load auth config: ${response.status}`);
        }
        const config = await response.json();
        setAuthConfig(config);
      } catch (err) {
        console.error("Failed to load auth config:", err);
        setConfigError(err instanceof Error ? err.message : "Failed to load configuration");
      }
    }
    loadConfig();
  }, []);

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

  // Show loading state while config loads
  if (!authConfig && !configError) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center animate-pulse">
            <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="4" y="4" width="16" height="16" rx="2" />
              <line x1="8" y1="12" x2="16" y2="12" />
            </svg>
          </div>
          <p className="text-sm text-muted-foreground">Loading configuration...</p>
        </div>
      </div>
    );
  }

  // Show error state if config failed to load
  if (configError) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 text-center px-4">
          <div className="h-12 w-12 rounded-lg bg-destructive/10 flex items-center justify-center">
            <svg className="h-6 w-6 text-destructive" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="15" y1="9" x2="9" y2="15" />
              <line x1="9" y1="9" x2="15" y2="15" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-medium text-destructive">Configuration Error</p>
            <p className="text-xs text-muted-foreground mt-1">{configError}</p>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="text-xs text-primary hover:underline"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return <AuthProviderWithTimeout authConfig={authConfig!}>{children}</AuthProviderWithTimeout>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

export function useAuthConfig() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuthConfig must be used within AuthProvider");
  }
  if (!context.authConfig) {
    throw new Error("Auth config not loaded");
  }
  return context.authConfig;
}

export { useTideCloak };
