import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
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
  getToken: () => string | null;
  hasRole: (role: UserRole) => boolean;
  vuid: string;
  approveTideRequests: (requests: TideApprovalRequest[]) => Promise<TideApprovalResponse[]>;
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

  useEffect(() => {
    if (!tidecloak.isInitializing) {
      if (tidecloak.authenticated) {
        const user: OIDCUser = {
          id: tidecloak.getValueFromIdToken("sub") || "",
          username: tidecloak.getValueFromIdToken("preferred_username") ||
                    tidecloak.getValueFromIdToken("name") || "",
          email: tidecloak.getValueFromIdToken("email") || "",
          role: tidecloak.hasClientRole("tide-realm-admin", "realm-management") ? "admin" : "user",
          allowedServers: (tidecloak.getValueFromIdToken("allowed_servers") as string[]) || [],
        };

        // Store token in localStorage for API calls
        if (tidecloak.token) {
          localStorage.setItem("access_token", tidecloak.token);
        }

        // Get vuid from token
        const tokenVuid = tidecloak.getValueFromIdToken("vuid");
        setVuid(tokenVuid || "");

        setState({
          user,
          accessToken: tidecloak.token || null,
          isAuthenticated: true,
          isLoading: false,
        });
      } else {
        // Clear token from localStorage
        localStorage.removeItem("access_token");
        setVuid("");

        setState({
          user: null,
          accessToken: null,
          isAuthenticated: false,
          isLoading: false,
        });
      }
    }
  }, [tidecloak.isInitializing, tidecloak.authenticated, tidecloak]);

  const login = useCallback(() => {
    tidecloak.login();
  }, [tidecloak]);

  const logout = useCallback(() => {
    localStorage.removeItem("access_token");
    tidecloak.logout();
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

  // Tide enclave approval function - opens popup for cryptographic signing
  // Uses IAMService._tc from @tidecloak/js like ideed-swarm does
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

  return (
    <AuthContext.Provider value={{ ...state, login, logout, getToken, hasRole, vuid, approveTideRequests }}>
      {children}
    </AuthContext.Provider>
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  return (
    <TideCloakContextProvider config={tidecloakConfig}>
      <TideCloakAuthBridge>{children}</TideCloakAuthBridge>
    </TideCloakContextProvider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

export { useTideCloak };
