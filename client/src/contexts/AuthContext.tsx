import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import { TideCloakContextProvider, useTideCloak } from "@tidecloak/react";
import type { OIDCUser, UserRole, AuthState } from "@shared/schema";

interface AuthContextValue extends AuthState {
  login: () => void;
  logout: () => void;
  getToken: () => string | null;
  hasRole: (role: UserRole) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const TIDECLOAK_URL = import.meta.env.VITE_TIDECLOAK_URL || "";
const TIDECLOAK_REALM = import.meta.env.VITE_TIDECLOAK_REALM || "";
const TIDECLOAK_CLIENT_ID = import.meta.env.VITE_TIDECLOAK_CLIENT_ID || "";
const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true" || !TIDECLOAK_URL;

const tidecloakConfig = {
  realm: TIDECLOAK_REALM,
  "auth-server-url": TIDECLOAK_URL,
  "ssl-required": "external",
  resource: TIDECLOAK_CLIENT_ID,
  "public-client": true,
  "confidential-port": 0,
};

const mockUser: OIDCUser = {
  id: "mock-user-1",
  username: "demo.user",
  email: "demo@keylessh.dev",
  role: "admin",
  allowedServers: ["server-1", "server-2", "server-3"],
};

function MockAuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    accessToken: null,
    isAuthenticated: false,
    isLoading: true,
  });

  useEffect(() => {
    const storedToken = localStorage.getItem("access_token");
    if (storedToken === "mock-token") {
      setState({
        user: mockUser,
        accessToken: "mock-token",
        isAuthenticated: true,
        isLoading: false,
      });
    } else {
      setState((prev) => ({ ...prev, isLoading: false }));
    }
  }, []);

  const login = useCallback(() => {
    localStorage.setItem("access_token", "mock-token");
    setState({
      user: mockUser,
      accessToken: "mock-token",
      isAuthenticated: true,
      isLoading: false,
    });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("access_token");
    setState({
      user: null,
      accessToken: null,
      isAuthenticated: false,
      isLoading: false,
    });
  }, []);

  const getToken = useCallback(() => state.accessToken, [state.accessToken]);

  const hasRole = useCallback(
    (role: UserRole) => state.user?.role === role || state.user?.role === "admin",
    [state.user]
  );

  return (
    <AuthContext.Provider value={{ ...state, login, logout, getToken, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

function TideCloakAuthBridge({ children }: { children: ReactNode }) {
  const tidecloak = useTideCloak();
  const [state, setState] = useState<AuthState>({
    user: null,
    accessToken: null,
    isAuthenticated: false,
    isLoading: true,
  });

  useEffect(() => {
    const checkAuth = () => {
      if (tidecloak.initialized) {
        if (tidecloak.authenticated) {
          const user: OIDCUser = {
            id: tidecloak.getValueFromIdToken("sub") || "",
            username: tidecloak.getValueFromIdToken("preferred_username") || 
                      tidecloak.getValueFromIdToken("name") || "",
            email: tidecloak.getValueFromIdToken("email") || "",
            role: tidecloak.hasRealmRole("admin") ? "admin" : "user",
            allowedServers: (tidecloak.getValueFromIdToken("allowed_servers") as string[]) || [],
          };

          setState({
            user,
            accessToken: tidecloak.token || null,
            isAuthenticated: true,
            isLoading: false,
          });
        } else {
          setState({
            user: null,
            accessToken: null,
            isAuthenticated: false,
            isLoading: false,
          });
        }
      }
    };

    checkAuth();
  }, [tidecloak.initialized, tidecloak.authenticated, tidecloak]);

  const login = useCallback(() => {
    tidecloak.login();
  }, [tidecloak]);

  const logout = useCallback(() => {
    tidecloak.logout();
  }, [tidecloak]);

  const getToken = useCallback(() => {
    return tidecloak.token || null;
  }, [tidecloak]);

  const hasRole = useCallback(
    (role: UserRole) => {
      if (role === "admin") {
        return tidecloak.hasRealmRole("admin");
      }
      return state.isAuthenticated;
    },
    [tidecloak, state.isAuthenticated]
  );

  return (
    <AuthContext.Provider value={{ ...state, login, logout, getToken, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  if (USE_MOCK) {
    return <MockAuthProvider>{children}</MockAuthProvider>;
  }

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
