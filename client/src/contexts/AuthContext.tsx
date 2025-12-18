import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import type { OIDCUser, UserRole, AuthState } from "@shared/schema";

interface AuthContextValue extends AuthState {
  login: () => void;
  logout: () => void;
  getToken: () => string | null;
  hasRole: (role: UserRole) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const OIDC_ISSUER = import.meta.env.VITE_OIDC_ISSUER || "";
const OIDC_CLIENT_ID = import.meta.env.VITE_OIDC_CLIENT_ID || "";
const OIDC_REDIRECT_URI = import.meta.env.VITE_OIDC_REDIRECT_URI || `${window.location.origin}/callback`;
const OIDC_LOGOUT_REDIRECT_URI = import.meta.env.VITE_OIDC_LOGOUT_REDIRECT_URI || window.location.origin;
const OIDC_SCOPE = import.meta.env.VITE_OIDC_SCOPE || "openid profile email";
const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true" || !OIDC_ISSUER;

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function parseJwt(token: string): Record<string, unknown> {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch {
    return {};
  }
}

const mockUser: OIDCUser = {
  id: "mock-user-1",
  username: "demo.user",
  email: "demo@keylessh.dev",
  role: "admin",
  allowedServers: ["server-1", "server-2", "server-3"],
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    accessToken: null,
    isAuthenticated: false,
    isLoading: true,
  });

  const processTokens = useCallback((accessToken: string, idToken?: string) => {
    const claims = parseJwt(idToken || accessToken);
    
    const user: OIDCUser = {
      id: (claims.sub as string) || "",
      username: (claims.preferred_username as string) || (claims.name as string) || "",
      email: (claims.email as string) || "",
      role: ((claims.realm_access as { roles?: string[] })?.roles?.includes("admin") ||
        (claims.role as string) === "admin" ||
        (claims.roles as string[])?.includes("admin"))
        ? "admin"
        : "user",
      allowedServers: (claims.allowed_servers as string[]) || [],
    };

    localStorage.setItem("access_token", accessToken);
    if (idToken) localStorage.setItem("id_token", idToken);

    setState({
      user,
      accessToken,
      isAuthenticated: true,
      isLoading: false,
    });
  }, []);

  useEffect(() => {
    const initAuth = async () => {
      if (USE_MOCK) {
        const storedToken = localStorage.getItem("access_token");
        if (storedToken === "mock-token") {
          setState({
            user: mockUser,
            accessToken: "mock-token",
            isAuthenticated: true,
            isLoading: false,
          });
          return;
        }
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get("code");
      const storedVerifier = sessionStorage.getItem("pkce_verifier");

      if (code && storedVerifier) {
        try {
          const tokenResponse = await fetch(`${OIDC_ISSUER}/protocol/openid-connect/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "authorization_code",
              client_id: OIDC_CLIENT_ID,
              code,
              redirect_uri: OIDC_REDIRECT_URI,
              code_verifier: storedVerifier,
            }),
          });

          if (tokenResponse.ok) {
            const tokens = await tokenResponse.json();
            sessionStorage.removeItem("pkce_verifier");
            window.history.replaceState({}, document.title, window.location.pathname);
            processTokens(tokens.access_token, tokens.id_token);
            return;
          }
        } catch (error) {
          console.error("Token exchange failed:", error);
        }
        sessionStorage.removeItem("pkce_verifier");
      }

      const storedToken = localStorage.getItem("access_token");
      if (storedToken) {
        const claims = parseJwt(storedToken);
        const exp = claims.exp as number;
        if (exp && exp * 1000 > Date.now()) {
          processTokens(storedToken, localStorage.getItem("id_token") || undefined);
          return;
        }
        localStorage.removeItem("access_token");
        localStorage.removeItem("id_token");
      }

      setState((prev) => ({ ...prev, isLoading: false }));
    };

    initAuth();
  }, [processTokens]);

  const login = useCallback(async () => {
    if (USE_MOCK) {
      localStorage.setItem("access_token", "mock-token");
      setState({
        user: mockUser,
        accessToken: "mock-token",
        isAuthenticated: true,
        isLoading: false,
      });
      return;
    }

    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    sessionStorage.setItem("pkce_verifier", verifier);

    const authUrl = new URL(`${OIDC_ISSUER}/protocol/openid-connect/auth`);
    authUrl.searchParams.set("client_id", OIDC_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", OIDC_REDIRECT_URI);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", OIDC_SCOPE);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    window.location.href = authUrl.toString();
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("id_token");
    
    setState({
      user: null,
      accessToken: null,
      isAuthenticated: false,
      isLoading: false,
    });

    if (!USE_MOCK && OIDC_ISSUER) {
      const logoutUrl = new URL(`${OIDC_ISSUER}/protocol/openid-connect/logout`);
      logoutUrl.searchParams.set("post_logout_redirect_uri", OIDC_LOGOUT_REDIRECT_URI);
      window.location.href = logoutUrl.toString();
    }
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

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
