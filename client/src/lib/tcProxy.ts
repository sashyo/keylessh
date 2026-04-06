/**
 * TideCloak proxy — routes admin API calls through our server.
 *
 * Double DPoP:
 *   1. Browser signs DPoP proof for our server (/api/tc-proxy) — via appFetch/secureFetch
 *   2. Browser signs DPoP proof for TideCloak URL — via IAMService._dpopProvider
 *   Server validates proof #1, forwards proof #2 to TideCloak.
 *
 * This avoids CORS issues and lets the server filter/audit responses.
 */

import { IAMService } from "@tidecloak/js";
import { appFetch, isDpopEnabled } from "./appFetch";

/**
 * Make a TideCloak admin API call through our server proxy.
 *
 * @param tcUrl - The full TideCloak URL (e.g., https://login.dauth.me/admin/realms/.../roles)
 * @param method - HTTP method (GET, POST, PUT, DELETE)
 * @param body - Request body (for POST/PUT)
 * @returns The response from TideCloak (parsed JSON)
 */
export async function tcProxyFetch<T>(
  tcUrl: string,
  method: string = "GET",
  body?: any,
): Promise<T> {
  // Generate DPoP proof for TideCloak URL (proof #2)
  let tcDpopProof: string | undefined;
  if (isDpopEnabled()) {
    try {
      const provider = (IAMService as any)._dpopProvider;
      if (provider?.generateDPoPProof) {
        const token = await IAMService.getToken();
        tcDpopProof = await provider.generateDPoPProof(
          tcUrl,
          method.toUpperCase(),
          token || undefined,
        );
      }
    } catch (e) {
      console.warn("[tcProxy] Failed to generate TideCloak DPoP proof:", e);
    }
  }

  // Build proxy request headers
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (tcDpopProof) {
    headers["X-TC-DPoP"] = tcDpopProof;
  }

  // Call our server's proxy endpoint
  // appFetch/secureFetch auto-signs DPoP proof #1 for our server URL
  const response = await appFetch("/api/tc-proxy", {
    method: "POST",
    headers,
    body: JSON.stringify({
      url: tcUrl,
      method: method.toUpperCase(),
      body: body || undefined,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => response.statusText);
    throw new Error(`TC Proxy error: ${response.status} ${errorBody}`);
  }

  const text = await response.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}
