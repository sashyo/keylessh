import { IAMService } from "@tidecloak/js";
import { TideMemory, BaseTideRequest } from "heimdall-tide";
import type { SSHSigner, SSHSignatureRequest } from "@/lib/sshClient";
import { api } from "@/lib/api";
import { BasicCustomRequest } from "asgard-tide";

/**
 * Convert base64 string to Uint8Array
 */
function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodeBase64Url(input: string): string {
  let output = input.replace(/-/g, "+").replace(/_/g, "/");
  while (output.length % 4) output += "=";
  return atob(output);
}

function decodeJwtPayload(token: string): any {
  try {
    const parts = token.split(".");
    if (parts.length < 2) throw new Error("Invalid JWT format");
    const json = decodeBase64Url(parts[1]);
    return JSON.parse(json);
  } catch (err) {
    console.error("Failed to decode JWT payload:", err);
    throw new Error("Invalid or corrupted JWT token");
  }
}

function getTideCloakInstance(): any {
  const tc = (IAMService as any)._tc;
  if (!tc) throw new Error("TideCloak is not initialized");
  return tc;
}

export function getDokenPayload(): any {
  const tc = getTideCloakInstance();
  if (tc.dokenParsed) return tc.dokenParsed;
  if (typeof tc.doken === "string") return decodeJwtPayload(tc.doken);
  throw new Error("No doken available");
}

/**
 * Create human-readable info for SSH signing approval display
 */
function createHumanReadableInfo(req: SSHSignatureRequest): Uint8Array {
  const info = {
    action: "SSH Authentication",
    algorithm: req.algorithmName,
    keyAlgorithm: req.keyAlgorithmName,
    username: req.username,
    serverId: req.serverId,
    timestamp: new Date().toISOString(),
  };
  return new TextEncoder().encode(JSON.stringify(info));
}

/**
 * Creates a Tide SSH signer using the new BasicCustomRequest pattern.
 *
 * BasicCustomRequest format:
 * - Pattern: BasicCustom<Name>:BasicCustom<Version>
 * - Draft[0]: Human readable info (for approval display)
 * - Draft[1+]: Data to sign (SSH challenge)
 *
 * This replaces the legacy Custom<SSH>:Custom<1> pattern.
 */
export function createTideSshSigner(): SSHSigner {
  return async (req: SSHSignatureRequest) => {
    console.log(`[TideSsh] === Starting SSH signing for user '${req.username}' ===`);

    const tc = getTideCloakInstance();

    if (typeof tc.createTideRequest !== "function" || typeof tc.executeSignRequest !== "function") {
      throw new Error("Tide signing APIs are not available (createTideRequest/executeSignRequest)");
    }

    // Fetch the committed policy for this SSH user
    // Policy is matched by role: ssh:<username>
    let policyBytes: Uint8Array | null = null;
    console.log(`[TideSsh] Fetching policy for SSH user '${req.username}' (role: ssh:${req.username})`);
    try {
      const policyResult = await api.sshPolicies.getForSshUser(req.username);
      console.log(`[TideSsh] API response:`, policyResult);
      if (policyResult.policyData) {
        policyBytes = base64ToBytes(policyResult.policyData);
        console.log(`[TideSsh] Decoded policy bytes: ${policyBytes.length} bytes`);
      } else {
        console.warn(`[TideSsh] API returned no policyData for user '${req.username}'`);
      }
    } catch (err) {
      console.error(`[TideSsh] Failed to fetch committed policy for SSH user '${req.username}':`, err);
      // Continue without policy - Ork will reject if policy is required
    }

    // New pattern: BasicCustom<SSH>:BasicCustom<1>
    // Draft contains: data to sign
    const draft = req.data;

    // Use BasicCustomRequest pattern for SSH challenge signing
    // Use Policy:1 auth flow with contract validation (implicit flow - no operator signatures)
    const name = "BasicCustom<SSH>";
    const version = "BasicCustom<1>";
    console.log(`[TideSsh] Creating request with name='${name}' version='${version}' modelId='${name}:${version}'`);
    const tideRequest = new BasicCustomRequest(
      name,                    // Name: BasicCustom<SSH>
      version,                 // Version: BasicCustom<1>
      "Policy:1",              // AuthFlow: Policy authorization with implicit flow (no popup)
      draft,                   // Draft: what you want to sign
      new TideMemory()         // DynamicData: empty (not needed for basic)
    );

    // Add doken to Authorizer field (Policy:1 implicit flow reads from here)
    const doken = tc.doken;
    if (!doken) {
      throw new Error("[TideSsh] No doken available");
    }

    const dokenBytes = new TextEncoder().encode(doken);
    const dokenMemory = TideMemory.CreateFromArray([dokenBytes]);
    tideRequest.addAuthorizer(dokenMemory);
    console.log(`[TideSsh] Added doken to authorizer`);

    // Add the policy if we fetched one (for contract validation in the request model)
    if (policyBytes) {
      tideRequest.addPolicy(policyBytes);
      console.log(`[TideSsh] Added policy (${policyBytes.length} bytes)`);
    }

    // Initialize and execute the request
    // Policy:1 implicit flow verifies dokens and runs contract validation
    // No operator signatures needed (empty authorization[1] triggers implicit flow)
    console.log(`[TideSsh] Calling createTideRequest...`);
    const initializedRequestBytes = await tc.createTideRequest(tideRequest.encode());

    console.log(`[TideSsh] Executing sign request...`);
    const sigs: Uint8Array[] = await tc.executeSignRequest(initializedRequestBytes, true);

    const sig = sigs?.[0];
    if (!(sig instanceof Uint8Array)) {
      throw new Error("Tide enclave did not return a signature");
    }
    if (sig.length !== 64) {
      throw new Error(`Unexpected Ed25519 signature length: ${sig.length}`);
    }
    return sig;
  };
}

/**
 * Creates a Tide SSH signer using the DynamicCustomRequest pattern.
 * Use this when the challenge data may change between authorization and signing.
 *
 * DynamicCustomRequest format:
 * - Pattern: DynamicCustom<Name>:DynamicCustom<Version>
 * - Draft: Metadata/configuration (optional)
 * - DynamicData: Data to sign (can change without invalidating auth)
 */
export function createDynamicTideSshSigner(): SSHSigner {
  return async (req: SSHSignatureRequest) => {
    const tc = getTideCloakInstance();

    if (typeof tc.createTideRequest !== "function" || typeof tc.executeSignRequest !== "function") {
      throw new Error("Tide signing APIs are not available (createTideRequest/executeSignRequest)");
    }

    // Fetch the committed policy for this SSH user
    // Policy is matched by role: ssh:<username>
    let policyBytes: Uint8Array | null = null;
    try {
      const policyResult = await api.sshPolicies.getForSshUser(req.username);
      if (policyResult.policyData) {
        policyBytes = base64ToBytes(policyResult.policyData);
        console.log(`[TideSsh] Fetched policy for SSH user '${req.username}' (role: ${policyResult.roleId}), ${policyBytes.length} bytes`);
      }
    } catch (err) {
      console.warn(`[TideSsh] Failed to fetch committed policy for SSH user '${req.username}':`, err);
      // Continue without policy - Ork will reject if policy is required
    }

    // DynamicCustom pattern: data to sign is in DynamicData
    const metadata = new TextEncoder().encode(JSON.stringify({
      algorithm: req.algorithmName,
      username: req.username,
      serverId: req.serverId,
    }));

    const draft = TideMemory.CreateFromArray([metadata]);
    const dynamicData = TideMemory.CreateFromArray([req.data]);

    // Use Policy:1 auth flow with contract validation
    const tideRequest = new BaseTideRequest(
      "DynamicCustom<SSH>",    // Name: DynamicCustom<SSH>
      "DynamicCustom<1>",      // Version: DynamicCustom<1>
      "Policy:1",              // AuthFlow: Policy authorization with contract validation
      draft,                   // Draft: metadata
      dynamicData              // DynamicData: challengeData (can change)
    );

    // Add doken to Authorizer field and doken.Signature as authorization
    const doken = tc.doken;
    if (doken) {
      const dokenBytes = new TextEncoder().encode(doken);
      const dokenMemory = TideMemory.CreateFromArray([dokenBytes]);
      tideRequest.addAuthorizer(dokenMemory);

      // Extract signature from doken JWT (third part)
      const parts = doken.split('.');
      if (parts.length >= 3) {
        const signatureB64 = parts[2];
        const signatureBytes = base64ToBytes(signatureB64.replace(/-/g, '+').replace(/_/g, '/'));
        const signatureMemory = TideMemory.CreateFromArray([signatureBytes]);
        tideRequest.addAuthorization(signatureMemory);
      }
    }

    // Add the policy if we fetched one
    if (policyBytes) {
      tideRequest.addPolicy(policyBytes);
    }

    const initializedRequestBytes = await tc.createTideRequest(tideRequest.encode());
    const sigs: Uint8Array[] = await tc.executeSignRequest(initializedRequestBytes, true);

    const sig = sigs?.[0];
    if (!(sig instanceof Uint8Array)) {
      throw new Error("Tide enclave did not return a signature");
    }
    if (sig.length !== 64) {
      throw new Error(`Unexpected Ed25519 signature length: ${sig.length}`);
    }
    return sig;
  };
}

