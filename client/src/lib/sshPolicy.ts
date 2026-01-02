import { Policy, PolicySignRequest, TideMemory } from "heimdall-tide";
import { api } from "./api";

/**
 * Creates a TideMemory-compatible byte array from an array of Uint8Arrays.
 * This matches the exact format expected by Ork's enclave Serialization.js:
 * - Bytes 0-3: version (int32 LE, always 1)
 * - For each value: 4 bytes length (int32 LE) + data bytes
 */
function createTideMemoryBytes(datas: Uint8Array[]): Uint8Array {
  // Calculate total length: 4 (version) + sum of (4 + data.length) for each value
  const totalDataLength = datas.reduce((sum, d) => sum + 4 + d.length, 0);
  const bufferLength = 4 + totalDataLength;
  const buffer = new Uint8Array(bufferLength);
  const view = new DataView(buffer.buffer);

  // Write version at position 0
  view.setInt32(0, 1, true); // version = 1, little-endian

  let offset = 4;
  for (const data of datas) {
    // Write length
    view.setInt32(offset, data.length, true);
    offset += 4;
    // Write data
    buffer.set(data, offset);
    offset += data.length;
  }

  return buffer;
}

/**
 * Reads a value at the given index from a TideMemory-formatted byte array.
 * This matches Ork's enclave Serialization.js GetValue function.
 */
function getTideMemoryValue(buffer: Uint8Array, index: number): Uint8Array {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let offset = 4; // Skip version

  for (let i = 0; i < index; i++) {
    const len = view.getInt32(offset, true);
    offset += 4 + len;
  }

  const finalLen = view.getInt32(offset, true);
  offset += 4;

  return buffer.slice(offset, offset + finalLen);
}

// SSH Contract Model IDs
export const SSH_MODEL_IDS = {
  BASIC: "BasicCustom<SSH>:BasicCustom<1>",
  DYNAMIC: "DynamicCustom<SSH>:DynamicCustom<1>",
  DYNAMIC_APPROVED: "DynamicApprovedCustom<SSH>:DynamicApprovedCustom<1>",
} as const;

export type SshModelId = (typeof SSH_MODEL_IDS)[keyof typeof SSH_MODEL_IDS];

// The Forseti SSH contract source code
// This C# code is compiled and executed by Ork for policy validation
// Exported for display in the approval review dialog
export const SSH_FORSETI_CONTRACT = `using Ork.Forseti.Sdk;

/// <summary>
/// SSH Challenge Signing Policy for Keyle-SSH.
/// Implements the 3-method IAccessPolicy interface:
/// - ValidateData: ALWAYS called (validates policy parameters)
/// - ValidateApprovers: Called if approvalType == EXPLICIT (validates approver dokens)
/// - ValidateExecutor: Called if executorType == PRIVATE (validates executor doken)
/// </summary>
public class SshPolicy : IAccessPolicy
{
    /// <summary>
    /// Validate the request data. Always called.
    /// Checks that required policy parameters (role, resource) are present.
    /// </summary>
    public PolicyDecision ValidateData(DataContext ctx)
    {
        var policy = ctx.Policy;

        if (policy == null)
            return PolicyDecision.Deny("No policy provided");

        // Get required parameters from policy
        if (!policy.Params.TryGetParameter<string>("role", out var requiredRole) || string.IsNullOrEmpty(requiredRole))
            return PolicyDecision.Deny("Policy missing required 'role' parameter");

        if (!policy.Params.TryGetParameter<string>("resource", out var resource) || string.IsNullOrEmpty(resource))
            return PolicyDecision.Deny("Policy missing required 'resource' parameter");

        ForsetiSdk.Log($"ValidateData: policy validated for role '{requiredRole}' on resource '{resource}'");
        return PolicyDecision.Allow();
    }

    /// <summary>
    /// Validate approvers when policy.approvalType == EXPLICIT.
    /// Checks that at least one approver has the required role for the resource.
    /// </summary>
    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var policy = ctx.Policy;
        var dokens = ctx.Dokens;

        if (policy == null)
            return PolicyDecision.Deny("No policy provided");

        if (dokens == null || dokens.Count == 0)
            return PolicyDecision.Deny("No approver dokens provided");

        // Get required parameters
        if (!policy.Params.TryGetParameter<string>("role", out var requiredRole) || string.IsNullOrEmpty(requiredRole))
            return PolicyDecision.Deny("Policy missing required 'role' parameter");

        if (!policy.Params.TryGetParameter<string>("resource", out var resource) || string.IsNullOrEmpty(resource))
            return PolicyDecision.Deny("Policy missing required 'resource' parameter");

        // Check if any approver has the required role
        foreach (var doken in dokens)
        {
            if (doken.Payload.ResourceAccessRoleExists(resource, requiredRole))
            {
                ForsetiSdk.Log($"ValidateApprovers: approver has role '{requiredRole}' for resource '{resource}'");
                return PolicyDecision.Allow();
            }
        }

        return PolicyDecision.Deny($"No approver has the required role '{requiredRole}' for resource '{resource}'");
    }

    /// <summary>
    /// Validate executor when policy.executorType == PRIVATE.
    /// Checks that the executor (from Authorization header) has the required role.
    /// </summary>
    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var policy = ctx.Policy;
        var doken = ctx.Doken;

        if (policy == null)
            return PolicyDecision.Deny("No policy provided");

        if (doken == null)
            return PolicyDecision.Deny("No executor doken provided");

        // Get required parameters
        if (!policy.Params.TryGetParameter<string>("role", out var requiredRole) || string.IsNullOrEmpty(requiredRole))
            return PolicyDecision.Deny("Policy missing required 'role' parameter");

        if (!policy.Params.TryGetParameter<string>("resource", out var resource) || string.IsNullOrEmpty(resource))
            return PolicyDecision.Deny("Policy missing required 'resource' parameter");

        // Verify that the executor's doken contains the required role
        if (!doken.Payload.ResourceAccessRoleExists(resource, requiredRole))
            return PolicyDecision.Deny($"Executor does not have the required role '{requiredRole}' for resource '{resource}'");

        ForsetiSdk.Log($"ValidateExecutor: executor has role '{requiredRole}' for resource '{resource}'");
        return PolicyDecision.Allow();
    }
}`;

export interface SshPolicyConfig {
  roleName: string;
  threshold: number;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  modelId: SshModelId | string;
  resource: string;
  vendorId: string;
}

export interface SshPolicyConfigWithCode extends SshPolicyConfig {
  contractCode: string;
}

/**
 * Compiles a Forseti contract and returns its contract ID (SHA512 hash).
 * This ensures the contractId matches exactly what Ork will compute.
 *
 * @param source - The C# source code of the contract
 * @param options - Optional validation settings
 * @returns The compiled contract ID and SDK version
 * @throws Error if compilation fails
 */
export async function compileForsetiContract(
  source: string,
  options?: { validate?: boolean; entryType?: string }
): Promise<{ contractId: string; sdkVersion: string; validated: boolean }> {
  const result = await api.forseti.compile(source, options);

  if (!result.success || !result.contractId) {
    throw new Error(result.error || "Contract compilation failed");
  }

  return {
    contractId: result.contractId,
    sdkVersion: result.sdkVersion || "unknown",
    validated: result.validated || false,
  };
}

/**
 * Creates a PolicySignRequest for SSH signing with automatic contract compilation.
 * Compiles the contract first to get the correct contractId from Ork's API.
 *
 * This ensures the contractId always matches what Ork will compute.
 */
export async function createSshPolicyRequest(
  config: SshPolicyConfig
): Promise<PolicySignRequest> {
  // Compile the contract to get the correct contractId
  const { contractId } = await compileForsetiContract(SSH_FORSETI_CONTRACT, {
    validate: true,
    entryType: "SshPolicy",
  });

  // Create policy request with the compiled contractId
  const policyParams = new Map<string, any>();
  policyParams.set("role", config.roleName);
  policyParams.set("threshold", config.threshold);
  policyParams.set("resource", config.resource);
  policyParams.set("approval_type", config.approvalType);
  policyParams.set("execution_type", config.executionType);

  const policy = new Policy({
    version: "1",
    modelId: config.modelId,
    contractId: contractId,
    keyId: config.vendorId,
    params: policyParams,
  });

  const policyRequest = PolicySignRequest.New(policy);
  const policyBytes = policy.toBytes();

  // Create contract transport
  // Structure: forsetiData[1] = innerPayload = [source, entryType]
  const contractTypeBytes = new TextEncoder().encode("forseti");
  const sourceCodeBytes = new TextEncoder().encode(SSH_FORSETI_CONTRACT);
  const entryTypeBytes = new TextEncoder().encode("SshPolicy");
  const innerPayload = TideMemory.CreateFromArray([sourceCodeBytes, entryTypeBytes]);
  const forsetiData = TideMemory.CreateFromArray([new Uint8Array(0), innerPayload]);
  const contractTransport = TideMemory.CreateFromArray([contractTypeBytes, forsetiData]);

  const draftWithContract = TideMemory.CreateFromArray([policyBytes, contractTransport]);
  policyRequest.draft = draftWithContract;
  policyRequest.setCustomExpiry(604800);

  return policyRequest;
}

/**
 * Creates a PolicySignRequest with custom contract code and automatic compilation.
 * Compiles the contract first to get the correct contractId from Ork's API.
 *
 * Use this when creating policies from templates with custom contract logic.
 */
export async function createSshPolicyRequestWithCode(
  config: SshPolicyConfigWithCode
): Promise<{ request: PolicySignRequest; contractId: string; sdkVersion: string }> {
  // Compile the custom contract to get the contractId
  const { contractId, sdkVersion, validated } = await compileForsetiContract(
    config.contractCode,
    {
      validate: true,
      // Try to detect entry type from code, fallback to SshPolicy
      entryType: detectEntryType(config.contractCode) || "SshPolicy",
    }
  );

  if (!validated) {
    throw new Error("Contract validation failed - code may contain forbidden operations");
  }

  // Detect entry type from custom code
  const entryType = detectEntryType(config.contractCode) || "SshPolicy";

  // Create policy request with the compiled contractId
  const policyParams = new Map<string, any>();
  policyParams.set("role", config.roleName);
  policyParams.set("threshold", config.threshold);
  policyParams.set("resource", config.resource);
  policyParams.set("approval_type", config.approvalType);
  policyParams.set("execution_type", config.executionType);

  const policy = new Policy({
    version: "1",
    modelId: config.modelId,
    contractId: contractId,
    keyId: config.vendorId,
    params: policyParams,
  });

  const policyRequest = PolicySignRequest.New(policy);
  const policyBytes = policy.toBytes();

  // Create contract transport with custom code
  // Structure: forsetiData[1] = innerPayload = [source, entryType]
  const contractTypeBytes = new TextEncoder().encode("forseti");
  const sourceCodeBytes = new TextEncoder().encode(config.contractCode);
  const entryTypeBytes = new TextEncoder().encode(entryType);
  const innerPayload = TideMemory.CreateFromArray([sourceCodeBytes, entryTypeBytes]);
  const forsetiData = TideMemory.CreateFromArray([new Uint8Array(0), innerPayload]);
  const contractTransport = TideMemory.CreateFromArray([contractTypeBytes, forsetiData]);

  const draftWithContract = TideMemory.CreateFromArray([policyBytes, contractTransport]);
  policyRequest.draft = draftWithContract;
  policyRequest.setCustomExpiry(604800);

  return { request: policyRequest, contractId, sdkVersion };
}

/**
 * Detects the entry type (class name) from C# source code.
 * Looks for a public class implementing IAccessPolicy.
 */
function detectEntryType(source: string): string | null {
  // Match: public class ClassName : IAccessPolicy
  const match = source.match(/public\s+class\s+(\w+)\s*:\s*IAccessPolicy/);
  return match ? match[1] : null;
}

/**
 * Converts a Uint8Array to base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a base64 string to Uint8Array
 */
export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
