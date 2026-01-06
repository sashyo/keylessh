import { Policy, PolicySignRequest, TideMemory } from "heimdall-tide";
import { ApprovalType, ExecutionType } from "asgard-tide";
import { api } from "./api";


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
// Uses [PolicyParam] attributes and DecisionBuilder for clean, declarative policy logic
export const SSH_FORSETI_CONTRACT = `using Ork.Forseti.Sdk;

/// <summary>
/// SSH Challenge Signing Policy for Keyle-SSH.
/// Uses [PolicyParam] attributes for automatic parameter binding and
/// DecisionBuilder for composable policy validation.
/// </summary>
public class SshPolicy : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Role required for SSH access")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role check")]
    public string Resource { get; set; }

    /// <summary>
    /// Validate the request data. Always called.
    /// Parameters are validated automatically via [PolicyParam] attributes.
    /// </summary>
    public PolicyDecision ValidateData(DataContext ctx)
    {
        return PolicyDecision.Allow();
    }

    /// <summary>
    /// Validate approvers when policy.approvalType == EXPLICIT.
    /// Checks that at least one approver has the required role for the resource.
    /// </summary>
    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var approvers = DokenDto.WrapAll(ctx.Dokens);
        return Decision
            .Require(approvers != null && approvers.Count > 0, "No approver dokens provided")
            .RequireAnyWithRole(approvers, Resource, Role);
    }

    /// <summary>
    /// Validate executor when policy.executorType == PRIVATE.
    /// Checks that the executor has the required role for the resource.
    /// </summary>
    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var executor = new DokenDto(ctx.Doken);
        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, Resource, Role);
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
 * Computes the contract ID (SHA512 hash of source code) for a Forseti contract.
 * This ensures the contractId matches exactly what Ork will compute.
 *
 * @param source - The C# source code of the contract
 * @returns The contract ID (SHA512 hash)
 * @throws Error if computation fails
 */
export async function compileForsetiContract(
  source: string,
  _options?: { validate?: boolean; entryType?: string }
): Promise<{ contractId: string }> {
  const result = await api.forseti.compile(source);

  if (!result.success || !result.contractId) {
    throw new Error(result.error || "Failed to compute contract ID");
  }

  return {
    contractId: result.contractId,
  };
}

/**
 * Creates a PolicySignRequest for SSH signing.
 * Computes the contract ID (SHA512 hash) from source code.
 */
export async function createSshPolicyRequest(
  config: SshPolicyConfig
): Promise<PolicySignRequest> {
  // Compute the contract ID from source code
  const { contractId } = await compileForsetiContract(SSH_FORSETI_CONTRACT);

  // Create policy request with the contract ID
  const policyParams = new Map<string, any>();
  policyParams.set("role", config.roleName);
  policyParams.set("threshold", config.threshold);
  policyParams.set("resource", config.resource);
  policyParams.set("approval_type", config.approvalType);
  policyParams.set("execution_type", config.executionType);

  // Version 2 includes approvalType and executionType in the serialized format
  const policy = new Policy({
    version: "2",
    modelId: config.modelId,
    contractId: contractId,
    keyId: config.vendorId,
    approvalType: config.approvalType === "explicit" ? ApprovalType.EXPLICIT : ApprovalType.IMPLICIT,
    executionType: config.executionType === "private" ? ExecutionType.PRIVATE : ExecutionType.PUBLIC,
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
 * Creates a PolicySignRequest with custom contract code.
 * Computes the contract ID (SHA512 hash) from the source code.
 *
 * Use this when creating policies from templates with custom contract logic.
 */
export async function createSshPolicyRequestWithCode(
  config: SshPolicyConfigWithCode
): Promise<{ request: PolicySignRequest; contractId: string }> {
  // Compute the contract ID from source code
  const { contractId } = await compileForsetiContract(config.contractCode);

  // Detect entry type from custom code
  const entryType = detectEntryType(config.contractCode) || "SshPolicy";

  // Create policy request with the contract ID
  const policyParams = new Map<string, any>();
  policyParams.set("role", config.roleName);
  policyParams.set("threshold", config.threshold);
  policyParams.set("resource", config.resource);
  policyParams.set("approval_type", config.approvalType);
  policyParams.set("execution_type", config.executionType);

  // Version 2 includes approvalType and executionType in the serialized format
  const policy = new Policy({
    version: "2",
    modelId: config.modelId,
    contractId: contractId,
    keyId: config.vendorId,
    approvalType: config.approvalType === "explicit" ? ApprovalType.EXPLICIT : ApprovalType.IMPLICIT,
    executionType: config.executionType === "private" ? ExecutionType.PRIVATE : ExecutionType.PUBLIC,
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

  return { request: policyRequest, contractId };
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
