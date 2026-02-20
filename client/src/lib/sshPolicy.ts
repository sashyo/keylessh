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
using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// SSH Challenge Signing Policy for Keyle-SSH.
/// Uses [PolicyParam] attributes for automatic parameter binding and
/// DecisionBuilder for composable policy validation.
/// </summary>
public class Contract : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Role required for SSH access.")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role check.")]
    public string Resource { get; set; }

    /// <summary>
    /// Validate the request data. Always called.
    /// This validates ctx.Data is an SSHv2 publickey authentication "to-be-signed" payload:
    /// string session_id || byte 50 || string user || string "ssh-connection" || string "publickey" || bool TRUE
    /// || string alg || string key_blob
    /// </summary>
    public PolicyDecision ValidateData(DataContext ctx)
    {
        if (string.IsNullOrWhiteSpace(Role))
            return PolicyDecision.Deny("Role is missing.");

        var parts = Role.Split(':', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || parts[1].Length == 0)
            return PolicyDecision.Deny("Role must be in the form 'prefix:role'.");

        var userRole = parts[1];

        if (ctx == null || ctx.Data == null || ctx.Data.Length == 0)
            return PolicyDecision.Deny("No data provided for SSH challenge validation");

        if (ctx.Data.Length < 24)
            return PolicyDecision.Deny($"Data too short to be an SSH publickey challenge: {ctx.Data.Length} bytes");

        if (ctx.Data.Length > 8192)
            return PolicyDecision.Deny($"Data too large for SSH challenge: {ctx.Data.Length} bytes (maximum 8192)");

        if (!SshPublicKeyChallenge.TryParse(ctx.Data, out var parsed, out var err))
            return PolicyDecision.Deny(err);

        if (parsed.PublicKeyAlgorithm != "ssh-ed25519")
            return PolicyDecision.Deny("Only ssh-ed25519 allowed");
        
        if(parsed.Username != userRole) {
            return PolicyDecision.Deny("Not allowed to log in as " + parsed.Username);
        }

        return PolicyDecision.Allow();
    }

    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var approvers = DokenDto.WrapAll(ctx.Dokens);
        return Decision
            .Require(approvers != null && approvers.Count > 0, "No approver dokens provided")
            .RequireAnyWithRole(approvers, Resource, Role);
    }

    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var executor = new DokenDto(ctx.Doken);
        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, Resource, Role);
    }

    internal static class SshPublicKeyChallenge
    {
        internal sealed class Parsed
        {
            public int SessionIdLength { get; set; }
            public string Username { get; set; }
            public string Service { get; set; }
            public string Method { get; set; }
            public string PublicKeyAlgorithm { get; set; }
            public string PublicKeyBlobType { get; set; }
            public int PublicKeyBlobLength { get; set; }
        }

        public static bool TryParse(byte[] buf, out Parsed parsed, out string error)
        {
            parsed = null;
            error = "";

            int off = 0;

            // session_id (ssh string)
            if (!TryReadSshString(buf, ref off, out var sessionId))
            {
                error = "Invalid SSH string for session_id";
                return false;
            }

            // Common session_id lengths: 20/32/48/64
            if (!(sessionId.Length == 20 || sessionId.Length == 32 || sessionId.Length == 48 || sessionId.Length == 64))
            {
                error = $"Unexpected session_id length: {sessionId.Length}";
                return false;
            }

            // message type
            if (!TryReadByte(buf, ref off, out byte msg))
            {
                error = "Missing SSH message type";
                return false;
            }

            if (msg != 50) // SSH_MSG_USERAUTH_REQUEST
            {
                error = $"Not SSH userauth request (expected msg 50, got {msg})";
                return false;
            }

            // username, service, method
            if (!TryReadSshAscii(buf, ref off, 256, out var username, out error)) return false;
            if (!TryReadSshAscii(buf, ref off, 64, out var service, out error)) return false;
            if (!TryReadSshAscii(buf, ref off, 64, out var method, out error)) return false;

            if (!string.Equals(service, "ssh-connection", StringComparison.Ordinal))
            {
                error = $"Unexpected SSH service: {service}";
                return false;
            }

            if (!string.Equals(method, "publickey", StringComparison.Ordinal))
            {
                error = $"Unexpected SSH auth method: {method}";
                return false;
            }

            // boolean TRUE
            if (!TryReadByte(buf, ref off, out byte hasSig))
            {
                error = "Missing publickey boolean";
                return false;
            }

            if (hasSig != 1)
            {
                error = "Expected publickey boolean TRUE (1)";
                return false;
            }

            // algorithm
            if (!TryReadSshAscii(buf, ref off, 128, out var alg, out error)) return false;

            // Allowlist
            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "ssh-ed25519",
                "rsa-sha2-256",
                "rsa-sha2-512",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            };

            if (!allowed.Contains(alg))
            {
                error = $"Disallowed/unknown SSH public key algorithm: {alg}";
                return false;
            }

            // key blob
            if (!TryReadSshString(buf, ref off, out var keyBlob))
            {
                error = "Invalid SSH string for publickey blob";
                return false;
            }

            if (keyBlob.Length < 8)
            {
                error = "Publickey blob too short";
                return false;
            }

            // key blob begins with ssh string key type
            int kbOff = 0;
            if (!TryReadSshString(keyBlob, ref kbOff, out var keyTypeBytes))
            {
                error = "Invalid publickey blob (missing key type string)";
                return false;
            }

            var keyType = AsciiString(keyTypeBytes, 64);
            if (keyType == null)
            {
                error = "Invalid publickey blob key type (non-ASCII or too long)";
                return false;
            }

            if (!IsAlgConsistentWithKeyType(alg, keyType))
            {
                error = $"Algorithm/key type mismatch: alg={alg}, keyType={keyType}";
                return false;
            }

            // Strict: no trailing bytes
            if (off != buf.Length)
            {
                error = $"Unexpected trailing data: {buf.Length - off} bytes";
                return false;
            }

            parsed = new Parsed
            {
                SessionIdLength = sessionId.Length,
                Username = username,
                Service = service,
                Method = method,
                PublicKeyAlgorithm = alg,
                PublicKeyBlobType = keyType,
                PublicKeyBlobLength = keyBlob.Length
            };

            return true;
        }

        private static bool IsAlgConsistentWithKeyType(string alg, string keyType)
        {
            if (alg == "ssh-ed25519") return keyType == "ssh-ed25519";
            if (alg == "rsa-sha2-256" || alg == "rsa-sha2-512") return keyType == "ssh-rsa";
            if (alg.StartsWith("ecdsa-sha2-nistp", StringComparison.Ordinal)) return keyType == alg;
            return false;
        }

        private static bool TryReadByte(byte[] buf, ref int off, out byte b)
        {
            b = 0;
            if (off >= buf.Length) return false;
            b = buf[off++];
            return true;
        }

        private static bool TryReadU32(byte[] buf, ref int off, out uint v)
        {
            v = 0;
            if (off + 4 > buf.Length) return false;
            v = (uint)(buf[off] << 24 | buf[off + 1] << 16 | buf[off + 2] << 8 | buf[off + 3]);
            off += 4;
            return true;
        }

        // SSH "string" = uint32 len + len bytes
        private static bool TryReadSshString(byte[] buf, ref int off, out byte[] s)
        {
            s = null;
            if (!TryReadU32(buf, ref off, out var len)) return false;
            if (len > (uint)(buf.Length - off)) return false;

            s = new byte[(int)len];
            Buffer.BlockCopy(buf, off, s, 0, (int)len);
            off += (int)len;
            return true;
        }

        private static bool TryReadSshAscii(byte[] buf, ref int off, int maxLen, out string value, out string error)
        {
            value = "";
            error = "";

            if (!TryReadSshString(buf, ref off, out var bytes))
            {
                error = "Invalid SSH string field";
                return false;
            }

            if (bytes.Length == 0 || bytes.Length > maxLen)
            {
                error = $"Invalid field length: {bytes.Length} (max {maxLen})";
                return false;
            }

            var s = AsciiString(bytes, maxLen);
            if (s == null)
            {
                error = "Field contains non-ASCII or control characters";
                return false;
            }

            value = s;
            return true;
        }

        private static string AsciiString(byte[] bytes, int maxLen)
        {
            if (bytes.Length == 0 || bytes.Length > maxLen) return null;

            for (int i = 0; i < bytes.Length; i++)
            {
                byte c = bytes[i];
                if (c < 0x20 || c > 0x7E) return null;
            }

            return Encoding.ASCII.GetString(bytes);
        }
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
  const entryTypeBytes = new TextEncoder().encode("Contract");
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

  // Entry type must be a Contract implementing IAccessPolicy
  const detectedEntryType = detectEntryType(config.contractCode);
  if (!detectedEntryType) {
    throw new Error("Contract code must declare `public class Contract : IAccessPolicy`.");
  }
  if (detectedEntryType !== "Contract") {
    throw new Error(
      `Contract entry type must be "Contract" (expected \`public class Contract : IAccessPolicy\`, found "${detectedEntryType}").`
    );
  }
  const entryType = "Contract";

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
  const match = source.match(/public\s+(?:\w+\s+)*class\s+(\w+)\s*:\s*IAccessPolicy/);
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
