/**
 * TURN method handlers.
 *
 * When TURN_SECRET is set, all TURN requests (except Send indications)
 * require authentication via the TURN REST API ephemeral credentials.
 * The browser handles the 401 challenge/retry automatically.
 */

import type { StunMessage } from "../stun/message.js";
import { buildMessage, getAttribute } from "../stun/message.js";
import {
  CLASS_SUCCESS,
  CLASS_ERROR,
  METHOD_ALLOCATE,
  METHOD_REFRESH,
  METHOD_CREATE_PERMISSION,
  METHOD_CHANNEL_BIND,
  METHOD_SEND,
  SOFTWARE_NAME,
  TRANSPORT_UDP,
  ATTR_REQUESTED_TRANSPORT,
  ATTR_LIFETIME,
  ATTR_XOR_PEER_ADDRESS,
  ATTR_CHANNEL_NUMBER,
  ATTR_DATA,
  ATTR_USERNAME,
  ERR_BAD_REQUEST,
  ERR_UNAUTHORIZED,
  ERR_ALLOCATION_MISMATCH,
  ERR_UNSUPPORTED_TRANSPORT,
  ERR_INSUFFICIENT_CAPACITY,
} from "../stun/constants.js";
import {
  buildXorMappedAddress,
  buildXorRelayedAddress,
  buildLifetime,
  buildErrorCode,
  buildSoftware,
  buildRealm,
  buildNonce,
  decodeXorAddress,
  parseLifetime,
  parseRequestedTransport,
  parseChannelNumber,
} from "../stun/attributes.js";
import type { TransportInfo } from "../stun/binding.js";
import type { AllocationManager } from "./allocation-manager.js";
import { makeFiveTupleKey } from "./types.js";
import { installPermission } from "./permission-manager.js";
import { bindChannel } from "./channel-manager.js";
import { sendToRelay } from "./relay.js";
import { validateTurnCredentials } from "./auth.js";

export interface TurnHandlerContext {
  allocationManager: AllocationManager;
  defaultLifetime: number;
  realm: string;
  /** Shared secret for TURN REST API credentials. Empty = no auth. */
  turnSecret: string;
}

/**
 * Dispatch a TURN request to the appropriate handler.
 * Returns a response buffer, or null for indications (no response).
 */
export async function handleTurnMessage(
  ctx: TurnHandlerContext,
  msg: StunMessage,
  transport: TransportInfo
): Promise<Buffer | null> {
  // Authenticate all TURN requests (except Send indications) when secret is set
  let authKey: Buffer | undefined;
  if (ctx.turnSecret && msg.header.method !== METHOD_SEND) {
    const authResult = authenticateTurn(ctx, msg);
    if (authResult.error) return authResult.error;
    authKey = authResult.key;
  }

  switch (msg.header.method) {
    case METHOD_ALLOCATE:
      return handleAllocate(ctx, msg, transport, authKey);
    case METHOD_REFRESH:
      return handleRefresh(ctx, msg, transport, authKey);
    case METHOD_CREATE_PERMISSION:
      return handleCreatePermission(ctx, msg, transport, authKey);
    case METHOD_CHANNEL_BIND:
      return handleChannelBind(ctx, msg, transport, authKey);
    case METHOD_SEND:
      handleSend(ctx, msg, transport);
      return null; // Indications have no response
    default:
      return buildErrorMessage(
        msg,
        ERR_BAD_REQUEST,
        "Unknown method"
      );
  }
}

// ── Auth ──────────────────────────────────────────────────────────

/**
 * Validate TURN credentials. Returns { error } if auth fails,
 * or { key } with the long-term credential key if auth succeeds.
 */
function authenticateTurn(
  ctx: TurnHandlerContext,
  msg: StunMessage
): { error: Buffer; key?: undefined } | { error?: undefined; key: Buffer } {
  // If no USERNAME attribute, send 401 challenge with REALM + NONCE
  const usernameAttr = getAttribute(msg, ATTR_USERNAME);
  if (!usernameAttr) {
    // Generate a nonce (timestamp-based so we can detect staleness)
    const nonce = Math.floor(Date.now() / 1000).toString(36);

    return {
      error: buildMessage(
        msg.header.method,
        CLASS_ERROR,
        msg.header.transactionId,
        [
          buildErrorCode(ERR_UNAUTHORIZED, "Unauthorized"),
          buildRealm(ctx.realm),
          buildNonce(nonce),
          buildSoftware(SOFTWARE_NAME),
        ]
      ),
    };
  }

  // Validate credentials
  const result = validateTurnCredentials(msg, ctx.realm, ctx.turnSecret);
  if (!result.authenticated || !result.key) {
    console.log(`[TURN] Auth failed: ${result.reason}`);
    return {
      error: buildMessage(
        msg.header.method,
        CLASS_ERROR,
        msg.header.transactionId,
        [
          buildErrorCode(ERR_UNAUTHORIZED, result.reason || "Unauthorized"),
          buildRealm(ctx.realm),
          buildNonce(Math.floor(Date.now() / 1000).toString(36)),
          buildSoftware(SOFTWARE_NAME),
        ]
      ),
    };
  }

  return { key: result.key };
}

// ── Allocate ─────────────────────────────────────────────────────

async function handleAllocate(
  ctx: TurnHandlerContext,
  msg: StunMessage,
  transport: TransportInfo,
  authKey?: Buffer
): Promise<Buffer> {
  // Check REQUESTED-TRANSPORT
  const rtAttr = getAttribute(msg, ATTR_REQUESTED_TRANSPORT);
  if (!rtAttr) {
    return buildErrorMessage(msg, ERR_BAD_REQUEST, "Missing REQUESTED-TRANSPORT", authKey);
  }
  const requestedTransport = parseRequestedTransport(rtAttr.value);
  if (requestedTransport !== TRANSPORT_UDP) {
    return buildErrorMessage(msg, ERR_UNSUPPORTED_TRANSPORT, "Only UDP relay supported", authKey);
  }

  // Check for existing allocation
  const tupleKey = makeFiveTupleKey(
    transport.protocol,
    transport.sourceAddress,
    transport.sourcePort
  );
  if (ctx.allocationManager.get(tupleKey)) {
    return buildErrorMessage(msg, ERR_ALLOCATION_MISMATCH, "Allocation already exists", authKey);
  }

  // Get requested lifetime
  const ltAttr = getAttribute(msg, ATTR_LIFETIME);
  let lifetime = ctx.defaultLifetime;
  if (ltAttr) {
    lifetime = Math.min(parseLifetime(ltAttr.value), 3600); // Max 1 hour
    lifetime = Math.max(lifetime, 60); // Min 1 minute
  }

  // Create allocation
  try {
    const alloc = await ctx.allocationManager.create(
      transport.sourceAddress,
      transport.sourcePort,
      transport.protocol,
      lifetime
    );

    const attrs = [
      buildXorRelayedAddress(
        alloc.relayAddress,
        alloc.relayPort,
        msg.header.transactionId
      ),
      buildXorMappedAddress(
        transport.sourceAddress,
        transport.sourcePort,
        msg.header.transactionId
      ),
      buildLifetime(alloc.lifetime),
      buildSoftware(SOFTWARE_NAME),
    ];

    return buildMessage(
      METHOD_ALLOCATE,
      CLASS_SUCCESS,
      msg.header.transactionId,
      attrs,
      { integrityKey: authKey }
    );
  } catch (err) {
    console.error("[TURN] Allocate failed:", err);
    return buildErrorMessage(msg, ERR_INSUFFICIENT_CAPACITY, "No relay ports available", authKey);
  }
}

// ── Refresh ──────────────────────────────────────────────────────

function handleRefresh(
  ctx: TurnHandlerContext,
  msg: StunMessage,
  transport: TransportInfo,
  authKey?: Buffer
): Buffer {
  const tupleKey = makeFiveTupleKey(
    transport.protocol,
    transport.sourceAddress,
    transport.sourcePort
  );

  const ltAttr = getAttribute(msg, ATTR_LIFETIME);
  let lifetime = ctx.defaultLifetime;
  if (ltAttr) {
    lifetime = parseLifetime(ltAttr.value);
    if (lifetime > 0) {
      lifetime = Math.min(lifetime, 3600);
      lifetime = Math.max(lifetime, 60);
    }
    // lifetime === 0 means deallocate
  }

  const result = ctx.allocationManager.refresh(tupleKey, lifetime);
  if (result === null) {
    return buildErrorMessage(msg, ERR_ALLOCATION_MISMATCH, "No allocation found", authKey);
  }

  return buildMessage(
    METHOD_REFRESH,
    CLASS_SUCCESS,
    msg.header.transactionId,
    [buildLifetime(result), buildSoftware(SOFTWARE_NAME)],
    { integrityKey: authKey }
  );
}

// ── CreatePermission ─────────────────────────────────────────────

function handleCreatePermission(
  ctx: TurnHandlerContext,
  msg: StunMessage,
  transport: TransportInfo,
  authKey?: Buffer
): Buffer {
  const tupleKey = makeFiveTupleKey(
    transport.protocol,
    transport.sourceAddress,
    transport.sourcePort
  );
  const alloc = ctx.allocationManager.get(tupleKey);
  if (!alloc) {
    return buildErrorMessage(msg, ERR_ALLOCATION_MISMATCH, "No allocation found", authKey);
  }

  // Install permissions for all XOR-PEER-ADDRESS attributes
  let foundPeer = false;
  for (const attr of msg.attributes) {
    if (attr.type === ATTR_XOR_PEER_ADDRESS) {
      const peer = decodeXorAddress(attr.value, msg.header.transactionId);
      if (peer) {
        installPermission(alloc, peer.address);
        foundPeer = true;
      }
    }
  }

  if (!foundPeer) {
    return buildErrorMessage(msg, ERR_BAD_REQUEST, "Missing XOR-PEER-ADDRESS", authKey);
  }

  return buildMessage(
    METHOD_CREATE_PERMISSION,
    CLASS_SUCCESS,
    msg.header.transactionId,
    [buildSoftware(SOFTWARE_NAME)],
    { integrityKey: authKey }
  );
}

// ── ChannelBind ──────────────────────────────────────────────────

function handleChannelBind(
  ctx: TurnHandlerContext,
  msg: StunMessage,
  transport: TransportInfo,
  authKey?: Buffer
): Buffer {
  const tupleKey = makeFiveTupleKey(
    transport.protocol,
    transport.sourceAddress,
    transport.sourcePort
  );
  const alloc = ctx.allocationManager.get(tupleKey);
  if (!alloc) {
    return buildErrorMessage(msg, ERR_ALLOCATION_MISMATCH, "No allocation found", authKey);
  }

  const cnAttr = getAttribute(msg, ATTR_CHANNEL_NUMBER);
  if (!cnAttr) {
    return buildErrorMessage(msg, ERR_BAD_REQUEST, "Missing CHANNEL-NUMBER", authKey);
  }
  const channelNumber = parseChannelNumber(cnAttr.value);

  const peerAttr = getAttribute(msg, ATTR_XOR_PEER_ADDRESS);
  if (!peerAttr) {
    return buildErrorMessage(msg, ERR_BAD_REQUEST, "Missing XOR-PEER-ADDRESS", authKey);
  }
  const peer = decodeXorAddress(peerAttr.value, msg.header.transactionId);
  if (!peer) {
    return buildErrorMessage(msg, ERR_BAD_REQUEST, "Invalid XOR-PEER-ADDRESS", authKey);
  }

  const ok = bindChannel(alloc, channelNumber, peer.address, peer.port);
  if (!ok) {
    return buildErrorMessage(msg, ERR_BAD_REQUEST, "Channel binding conflict", authKey);
  }

  return buildMessage(
    METHOD_CHANNEL_BIND,
    CLASS_SUCCESS,
    msg.header.transactionId,
    [buildSoftware(SOFTWARE_NAME)],
    { integrityKey: authKey }
  );
}

// ── Send indication ──────────────────────────────────────────────

function handleSend(
  ctx: TurnHandlerContext,
  msg: StunMessage,
  transport: TransportInfo
): void {
  const key = makeFiveTupleKey(
    transport.protocol,
    transport.sourceAddress,
    transport.sourcePort
  );
  const alloc = ctx.allocationManager.get(key);
  if (!alloc) return;

  const peerAttr = getAttribute(msg, ATTR_XOR_PEER_ADDRESS);
  const dataAttr = getAttribute(msg, ATTR_DATA);
  if (!peerAttr || !dataAttr) return;

  const peer = decodeXorAddress(peerAttr.value, msg.header.transactionId);
  if (!peer) return;

  sendToRelay(alloc, peer.address, peer.port, dataAttr.value);
}

// ── Helpers ──────────────────────────────────────────────────────

function buildErrorMessage(
  request: StunMessage,
  code: number,
  reason: string,
  authKey?: Buffer
): Buffer {
  return buildMessage(
    request.header.method,
    CLASS_ERROR,
    request.header.transactionId,
    [buildErrorCode(code, reason), buildSoftware(SOFTWARE_NAME)],
    { integrityKey: authKey }
  );
}
