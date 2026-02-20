/**
 * STUN Binding Request handler.
 *
 * Responds with XOR-MAPPED-ADDRESS containing the client's
 * server-reflexive transport address (what the server sees as
 * their source IP:port).
 */

import {
  CLASS_SUCCESS,
  SOFTWARE_NAME,
  METHOD_BINDING,
} from "./constants.js";
import { buildXorMappedAddress, buildSoftware } from "./attributes.js";
import { buildMessage } from "./message.js";
import type { StunMessage } from "./message.js";

export interface TransportInfo {
  sourceAddress: string;
  sourcePort: number;
  protocol: "udp" | "tcp";
}

/**
 * Handle a STUN Binding Request. Returns a Binding Success Response.
 * No authentication required (per RFC 5389).
 */
export function handleBindingRequest(
  request: StunMessage,
  transport: TransportInfo
): Buffer {
  const attrs = [
    buildXorMappedAddress(
      transport.sourceAddress,
      transport.sourcePort,
      request.header.transactionId
    ),
    buildSoftware(SOFTWARE_NAME),
  ];

  return buildMessage(
    METHOD_BINDING,
    CLASS_SUCCESS,
    request.header.transactionId,
    attrs
  );
}
