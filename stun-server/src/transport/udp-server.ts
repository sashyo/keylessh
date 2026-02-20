/**
 * UDP transport for STUN/TURN.
 *
 * Listens on a UDP socket, dispatches incoming packets to
 * STUN message handler or ChannelData handler based on the first byte.
 */

import { createSocket, Socket, RemoteInfo } from "dgram";
import { isStunMessage, isChannelData } from "./dispatcher.js";

export interface UdpServerOptions {
  port: number;
  /** Bind address — use "fly-global-services" on Fly.io for UDP */
  bindAddress?: string;
  onStunMessage: (buf: Buffer, rinfo: RemoteInfo) => void;
  onChannelData: (buf: Buffer, rinfo: RemoteInfo) => void;
}

export interface UdpServer {
  socket: Socket;
  send: (buf: Buffer, port: number, address: string) => void;
  close: () => void;
}

export function createUdpServer(options: UdpServerOptions): UdpServer {
  const socket = createSocket("udp4");

  socket.on("message", (buf: Buffer, rinfo: RemoteInfo) => {
    if (isStunMessage(buf)) {
      options.onStunMessage(buf, rinfo);
    } else if (isChannelData(buf)) {
      options.onChannelData(buf, rinfo);
    }
    // Ignore unrecognized packets
  });

  socket.on("error", (err) => {
    console.error("[UDP] Socket error:", err.message);
  });

  const bindAddr = options.bindAddress || "0.0.0.0";
  socket.bind(options.port, bindAddr, () => {
    const addr = socket.address();
    console.log(`[UDP] Listening on ${addr.address}:${addr.port}`);
  });

  return {
    socket,
    send(buf: Buffer, port: number, address: string) {
      socket.send(buf, 0, buf.length, port, address);
    },
    close() {
      socket.close();
    },
  };
}
