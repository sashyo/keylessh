/**
 * TCP transport for STUN/TURN.
 *
 * STUN over TCP uses the message's own length fields for framing:
 *   - STUN messages: first 4 bytes give type (2) + length (2), total = 20 + length
 *   - ChannelData: first 4 bytes give channel (2) + length (2), total = 4 + length (padded to 4)
 */

import { createServer, Server, Socket } from "net";
import { HEADER_LENGTH } from "../stun/constants.js";
import { isStunMessage, isChannelData } from "./dispatcher.js";

export interface TcpConnection {
  remoteAddress: string;
  remotePort: number;
  send(buf: Buffer): void;
  close(): void;
}

export interface TcpServerOptions {
  port: number;
  onStunMessage: (buf: Buffer, conn: TcpConnection) => void;
  onChannelData: (buf: Buffer, conn: TcpConnection) => void;
  onClose?: (conn: TcpConnection) => void;
}

export interface TcpServerHandle {
  server: Server;
  close: () => void;
}

export function createTcpServer(options: TcpServerOptions): TcpServerHandle {
  const server = createServer((socket: Socket) => {
    const conn: TcpConnection = {
      remoteAddress: socket.remoteAddress || "unknown",
      remotePort: socket.remotePort || 0,
      send(buf: Buffer) {
        if (!socket.destroyed) {
          socket.write(buf);
        }
      },
      close() {
        if (!socket.destroyed) {
          socket.destroy();
        }
      },
    };

    let buffer = Buffer.alloc(0);

    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      processBuffer();
    });

    function processBuffer() {
      while (buffer.length >= 4) {
        let frameLen: number;

        if (isStunMessage(buffer)) {
          // STUN message: need at least 20 bytes for header
          if (buffer.length < HEADER_LENGTH) return;
          const msgLen = buffer.readUInt16BE(2);
          frameLen = HEADER_LENGTH + msgLen;
        } else if (isChannelData(buffer)) {
          // ChannelData: 4-byte header + data (padded to 4 bytes over TCP)
          const dataLen = buffer.readUInt16BE(2);
          const padLen = (4 - (dataLen % 4)) % 4;
          frameLen = 4 + dataLen + padLen;
        } else {
          // Unrecognized — discard 1 byte and retry
          buffer = buffer.subarray(1);
          continue;
        }

        if (buffer.length < frameLen) return; // wait for more data

        const frame = buffer.subarray(0, frameLen);
        buffer = buffer.subarray(frameLen);

        if (isStunMessage(frame)) {
          options.onStunMessage(frame, conn);
        } else if (isChannelData(frame)) {
          options.onChannelData(frame, conn);
        }
      }
    }

    socket.on("close", () => {
      options.onClose?.(conn);
    });

    socket.on("error", (err) => {
      console.error(
        `[TCP] Connection error from ${conn.remoteAddress}:${conn.remotePort}:`,
        err.message
      );
    });
  });

  server.listen(options.port, () => {
    console.log(`[TCP] Listening on port ${options.port}`);
  });

  server.on("error", (err) => {
    console.error("[TCP] Server error:", err.message);
  });

  return {
    server,
    close() {
      server.close();
    },
  };
}
