/**
 * HTTP health check endpoint.
 */

import { createServer, Server } from "http";

export function createHealthServer(
  port: number,
  getStats: () => Record<string, unknown>
): Server {
  const server = createServer((req, res) => {
    if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", ...getStats() }));
      return;
    }
    res.writeHead(404);
    res.end("Not found");
  });

  server.listen(port, () => {
    console.log(`[Health] http://localhost:${port}/health`);
  });

  return server;
}
