/**
 * Generate a self-signed TLS certificate for the WAF HTTPS server.
 * The cert is created in-memory on startup — no files written to disk.
 */

import { generate } from "selfsigned";

export interface TlsCert {
  key: string;
  cert: string;
}

export async function generateSelfSignedCert(hostname = "localhost"): Promise<TlsCert> {
  const now = new Date();
  const expiry = new Date(now);
  expiry.setFullYear(expiry.getFullYear() + 1);

  const attrs = [{ name: "commonName", value: hostname }];
  const pems = await generate(attrs, {
    keySize: 2048,
    algorithm: "sha256",
    notBeforeDate: now,
    notAfterDate: expiry,
    extensions: [
      { name: "subjectAltName", altNames: [
        { type: 2, value: hostname },
        { type: 2, value: "localhost" },
        { type: 7, ip: "127.0.0.1" },
      ]},
    ],
  });

  console.log(`[TLS] Generated self-signed certificate for ${hostname}`);
  return { key: pems.private, cert: pems.cert };
}
