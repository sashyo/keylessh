import fs from "fs";
import path from "path";

let tcData: TidecloakConfig | undefined;

interface JSONWebKeySet {
  keys: JWK[];
}

interface JWK {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  crv: string;
  x: string;
}

export interface TidecloakConfig {
  realm: string;
  "auth-server-url": string;
  "ssl-required": string;
  resource: string;
  "public-client": boolean;
  "confidential-port": number;
  jwk: {
    keys: JWK[];
  };
  vendorId: string;
  homeOrkUrl: string;
  [key: string]: any;
}

const filePath = path.join(process.cwd(), "data", "tidecloak.json");

export function GetConfig(): TidecloakConfig {
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

export function initTcData(): TidecloakConfig {
  if (tcData === undefined) {
    console.info("[initTcData] Initializing TideCloak config...");
    tcData = GetConfig();
    console.info("[initTcData] TideCloak config was set.");
  }
  return tcData;
}

const typedTcData = (): TidecloakConfig => {
  if (!tcData) {
    initTcData();
  }
  return tcData as TidecloakConfig;
};

export const tidecloakConfig = () => {
  const requiredKeys: (keyof TidecloakConfig)[] = [
    "auth-server-url",
    "realm",
    "resource",
  ];

  for (const key of requiredKeys) {
    if (!typedTcData()[key]) {
      console.error("Config error: missing key", key);
      throw new Error(`Missing required config value: ${key}`);
    }
  }

  return typedTcData;
};

export function getAuthServerUrl(): string {
  return typedTcData()["auth-server-url"] || "";
}

export function getAuthOverrideUrl(): string {
  const envUrl = process.env.AUTH_SERVER_OVERRIDE_URL;

  if (envUrl && envUrl.trim().length > 0) {
    try {
      new URL(envUrl);
      return envUrl.replace(/\/+$/, "");
    } catch {
      console.warn(
        "[TidecloakConfig] Invalid AUTH_SERVER_OVERRIDE_URL in environment. Falling back to config file."
      );
    }
  }
  return (typedTcData()["auth-server-url"] || "").replace(/\/+$/, "");
}

export function getRealm(): string {
  return typedTcData()["realm"] || "";
}

export function getVendorId(): string {
  return typedTcData()["vendorId"] || "";
}

export function getResource(): string {
  return typedTcData()["resource"] || "";
}

export function getHomeOrkUrl(): string {
  return typedTcData()["homeOrkUrl"] || "";
}

export function getJWK(): JSONWebKeySet | null {
  if (
    !typedTcData().jwk ||
    !typedTcData().jwk.keys ||
    typedTcData().jwk.keys.length === 0
  ) {
    console.error(
      "[TideJWT] No keys were found in tidecloak.json. Did you forget to download the client adaptor from TideCloak?"
    );
    return null;
  }
  return typedTcData().jwk;
}

export function getPublicKey(): string {
  const jwkSet = getJWK();

  if (!jwkSet || !jwkSet.keys || jwkSet.keys.length === 0) {
    throw new Error(
      "[Tidecloak JWK] No JWK keys found in tidecloak.json. Make sure you downloaded the correct client adapter."
    );
  }

  const jwk = jwkSet.keys[0];
  if (!jwk.x) {
    throw new Error("[Tidecloak JWK] JWK 'x' value is missing. Check tidecloak.json.");
  }

  return jwk.x;
}
