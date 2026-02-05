// Multi-tenancy configuration

/** When true, org is extracted from JWT. When false, all data belongs to DEFAULT_ORG_ID. */
export const ENABLE_MULTI_TENANT =
  process.env.ENABLE_MULTI_TENANT === "true" || process.env.ENABLE_MULTI_TENANT === "1";

/** Fallback organization used in single-tenant mode and for migrating existing data. */
export const DEFAULT_ORG_ID = "default";
export const DEFAULT_ORG_NAME = "Default";
export const DEFAULT_ORG_SLUG = "default";
