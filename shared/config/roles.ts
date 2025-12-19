export enum Roles {
  Admin = "tide-realm-admin",
  User = "appUser",
}

// Roles that should be treated as "admin" across the app.
export const ADMIN_ROLE_NAMES = [Roles.Admin, "realm-admin"] as const;
export const ADMIN_ROLE_SET: ReadonlySet<string> = new Set(ADMIN_ROLE_NAMES);
