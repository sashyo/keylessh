// Entry point for browser bundle — exposes TideCloak as window.Keycloak
// (Keycloak-compatible API so existing code works unchanged)
import { TideCloak } from "@tidecloak/js";
window.Keycloak = TideCloak;
