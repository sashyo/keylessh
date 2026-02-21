// Entry point for browser bundle — exposes Keycloak as window.Keycloak
// Standard keycloak-js adapter works with TideCloak (Keycloak-compatible)
import Keycloak from "keycloak-js";
window.Keycloak = Keycloak;
