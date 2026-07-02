#!/bin/bash

# +-----------------------------------------------------------------------------------------------+
# | init-tidecloak.sh - Initialize TideCloak realm after deployment                               |
# | ===============================================================                               |
# | This script initializes a TideCloak instance with:                                            |
# |   1. Create a new realm from a JSON template                                                  |
# |   2. Initialize Tide + IGA                                                                    |
# |   3. Approve and commit change-sets                                                           |
# |   4. Create admin user with tide-realm-admin role                                             |
# |   5. Generate adapter config                                                                  |
# |   6. Upload branding (optional)                                                               |
# |   7. Generate invite link and wait for account linking                                        |
# |   8. Update CustomAdminUIDomain                                                               |
# |                                                                                               |
# | Reads configuration from the same .env file as setup-azure-env.sh.                           |
# | Usage:                                                                                        |
# |   ./init-tidecloak.sh [.env file]                                                            |
# |                                                                                               |
# +-----------------------------------------------------------------------------------------------+

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# =============================================
#  Load .env file
# =============================================

ENV_FILE="${1:-.env}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$ENV_FILE" ]; then
  log_error "Configuration file '$ENV_FILE' not found."
  echo "Use the same .env file as setup-azure-env.sh"
  exit 1
fi

log_info "Loading configuration from ${ENV_FILE}..."
source "$ENV_FILE"

# =============================================
#  Configuration
# =============================================

# TideCloak connection - auto-detect FQDN from Azure if not set
TC_APP_NAME="${TC_APP_NAME:-tidecloak}"
RESOURCE_GROUP="${RESOURCE_GROUP:-tidecloak-rg}"

if [ -n "${TIDECLOAK_URL:-}" ]; then
  # Use explicit URL if provided
  TIDECLOAK_URL="$TIDECLOAK_URL"
elif [ -n "${TC_HOSTNAME:-}" ]; then
  # Use custom hostname if configured
  TIDECLOAK_URL="https://${TC_HOSTNAME}"
else
  # Auto-detect from Azure container app
  log_info "Detecting TideCloak URL from Azure..."
  APP_FQDN=$(az containerapp show \
    -n "$TC_APP_NAME" -g "$RESOURCE_GROUP" \
    --query 'properties.configuration.ingress.fqdn' -o tsv 2>/dev/null || true)
  if [ -n "$APP_FQDN" ]; then
    TIDECLOAK_URL="https://${APP_FQDN}"
  else
    log_error "Could not detect TideCloak URL. Set TIDECLOAK_URL in .env"
    exit 1
  fi
fi

# Realm settings
REALM_NAME="${REALM_NAME:-myrealm}"
REALM_JSON_PATH="${REALM_JSON_PATH:-${SCRIPT_DIR}/realm.json}"
CLIENT_NAME="${CLIENT_NAME:-myclient}"
CLIENT_APP_URL="${CLIENT_APP_URL:-http://localhost:3000}"
ADAPTER_OUTPUT_PATH="${ADAPTER_OUTPUT_PATH:-${SCRIPT_DIR}/tidecloak.json}"

# Admin credentials (from setup-azure-env.sh .env)
KC_USER="${TC_ADMIN:-admin}"
KC_PASSWORD="${TC_ADMIN_PASSWORD:-password}"

# Internal
REALM_MGMT_CLIENT_ID="realm-management"
ADMIN_ROLE_NAME="tide-realm-admin"

# Curl options
CURL_OPTS=""
if [[ "$TIDECLOAK_URL" == https://* ]]; then
  CURL_OPTS="-k"
fi

# =============================================
#  Checks
# =============================================

echo ""
echo "=================================="
echo "  TideCloak Realm Initialization  "
echo "=================================="
echo ""

# Check dependencies
log_info "Checking dependencies..."
for cmd in curl jq; do
  if ! command -v $cmd &> /dev/null; then
    log_error "$cmd is not installed"
    exit 1
  fi
done
log_info "All dependencies installed"
echo ""

log_info "Configuration:"
log_info "  TideCloak URL:   $TIDECLOAK_URL"
log_info "  Realm Name:      $REALM_NAME"
log_info "  Client Name:     $CLIENT_NAME"
log_info "  Client App URL:  $CLIENT_APP_URL"
log_info "  Realm Template:  $REALM_JSON_PATH"
log_info "  Adapter Output:  $ADAPTER_OUTPUT_PATH"
echo ""

# Check realm.json exists
if [ ! -f "$REALM_JSON_PATH" ]; then
  log_error "Realm template not found at: $REALM_JSON_PATH"
  exit 1
fi

# Wait for TideCloak to be ready
log_info "Checking TideCloak connectivity..."
for i in $(seq 1 30); do
  if curl -s $CURL_OPTS --connect-timeout 5 "$TIDECLOAK_URL" > /dev/null 2>&1; then
    log_info "TideCloak is accessible"
    break
  fi
  if [ $i -eq 30 ]; then
    log_error "Cannot connect to TideCloak at $TIDECLOAK_URL after 30 attempts"
    exit 1
  fi
  log_warn "Waiting for TideCloak (attempt $i/30)..."
  sleep 10
done
echo ""

# =============================================
#  Helper functions
# =============================================

get_admin_token() {
  curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${KC_USER}" \
    -d "password=${KC_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | jq -r '.access_token'
}

# Diagnostic: exercise the token endpoint and report the URL + HTTP status +
# whether an access_token came back, WITHOUT printing the token or any secret.
# Reports which realm/user/client/grant we authenticate as. Returns non-zero if
# no token is obtained so callers can hard-fail early.
diag_admin_token() {
  local token_url="${TIDECLOAK_URL}/realms/master/protocol/openid-connect/token"
  log_info "[diag] token endpoint: POST ${token_url} (realm=master user=${KC_USER} client=admin-cli grant=password)"
  local resp status body
  resp=$(curl -s $CURL_OPTS -w "\n%{http_code}" -X POST "$token_url" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${KC_USER}" \
    -d "password=${KC_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" 2>&1)
  status=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | sed '$d')
  local have_token="no"
  if echo "$body" | jq -e '.access_token | type == "string" and length > 0' > /dev/null 2>&1; then
    have_token="yes"
  fi
  log_info "[diag] token endpoint -> HTTP ${status}, access_token returned: ${have_token}"
  if [ "$have_token" != "yes" ]; then
    # Print only the error/error_description fields (never the token), if present.
    log_error "[diag] token request did NOT return an access_token. error: $(echo "$body" | jq -r '{error, error_description} | select(.error != null)' 2>/dev/null | tr -d '\n' | head -c 300)"
    return 1
  fi
  return 0
}

# Sign ALL pending change-requests, regardless of entity type. The new iga-core
# model has no per-CLIENT change-set step; you simply authorize+commit every
# pending change request after realm/IGA init.
#
# This mirrors the ecosystem-canonical drain used by the iga-engine tests
# (tidecloak-iga-engine-tests/lib/iga.ts `drainPending`): list PENDING, then for
# each CR POST .../{id}/authorize {} followed by POST .../{id}/commit {}; loop up
# to a max number of passes, re-listing each pass (committing some CRs can
# generate/unblock others), and stop early when the pass makes no forward
# progress so it can never hang.
sign_all_change_requests() {
  local max_passes=8
  local pass=0
  while [ "$pass" -lt "$max_passes" ]; do
    pass=$((pass + 1))
    TOKEN="$(get_admin_token)"
    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
      log_error "Failed to get admin token for signing change-requests"
      return 1
    fi

    # Flat list of ALL pending change requests (every entity type).
    local pending id_count
    pending=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests?status=PENDING" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "[]")
    if ! echo "$pending" | jq -e 'type == "array"' > /dev/null 2>&1; then
      log_error "Unexpected response from change-request API: $pending"
      return 1
    fi

    id_count=$(echo "$pending" | jq 'length' 2>/dev/null || echo "0")
    if [ "$id_count" = "0" ] || [ "$id_count" = "" ]; then
      log_info "No pending change-requests remain."
      return 0
    fi

    log_info "Signing $id_count pending change-request(s) (pass $pass)..."
    local progressed=0
    # Iterate full CR objects (one compact JSON per line); subshell-free via
    # process substitution so `progressed` survives the loop.
    while read -r cr; do
      [ -z "$cr" ] && continue

      # Robust id extraction: the id field name has varied across iga-core
      # versions. Per the iga-core source it is `.id`, but fall back to the
      # legacy names so a version skew can't silently build an empty-id URL
      # (which routes to "Realm not found").
      local cr_id
      cr_id=$(echo "$cr" | jq -r '.id // .draftRecordId // .changeSetRequestId // .changeRequestId // empty')
      if [ -z "$cr_id" ] || [ "$cr_id" = "null" ]; then
        log_error "Could not resolve change-request id from rep (no id/draftRecordId/changeSetRequestId/changeRequestId). Raw CR:"
        echo "$cr" | jq . 2>/dev/null || echo "$cr"
        return 1
      fi

      local auth_url commit_url
      auth_url="${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests/${cr_id}/authorize"
      commit_url="${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests/${cr_id}/commit"
      log_info "[diag] CR id=${cr_id} entityType=$(echo "$cr" | jq -r '.entityType // "?"') actionType=$(echo "$cr" | jq -r '.actionType // "?"')"

      # authorize (empty body). Capture status + body for diagnostics.
      local auth_resp auth_status auth_body
      auth_resp=$(curl -s $CURL_OPTS -w "\n%{http_code}" -X POST "$auth_url" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{}" 2>&1)
      auth_status=$(echo "$auth_resp" | tail -1)
      auth_body=$(echo "$auth_resp" | sed '$d')
      log_info "[diag] POST ${auth_url} -> HTTP ${auth_status} :: $(echo "$auth_body" | head -c 300)"

      # commit (empty body). Capture status + body for diagnostics.
      local commit_resp commit_status commit_body
      commit_resp=$(curl -s $CURL_OPTS -w "\n%{http_code}" -X POST "$commit_url" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{}" 2>&1)
      commit_status=$(echo "$commit_resp" | tail -1)
      commit_body=$(echo "$commit_resp" | sed '$d')
      log_info "[diag] POST ${commit_url} -> HTTP ${commit_status} :: $(echo "$commit_body" | head -c 300)"

      if [[ "$commit_status" =~ ^2 ]]; then
        progressed=$((progressed + 1))
      else
        log_warn "CR ${cr_id} not committed (HTTP $commit_status); will retry next pass"
      fi
    done < <(echo "$pending" | jq -c '.[]')

    # No forward progress this pass -> stop rather than spin (a CR that stays
    # PENDING needs a role/quorum this bootstrap admin cannot satisfy).
    if [ "$progressed" -eq 0 ]; then
      log_warn "No change-requests committed this pass; stopping ($id_count still pending)."
      return 0
    fi

    sleep 2
  done

  log_warn "Reached max sign-all passes ($max_passes); some change-requests may remain pending."
  return 0
}

# =============================================
#  1. Create Realm
# =============================================

log_info "Creating realm '${REALM_NAME}'..."

# Diagnostic: verify we can actually get an admin token before doing anything.
if ! diag_admin_token; then
  log_error "Cannot obtain an admin token from staging master; aborting before realm create."
  exit 1
fi

TMP_REALM_JSON="$(mktemp)"

# Field-targeted realm-name substitution via jq (the old `sed s|KEYLESSH|...`
# matched nothing: realm.json uses lowercase "keylessh", and a blanket
# s|keylessh|...| would clobber the app identity — punchd.keylessh.com redirect
# URIs/webOrigins, client ids, role names). We rewrite ONLY the realm-NAME-
# dependent fields to $REALM_NAME and leave every app-identity keylessh
# reference untouched:
#   .realm                              -> $rn
#   .defaultRole.name (default-roles-*) -> default-roles-$rn
#   .roles.realm[] name default-roles-* -> default-roles-$rn  (must match
#                                          .defaultRole.name or KC import fails)
# If realm.json ever grows realm-name-embedded URLs (e.g. ".../realms/keylessh"
# issuers/broker URLs), extend the jq below to rewrite "/realms/keylessh" ->
# "/realms/$rn" in those specific fields only.
#
# Also fix the app-auth client ($CLIENT_NAME, default "myclient") so the browser
# token exchange is not CORS-blocked: the /token endpoint sets its
# Access-Control-Allow-Origin from the client's webOrigins. We set webOrigins to
# ["+"] (Keycloak special value = allow CORS from every registered redirect-URI
# origin), and ensure $CLIENT_APP_URL (the app origin, e.g. http://localhost:3000)
# is present in redirectUris. "+" is robust: it always tracks redirectUris, so a
# different app host only needs the redirectUri added. We do NOT touch the other
# clients (e.g. myclient-stun / punchd.keylessh.com app identity).
jq --arg rn "$REALM_NAME" --arg cn "$CLIENT_NAME" --arg appurl "$CLIENT_APP_URL" '
  .realm = $rn
  | (if (.defaultRole.name // "") == "default-roles-keylessh"
       then .defaultRole.name = ("default-roles-" + $rn) else . end)
  | (if has("roles") and (.roles | has("realm"))
       then .roles.realm |= map(if .name == "default-roles-keylessh"
                                  then .name = ("default-roles-" + $rn) else . end)
       else . end)
  | (if has("clients")
       then .clients |= map(
              if .clientId == $cn then
                .webOrigins = ["+"]
                | .redirectUris = (((.redirectUris // []) + [$appurl, ($appurl + "/*")]) | unique)
              else . end)
       else . end)
' "$REALM_JSON_PATH" > "$TMP_REALM_JSON"

# Diagnostic: the realm name the create body will actually use vs REALM_NAME.
BODY_REALM="$(jq -r '.realm // "(none)"' "$TMP_REALM_JSON" 2>/dev/null || echo '(unparseable)')"
log_info "[diag] REALM_NAME='${REALM_NAME}' ; realm.json body .realm='${BODY_REALM}'"
if [ "$BODY_REALM" != "$REALM_NAME" ]; then
  log_warn "[diag] MISMATCH: create body will create realm '${BODY_REALM}', NOT '${REALM_NAME}'. All later /admin/realms/${REALM_NAME}/* calls will 404 with 'Realm not found'."
fi

TOKEN="$(get_admin_token)"
CREATE_URL="${TIDECLOAK_URL}/admin/realms"
create_resp=$(curl -s $CURL_OPTS -w "\n%{http_code}" \
  -X POST "$CREATE_URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @"$TMP_REALM_JSON" 2>&1)
status=$(echo "$create_resp" | tail -1)
create_body=$(echo "$create_resp" | sed '$d')
log_info "[diag] POST ${CREATE_URL} (body .realm=${BODY_REALM}) -> HTTP ${status} :: $(echo "$create_body" | head -c 400)"

if [[ $status == 2* ]]; then
  log_info "Realm '${REALM_NAME}' created."
elif [[ $status == 409 ]]; then
  log_warn "Realm '${REALM_NAME}' already exists. Continuing..."
else
  log_error "Realm creation failed (HTTP $status): $(echo "$create_body" | head -c 400)"
  rm -f "$TMP_REALM_JSON"
  exit 1
fi

# VERIFY-EXISTS hard-fail: confirm the target REALM_NAME actually exists before
# proceeding into tide-init / change-request steps. A 2xx or 409 above does NOT
# prove REALM_NAME exists (e.g. if the create body created a differently-named
# realm). Hard-fail with a clear message instead of running everything against a
# non-existent realm and getting a cascade of "Realm not found".
TOKEN="$(get_admin_token)"
VERIFY_URL="${TIDECLOAK_URL}/admin/realms/${REALM_NAME}"
verify_status=$(curl -s $CURL_OPTS -o /dev/null -w "%{http_code}" -X GET "$VERIFY_URL" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "000")
log_info "[diag] verify realm exists: GET ${VERIFY_URL} -> HTTP ${verify_status}"
if [[ ! "$verify_status" =~ ^2 ]]; then
  log_error "Realm '${REALM_NAME}' does NOT exist after the create step (GET ${VERIFY_URL} -> HTTP ${verify_status})."
  log_error "The create call above reported HTTP ${status} but realm '${REALM_NAME}' is not present."
  if [ "$BODY_REALM" != "$REALM_NAME" ]; then
    log_error "Root cause: the create body's .realm ('${BODY_REALM}') does not match REALM_NAME ('${REALM_NAME}'). Fix realm.json / the name-substitution so the created realm is named '${REALM_NAME}'."
  fi
  rm -f "$TMP_REALM_JSON"
  exit 1
fi

# =============================================
#  2. Initialize Tide + IGA
# =============================================

log_info "Initializing Tide realm + IGA..."

# Prompt for email
echo ""
while true; do
  echo -ne "${YELLOW}Enter an email to manage your license: ${NC}"
  read LICENSE_EMAIL
  if [[ -n "$LICENSE_EMAIL" && "$LICENSE_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    break
  else
    log_error "Please enter a valid email address"
  fi
done

# Prompt for terms acceptance
echo ""
echo "Please review the Terms & Conditions at: https://tide.org/legal"
while true; do
  echo -ne "${YELLOW}I agree to the Terms & Conditions (enter 'y' or 'yes' to continue): ${NC}"
  read TERMS_ACCEPTANCE
  if [[ "$TERMS_ACCEPTANCE" == "y" || "$TERMS_ACCEPTANCE" == "yes" ]]; then
    break
  else
    log_error "You must explicitly agree to the Terms & Conditions by entering 'y' or 'yes'"
  fi
done

echo ""
TOKEN="$(get_admin_token)"
curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/vendorResources/setUpTideRealm" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "email=${LICENSE_EMAIL}" \
  --data-urlencode "isRagnarokEnabled=true" > /dev/null 2>&1

curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tide-admin/toggle-iga" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "isIGAEnabled=true" > /dev/null 2>&1

log_info "Tide realm + IGA initialized."

# =============================================
#  3. Sign all pending change-requests
# =============================================

# On a fresh firstAdmin realm, setUpTideRealm + toggle-iga AUTO-COMMIT their
# baseline/ADOPT change-requests (the firstAdmin auto-commit sweep), so there are
# typically ZERO PENDING CRs at this point (verified live on staging: init CRs
# land as APPROVED, none PENDING). Do NOT block waiting for them. We poll briefly
# (bounded, short) only to opportunistically catch any that are momentarily
# PENDING, then ALWAYS proceed; sign_all_change_requests() no-ops cleanly if the
# pending list is empty. This replaces the old 60s "wait for CRs" that hung the
# run when (as expected) nothing was pending.
log_info "Checking for any pending change-requests (init CRs usually auto-commit on firstAdmin)..."
WAIT_POLLS=6      # bounded: 6 polls
WAIT_SLEEP=2      # 2s apart -> max ~12s, then proceed regardless
cs_count=0
for i in $(seq 1 $WAIT_POLLS); do
  TOKEN="$(get_admin_token)"
  cs_count=$(curl -s $CURL_OPTS "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests?status=PENDING" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
  log_info "[diag] pending-CR poll ${i}/${WAIT_POLLS}: status=PENDING count=${cs_count}"
  if [ "$cs_count" -gt 0 ] 2>/dev/null; then
    log_info "Found $cs_count pending change-request(s); proceeding to sign."
    break
  fi
  [ "$i" -lt "$WAIT_POLLS" ] && sleep "$WAIT_SLEEP"
done
if [ "$cs_count" = "0" ] || [ -z "$cs_count" ]; then
  log_info "No pending change-requests at init (auto-committed on firstAdmin); proceeding."
fi

sign_all_change_requests

# =============================================
#  4. Create admin user
# =============================================

TOKEN="$(get_admin_token)"
log_info "Creating admin user..."

# NOTE (async IGA model): POST /users returns 202 and captures a CREATE_USER
# change-request; the user does NOT exist until that CR is committed. The user is
# created with tideInvitable=true so the invite link (step 7) can be generated
# (that attribute is required, and it too is captured as a SET_USER_ATTRIBUTE CR
# that must be committed). We therefore create the user, then sign_all to commit
# the CREATE_USER (+ tideInvitable) CRs, then verify the user actually exists.
# The tide-realm-admin role is NOT assigned here: it can only be granted AFTER
# the user is linked to the Tide IdP (verified live: assigning it to an unlinked
# user returns 400 "target user is not linked to the Tide identity provider").
# The role grant therefore happens after the wait-for-link step below.
curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@yourorg.com","firstName":"admin","lastName":"user","enabled":true,"emailVerified":false,"requiredActions":[],"attributes":{"locale":"","tideInvitable":["true"]},"groups":[]}' > /dev/null 2>&1

# Commit the CREATE_USER (+ tideInvitable SET_USER_ATTRIBUTE) change-requests so
# the user genuinely exists before anything depends on it.
log_info "Committing admin-user change-request(s)..."
sign_all_change_requests

# Verify the user now exists with a real id (short retry in case commit + read
# are eventually-consistent). Hard-fail with a clear message if it never lands.
USER_ID=""
for i in $(seq 1 6); do
  TOKEN="$(get_admin_token)"
  USER_ID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users?username=admin" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id // empty')
  [ -n "$USER_ID" ] && break
  log_info "[diag] admin user not visible yet (attempt ${i}/6); retrying..."
  sleep 2
done
if [ -z "$USER_ID" ]; then
  log_error "Admin user was not created (no id after committing CREATE_USER CR). Aborting."
  exit 1
fi
log_info "Admin user created (id=${USER_ID}). tide-realm-admin will be granted after Tide linking."

# =============================================
#  5. Fetch adapter config
# =============================================

TOKEN="$(get_admin_token)"
log_info "Fetching adapter config..."

CLIENT_UUID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/clients?clientId=${CLIENT_NAME}" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/vendorResources/get-installations-provider?clientId=${CLIENT_UUID}&providerId=keycloak-oidc-keycloak-json" \
  -H "Authorization: Bearer $TOKEN" > "$ADAPTER_OUTPUT_PATH"

log_info "Adapter config saved to $ADAPTER_OUTPUT_PATH"

# Validate the fetched adapter before installing it, then copy it to the location
# the app ACTUALLY reads at runtime: <repo>/data/tidecloak.json. The server serves
# this file to the browser via GET /api/auth/config (server/lib/auth/tidecloakConfig.ts
# -> process.cwd()/data/tidecloak.json), and the OIDC login redirect is built from
# its auth-server-url/realm/resource. Without this copy the app keeps using a STALE
# data/tidecloak.json (wrong host/realm) and never picks up the freshly-generated one.
if ! jq -e '.realm and ."auth-server-url" and .resource' "$ADAPTER_OUTPUT_PATH" > /dev/null 2>&1; then
  log_error "Fetched adapter at ${ADAPTER_OUTPUT_PATH} is not valid or missing realm/auth-server-url/resource:"
  head -c 400 "$ADAPTER_OUTPUT_PATH" 2>/dev/null; echo ""
  log_error "Not installing a bad adapter into data/. The app would fail to log in."
  rm -f "$TMP_REALM_JSON"
  exit 1
fi

# <repo>/data is two levels up from this script dir (script/tidecloak/..).
DATA_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)/data"
mkdir -p "$DATA_DIR"
APP_ADAPTER_PATH="${DATA_DIR}/tidecloak.json"
cp "$ADAPTER_OUTPUT_PATH" "$APP_ADAPTER_PATH"
log_info "Installed adapter to app read path: ${APP_ADAPTER_PATH} (realm=$(jq -r '.realm' "$APP_ADAPTER_PATH"), auth-server-url=$(jq -r '."auth-server-url"' "$APP_ADAPTER_PATH"), resource=$(jq -r '.resource' "$APP_ADAPTER_PATH"))"

rm -f "$TMP_REALM_JSON"

# =============================================
#  6. Upload branding (optional)
# =============================================

BRANDING_DIR="${BRANDING_DIR:-${SCRIPT_DIR}/branding}"

if [ -d "$BRANDING_DIR" ]; then
  log_info "Uploading branding images from ${BRANDING_DIR}..."
  TOKEN="$(get_admin_token)"

  # Upload logo
  LOGO_FILE=$(find "$BRANDING_DIR" -name "*logo*" -type f 2>/dev/null | head -1)
  if [ -n "$LOGO_FILE" ]; then
    logo_status=$(curl -s -k -o /dev/null -w "%{http_code}" \
      -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tide-idp-admin-resources/images/upload" \
      -H "Authorization: Bearer ${TOKEN}" \
      -F "fileData=@${LOGO_FILE}" \
      -F "fileName=$(basename "$LOGO_FILE")" \
      -F "fileType=LOGO" 2>/dev/null || echo "000")
    if [[ "$logo_status" =~ ^2 ]]; then
      log_info "Logo uploaded: $(basename "$LOGO_FILE")"
    else
      log_warn "Logo upload failed (HTTP $logo_status)"
    fi
  fi

  # Upload background
  BG_FILE=$(find "$BRANDING_DIR" -name "*bg*" -o -name "*background*" -type f 2>/dev/null | head -1)
  if [ -n "$BG_FILE" ]; then
    bg_status=$(curl -s -k -o /dev/null -w "%{http_code}" \
      -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tide-idp-admin-resources/images/upload" \
      -H "Authorization: Bearer ${TOKEN}" \
      -F "fileData=@${BG_FILE}" \
      -F "fileName=$(basename "$BG_FILE")" \
      -F "fileType=BACKGROUND_IMAGE" 2>/dev/null || echo "000")
    if [[ "$bg_status" =~ ^2 ]]; then
      log_info "Background uploaded: $(basename "$BG_FILE")"
    else
      log_warn "Background upload failed (HTTP $bg_status)"
    fi
  fi

  log_info "Branding upload complete."
else
  log_warn "No branding directory found at ${BRANDING_DIR}. Skipping."
fi

# =============================================
#  7. Generate invite link and wait for linking
# =============================================

TOKEN="$(get_admin_token)"
log_info "Generating invite link..."

RAW_INVITE_LINK=$(curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tideAdminResources/get-required-action-link?userId=${USER_ID}&lifespan=43200" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '["link-tide-account-action"]')

# Fail clearly if link generation errored (e.g. user not yet committed, or the
# tideInvitable attribute is not set/committed) instead of printing a bogus link
# and then hanging forever in the "waiting for link" loop below.
if [ -z "$RAW_INVITE_LINK" ] || echo "$RAW_INVITE_LINK" | jq -e '.error? // .errorMessage? // empty' > /dev/null 2>&1; then
  log_error "Invite-link generation failed: $(echo "$RAW_INVITE_LINK" | head -c 300)"
  log_error "The admin user must exist AND have tideInvitable=true committed before an invite link can be generated."
  exit 1
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  INVITE LINK (open in browser):${NC}"
echo ""
echo "  $RAW_INVITE_LINK"
echo ""
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Open this link in your browser to link the admin account."
echo -ne "Waiting for account to be linked"

while true; do
  TOKEN="$(get_admin_token)"
  ATTRS=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users?username=admin" \
    -H "Authorization: Bearer $TOKEN")
  KEY=$(echo "$ATTRS" | jq -r '.[0].attributes.tideUserKey[0] // empty')
  VUID=$(echo "$ATTRS" | jq -r '.[0].attributes.vuid[0] // empty')
  if [[ -n "$KEY" && -n "$VUID" ]]; then
    echo ""
    log_info "Account linked!"
    break
  fi
  echo -n "."
  sleep 5
done

# =============================================
#  8. Grant tide-realm-admin (now that the user is Tide-linked) + sign
# =============================================

# tide-realm-admin can ONLY be assigned to a user already linked to the Tide IdP
# (assigning it to an unlinked user returns 400). We are past the wait-for-link
# loop above, so the admin user is linked and the grant will be accepted. The
# grant may itself be captured as a change-request (e.g. GRANT_ROLES) in the
# async IGA model, so we sign_all afterwards to commit it and make the role land.
TOKEN="$(get_admin_token)"
log_info "Granting ${ADMIN_ROLE_NAME} to the linked admin user..."

CLIENT_UUID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/clients?clientId=${REALM_MGMT_CLIENT_ID}" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

ROLE_JSON=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/clients/$CLIENT_UUID/roles/${ADMIN_ROLE_NAME}" \
  -H "Authorization: Bearer $TOKEN")

grant_status=$(curl -s $CURL_OPTS -o /dev/null -w "%{http_code}" -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users/$USER_ID/role-mappings/clients/$CLIENT_UUID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$ROLE_JSON]")
log_info "[diag] role-mapping POST -> HTTP ${grant_status}"
if [[ ! "$grant_status" =~ ^2 ]]; then
  log_error "Failed to grant ${ADMIN_ROLE_NAME} (HTTP ${grant_status}). The user may not be Tide-linked."
  exit 1
fi

# Commit any change-request the grant produced (async GRANT_ROLES), plus any
# other still-pending CRs, so the role actually lands.
sign_all_change_requests

# Verify the role is actually present on the user (role-mappings realm/client).
TOKEN="$(get_admin_token)"
HAS_ROLE=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users/$USER_ID/role-mappings/clients/$CLIENT_UUID" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null | jq -r --arg r "${ADMIN_ROLE_NAME}" 'if type=="array" and (map(.name) | index($r)) then "yes" else "no" end' 2>/dev/null || echo "no")
if [ "$HAS_ROLE" = "yes" ]; then
  log_info "Admin user now has the ${ADMIN_ROLE_NAME} role."
else
  log_warn "Could not confirm ${ADMIN_ROLE_NAME} on the admin user after signing (it may commit shortly)."
fi

# =============================================
#  9. Update CustomAdminUIDomain
# =============================================

TOKEN="$(get_admin_token)"
log_info "Updating CustomAdminUIDomain to ${CLIENT_APP_URL}..."

INST=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/identity-provider/instances/tide" \
  -H "Authorization: Bearer $TOKEN")

UPDATED=$(echo "$INST" | jq --arg d "$CLIENT_APP_URL" '.config.CustomAdminUIDomain=$d')

curl -s $CURL_OPTS -X PUT "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/identity-provider/instances/tide" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPDATED" > /dev/null 2>&1

curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/vendorResources/sign-idp-settings" \
  -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1

log_info "CustomAdminUIDomain updated and signed."

# =============================================
#  Final drain: commit any remaining pending change-requests
# =============================================

# Defensive catch-all: after ALL setup steps, drain any still-pending CRs so the
# bootstrap always leaves ZERO pending. Today the earlier per-step sign_all calls
# (post user-create + role-grant) plus firstAdmin auto-commit already cover every
# CR the flow produces, and the trailing IdP/adapter steps create none — so this
# is normally a no-op. It exists so a future step that starts producing a CR can
# never silently leave one un-committed. Reuses sign_all_change_requests() (list
# PENDING -> authorize+commit each, loops until empty, no-op on empty).
log_info "Final drain: committing any remaining pending change-requests..."
sign_all_change_requests

# =============================================
#  Summary
# =============================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  TideCloak Initialization Complete!    ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "TideCloak URL:     ${GREEN}${TIDECLOAK_URL}${NC}"
echo -e "Realm:             ${GREEN}${REALM_NAME}${NC}"
echo -e "Admin Console:     ${GREEN}${TIDECLOAK_URL}/admin/${REALM_NAME}/console${NC}"
echo -e "Adapter Config:    ${GREEN}${ADAPTER_OUTPUT_PATH}${NC}"
echo ""