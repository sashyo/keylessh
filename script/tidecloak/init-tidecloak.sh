#!/usr/bin/env sh

# Tidecloak Realm Initialization Script (Codespaces Compatible)
# This script sets up a new Tidecloak realm with Tide configuration



RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "=================================="
echo "  Tidecloak Realm Initialization  "
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
log_info "✓ All dependencies installed"
echo ""

# Configuration
TIDECLOAK_LOCAL_URL="${TIDECLOAK_LOCAL_URL:-http://tidecloakP:8080}"
CLIENT_APP_URL="${CLIENT_APP_URL:-http://localhost:3000}"
REALM_JSON_PATH="${REALM_JSON_PATH:-realm.json}"
ADAPTER_OUTPUT_PATH="${ADAPTER_OUTPUT_PATH:-../../data/tidecloak.json}"
NEW_REALM_NAME="${NEW_REALM_NAME:-keylessh}"
REALM_MGMT_CLIENT_ID="realm-management"
ADMIN_ROLE_NAME="tide-realm-admin"
KC_USER="${KC_USER:-admin}"
KC_PASSWORD="${KC_PASSWORD:-password}"
CLIENT_NAME="${CLIENT_NAME:-myclient}"
SCRIPT_DIR="${SCRIPT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}"

CURL_OPTS="-f"
if [[ "$TIDECLOAK_LOCAL_URL" == https://* ]]; then
    CURL_OPTS="-k"
fi

log_info "Configuration:"
log_info "  Tidecloak URL: $TIDECLOAK_LOCAL_URL"
log_info "  Client App URL: $CLIENT_APP_URL"
echo ""

# Check if realm.json exists
if [ ! -f "$REALM_JSON_PATH" ]; then
    log_error "Realm template not found at: $REALM_JSON_PATH"
    exit 1
fi

# Wait for Tidecloak
log_info "Checking Tidecloak connectivity..."
for i in {1..15}; do
    if curl -s -f $CURL_OPTS --connect-timeout 5 "$TIDECLOAK_LOCAL_URL" > /dev/null 2>&1; then
        log_info "✓ Tidecloak is accessible"
        break
    fi
    if [ $i -eq 15 ]; then
        log_error "Cannot connect to Tidecloak at $TIDECLOAK_LOCAL_URL"
        exit 1
    fi
    log_warn "Waiting for Tidecloak (attempt $i/15)..."
    sleep 5
done
echo ""

# Function to get admin token
get_admin_token() {
    curl -s $CURL_OPTS -X POST "${TIDECLOAK_LOCAL_URL}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${KC_USER}" \
        -d "password=${KC_PASSWORD}" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" | jq -r '.access_token'
}

REALM_NAME="${NEW_REALM_NAME}"
echo "📄 Generated realm name: $REALM_NAME"

TMP_REALM_JSON="$(mktemp)"
cp "$REALM_JSON_PATH" "$TMP_REALM_JSON"
# sed -i "s|http://localhost:3000|$CLIENT_APP_URL|g" "$TMP_REALM_JSON"
sed -i "s|KEYLESSH|$REALM_NAME|g" "$TMP_REALM_JSON"

# Create realm
echo "🌍 Creating realm..."
TOKEN="$(get_admin_token)"
status=$(curl -s $CURL_OPTS -o /dev/null -w "%{http_code}" \
    -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @"$TMP_REALM_JSON")

if [[ $status == 2* ]]; then
    echo "✅ Realm created."
else
    echo "❌ Realm creation failed (HTTP $status)"
    exit 1
fi

# Initialize Tide realm + IGA
TOKEN="$(get_admin_token)"
echo "🔐 Initializing Tide realm + IGA..."

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

curl -s $CURL_OPTS -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/vendorResources/setUpTideRealm" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "email=${LICENSE_EMAIL}" \
    --data-urlencode "isRagnarokEnabled=true" > /dev/null 2>&1

curl -s $CURL_OPTS -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/tide-admin/toggle-iga" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "isIGAEnabled=true" > /dev/null 2>&1
echo "✅ Tide realm + IGA done."

approve_and_commit() {
    local TYPE=$1
    echo "🔄 Processing ${TYPE} change-sets..."
    TOKEN="$(get_admin_token)"

    # Get change-sets (don't use -f here as empty results are OK)
    local requests
    requests=$(curl -s -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/tide-admin/change-set/${TYPE}/requests" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "[]")

    # Check if there are any requests to process
    local count
    count=$(echo "$requests" | jq 'length' 2>/dev/null || echo "0")

    if [ "$count" = "0" ] || [ "$count" = "" ]; then
        echo "  No ${TYPE} change-sets to process"
    else
        echo "$requests" | jq -c '.[]' | while read -r req; do
            payload=$(jq -n --arg id "$(echo "$req" | jq -r .draftRecordId)" \
                            --arg cst "$(echo "$req" | jq -r .changeSetType)" \
                            --arg at "$(echo "$req" | jq -r .actionType)" \
                            '{changeSetId:$id,changeSetType:$cst,actionType:$at}')

            # Sign the change-set
            local sign_response
            sign_response=$(curl -s -w "\n%{http_code}" -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/tide-admin/change-set/sign" \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d "$payload" 2>&1)

            local sign_status=$(echo "$sign_response" | tail -1)
            local sign_body=$(echo "$sign_response" | sed '$d')

            if [[ ! "$sign_status" =~ ^2 ]]; then
                log_error "Failed to sign ${TYPE} change-set (HTTP $sign_status): $(echo "$req" | jq -r .draftRecordId)"
                log_error "Response: $sign_body"
                return 1
            fi

            # Commit the change-set
            local commit_response
            commit_response=$(curl -s -w "\n%{http_code}" -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/tide-admin/change-set/commit" \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d "$payload" 2>&1)

            local commit_status=$(echo "$commit_response" | tail -1)
            local commit_body=$(echo "$commit_response" | sed '$d')

            if [[ ! "$commit_status" =~ ^2 ]]; then
                log_error "Failed to commit ${TYPE} change-set (HTTP $commit_status): $(echo "$req" | jq -r .draftRecordId)"
                log_error "Response: $commit_body"
                return 1
            fi
        done
    fi
    echo "✅ ${TYPE} change-sets done."
}

approve_and_commit clients

# Create admin user
TOKEN="$(get_admin_token)"
echo "👤 Creating admin user..."
curl -s $CURL_OPTS -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/users" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","email":"admin@yourorg.com","firstName":"admin","lastName":"user","enabled":true,"emailVerified":false,"requiredActions":[],"attributes":{"locale":""},"groups":[]}' > /dev/null 2>&1

USER_ID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/users?username=admin" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

CLIENT_UUID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/clients?clientId=${REALM_MGMT_CLIENT_ID}" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

ROLE_JSON=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/clients/$CLIENT_UUID/roles/${ADMIN_ROLE_NAME}" \
    -H "Authorization: Bearer $TOKEN")

curl -s $CURL_OPTS -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/users/$USER_ID/role-mappings/clients/$CLIENT_UUID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "[$ROLE_JSON]" > /dev/null 2>&1
echo "✅ Admin user & role done."

# Fetch adapter config
TOKEN="$(get_admin_token)"
echo "📥 Fetching adapter config…"
CLIENT_UUID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/clients?clientId=${CLIENT_NAME}" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

curl -s $CURL_OPTS -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/vendorResources/get-installations-provider?clientId=${CLIENT_UUID}&providerId=keycloak-oidc-keycloak-json" \
    -H "Authorization: Bearer $TOKEN" > "$ADAPTER_OUTPUT_PATH"
echo "✅ Adapter config saved to $ADAPTER_OUTPUT_PATH"

rm -f "$TMP_REALM_JSON"

# Upload branding images (logo and background)
upload_branding() {
    echo "🎨 Uploading branding images..."
    TOKEN="$(get_admin_token)"

    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
        log_warn "Failed to get token for branding upload"
        return 1
    fi

    # Look for images in public folder (relative to script dir's parent)
    local PUBLIC_DIR="${SCRIPT_DIR}/tidecloak/public"

    # Upload logo if exists (use -s only, not $CURL_OPTS which has -f that exits on error)
    # Endpoint: tide-idp-admin-resources/images/upload
    if [ -f "${PUBLIC_DIR}/keylessh-logo_icon.svg" ]; then
        local logo_status
        logo_status=$(curl -s -k -o /dev/null -w "%{http_code}" \
            -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/tide-idp-admin-resources/images/upload" \
            -H "Authorization: Bearer ${TOKEN}" \
            -F "fileData=@${PUBLIC_DIR}/keylessh-logo_icon.svg" \
            -F "fileName=keylessh-logo_icon.svg" \
            -F "fileType=LOGO" 2>/dev/null || echo "000")
        if [[ "$logo_status" =~ ^2 ]]; then
            echo "  ✅ Logo uploaded"
        else
            log_warn "Logo upload failed (HTTP $logo_status) - continuing anyway"
        fi
    else
        log_warn "Logo not found at ${PUBLIC_DIR}/keylessh-logo_icon.svg"
    fi

    # Upload background if exists
    if [ -f "${PUBLIC_DIR}/keylessh_bg.gif" ]; then
        local bg_status
        bg_status=$(curl -s -k -o /dev/null -w "%{http_code}" \
            -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/tide-idp-admin-resources/images/upload" \
            -H "Authorization: Bearer ${TOKEN}" \
            -F "fileData=@${PUBLIC_DIR}/keylessh_bg.gif" \
            -F "fileName=keylessh_bg.gif" \
            -F "fileType=BACKGROUND_IMAGE" 2>/dev/null || echo "000")
        if [[ "$bg_status" =~ ^2 ]]; then
            echo "  ✅ Background uploaded"
        else
            log_warn "Background upload failed (HTTP $bg_status) - continuing anyway"
        fi
    else
        log_warn "Background not found at ${PUBLIC_DIR}/keylessh_bg.gif"
    fi

    echo "✅ Branding upload complete."
}

upload_branding

# Generate invite link
TOKEN="$(get_admin_token)"
echo "🔗 Generating invite link..."

RAW_INVITE_LINK=$(curl -s $CURL_OPTS -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/tideAdminResources/get-required-action-link?userId=${USER_ID}&lifespan=43200" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '["link-tide-account-action"]')

echo ""
echo "================================================"
echo "🔗 INVITE LINK (use this one):"
echo "$RAW_INVITE_LINK"
echo "================================================"
echo ""
echo "→ Open this link in your browser to link the admin account."
echo ""
echo -n "Checking link status… "
  
while true; do
    TOKEN="$(get_admin_token)"
    ATTRS=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/users?username=admin" \
        -H "Authorization: Bearer $TOKEN")
    KEY=$(echo "$ATTRS" | jq -r '.[0].attributes.tideUserKey[0] // empty')
    VUID=$(echo "$ATTRS" | jq -r '.[0].attributes.vuid[0] // empty')
    if [[ -n "$KEY" && -n "$VUID" ]]; then
        echo "✅ Linked!"
        break
    fi
    sleep 5
done

approve_and_commit users

# Update CustomAdminUIDomain
TOKEN="$(get_admin_token)"
echo "🌐 Updating CustomAdminUIDomain..."
INST=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/identity-provider/instances/tide" \
    -H "Authorization: Bearer $TOKEN")
UPDATED=$(echo "$INST" | jq --arg d "$CLIENT_APP_URL" '.config.CustomAdminUIDomain=$d')

curl -s $CURL_OPTS -X PUT "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/identity-provider/instances/tide" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$UPDATED" > /dev/null 2>&1

curl -s $CURL_OPTS -X POST "${TIDECLOAK_LOCAL_URL}/admin/realms/${REALM_NAME}/vendorResources/sign-idp-settings" \
    -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1
echo "✅ CustomAdminUIDomain updated + signed."

echo ""
echo "🎉 Tidecloak initialization complete!"
