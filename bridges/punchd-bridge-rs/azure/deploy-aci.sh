#!/usr/bin/env bash
# Deploy punchd-gateway to Azure Container Instance with UDP support for QUIC.
# Reads secrets from the signal server's .env file or environment variables.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SIGNAL_ENV="${REPO_DIR}/signal-server/.env"

# Load secrets from signal-server .env if available
if [ -f "$SIGNAL_ENV" ]; then
  echo "[Deploy] Loading secrets from signal-server/.env"
  source "$SIGNAL_ENV"
fi

# Required variables
: "${GATEWAY_ID:=Tide-GW}"
: "${STUN_SERVER_URL:?Set STUN_SERVER_URL}"
: "${API_SECRET:?Set API_SECRET}"
: "${TURN_SECRET:?Set TURN_SECRET}"
: "${TIDECLOAK_CONFIG_B64:?Set TIDECLOAK_CONFIG_B64}"
: "${BACKENDS:?Set BACKENDS e.g. 'My Server=ssh://10.0.0.4'}"
: "${AUTH_SERVER_PUBLIC_URL:=https://login.dauth.me}"
: "${SERVER_URL:=https://demo.keylessh.com}"
: "${ICE_SERVERS:=stun:${EXTERNAL_IP:-localhost}:3478}"
: "${TURN_SERVER:=turn:${EXTERNAL_IP:-localhost}:3478}"

RG="${RESOURCE_GROUP:-KeyleSSH}"
LOCATION="${LOCATION:-australiaeast}"
ACI_NAME="${ACI_NAME:-punchd-gateway}"
DNS_LABEL="${DNS_LABEL:-punchd-gateway}"
IMAGE="${IMAGE:-tideorg/punchd-gateway:latest}"

echo "[Deploy] Gateway: ${GATEWAY_ID}"
echo "[Deploy] Image:   ${IMAGE}"
echo "[Deploy] ACI:     ${ACI_NAME} (${LOCATION})"

# Delete existing container
echo "[Deploy] Deleting existing ACI (if any)..."
az container delete --resource-group "$RG" --name "$ACI_NAME" --yes 2>/dev/null || true

# Generate YAML with secrets interpolated (not checked into git)
TMPFILE=$(mktemp /tmp/aci-deploy-XXXXXX.yaml)
cat > "$TMPFILE" <<YAML
apiVersion: 2021-09-01
location: ${LOCATION}
name: ${ACI_NAME}
type: Microsoft.ContainerInstance/containerGroups
properties:
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    dnsNameLabel: ${DNS_LABEL}
    ports:
      - port: 7891
        protocol: TCP
      - port: 7892
        protocol: TCP
      - port: 7893
        protocol: UDP
  containers:
    - name: ${ACI_NAME}
      properties:
        image: ${IMAGE}
        resources:
          requests:
            cpu: 1
            memoryInGb: 1
        ports:
          - port: 7891
            protocol: TCP
          - port: 7892
            protocol: TCP
          - port: 7893
            protocol: UDP
        environmentVariables:
          - name: GATEWAY_ID
            value: "${GATEWAY_ID}"
          - name: STUN_SERVER_URL
            value: "${STUN_SERVER_URL}"
          - name: API_SECRET
            secureValue: "${API_SECRET}"
          - name: ICE_SERVERS
            value: "${ICE_SERVERS}"
          - name: TURN_SERVER
            value: "${TURN_SERVER}"
          - name: TURN_SECRET
            secureValue: "${TURN_SECRET}"
          - name: BACKENDS
            value: "${BACKENDS}"
          - name: TIDECLOAK_CONFIG_B64
            secureValue: "${TIDECLOAK_CONFIG_B64}"
          - name: AUTH_SERVER_PUBLIC_URL
            value: "${AUTH_SERVER_PUBLIC_URL}"
          - name: SERVER_URL
            value: "${SERVER_URL}"
          - name: LISTEN_PORT
            value: "7891"
          - name: HEALTH_PORT
            value: "7892"
          - name: QUIC_PORT
            value: "7893"
          - name: HTTPS
            value: "false"
YAML

echo "[Deploy] Creating ACI..."
az container create --resource-group "$RG" --file "$TMPFILE"
rm -f "$TMPFILE"

# Show result
echo ""
IP=$(az container show --resource-group "$RG" --name "$ACI_NAME" --query "ipAddress.ip" -o tsv)
FQDN=$(az container show --resource-group "$RG" --name "$ACI_NAME" --query "ipAddress.fqdn" -o tsv)
echo "============================================"
echo " Punchd Gateway ACI deployed"
echo "============================================"
echo "  IP:   ${IP}"
echo "  FQDN: ${FQDN}"
echo "  HTTP: http://${FQDN}:7891"
echo "  QUIC: ${FQDN}:7893 (UDP)"
echo ""
