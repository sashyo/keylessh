#!/bin/bash
set -e

# Configuration
RESOURCE_GROUP="keylessh-rg"
LOCATION="eastus"
VM_NAME="keylessh-stun"
VM_SIZE="Standard_B1s"
ACR_NAME="keylesshacr"
IMAGE_NAME="keylessh-stun"
CERT_DIR="/etc/stun-tls"

# Optional: domain for Let's Encrypt TLS. If not set, uses self-signed cert.
DOMAIN="${DOMAIN:-}"

# Optional: email for Let's Encrypt (required for real certs)
LE_EMAIL="${LE_EMAIL:-}"

# Auto-generate TURN secret if not provided
TURN_SECRET="${TURN_SECRET:-$(openssl rand -base64 32)}"

echo "=== KeyleSSH STUN/TURN Server Deployment (Azure VM) ==="
echo "Resource Group: $RESOURCE_GROUP"
echo "Location: $LOCATION"
echo "VM: $VM_NAME ($VM_SIZE)"
if [ -n "$DOMAIN" ]; then
    echo "TLS: Let's Encrypt ($DOMAIN)"
else
    echo "TLS: Self-signed certificate"
fi
echo ""

if ! az account show &> /dev/null; then
    echo "Please login to Azure first: az login"
    exit 1
fi

# Create resource group
echo "Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output none 2>/dev/null || true

# Create ACR and build image
echo "Creating container registry..."
az acr create \
    --resource-group $RESOURCE_GROUP \
    --name $ACR_NAME \
    --sku Basic \
    --admin-enabled true \
    --output none 2>/dev/null || true

echo "Building and pushing Docker image..."
az acr build \
    --registry $ACR_NAME \
    --image $IMAGE_NAME:latest \
    --file Dockerfile \
    .

ACR_SERVER=$(az acr show --name $ACR_NAME --query loginServer -o tsv)
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv)

# Build TLS generation script based on mode
if [ -n "$DOMAIN" ]; then
    # Let's Encrypt via certbot
    LE_EMAIL_FLAG=""
    if [ -n "$LE_EMAIL" ]; then
        LE_EMAIL_FLAG="-m ${LE_EMAIL}"
    else
        LE_EMAIL_FLAG="--register-unsafely-without-email"
    fi

    TLS_SETUP="
# Install certbot
apt-get install -y certbot

# Get Let's Encrypt certificate
certbot certonly --standalone -d ${DOMAIN} ${LE_EMAIL_FLAG} --agree-tos --non-interactive

# Copy certs to known location
mkdir -p ${CERT_DIR}
cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${CERT_DIR}/cert.pem
cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${CERT_DIR}/key.pem
chmod 644 ${CERT_DIR}/cert.pem ${CERT_DIR}/key.pem

# Auto-renew certs and restart container
cat > /etc/cron.d/certbot-renew <<'CRON'
0 3 * * * root certbot renew --quiet --deploy-hook \"cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${CERT_DIR}/cert.pem && cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${CERT_DIR}/key.pem && docker restart stun-server\"
CRON
"
else
    # Self-signed certificate
    TLS_SETUP="
mkdir -p ${CERT_DIR}
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ${CERT_DIR}/key.pem \
    -out ${CERT_DIR}/cert.pem \
    -days 365 \
    -subj '/CN=keylessh-stun'
chmod 644 ${CERT_DIR}/cert.pem ${CERT_DIR}/key.pem
"
fi

# Build cloud-init script
CLOUD_INIT=$(cat <<CLOUDINIT
#!/bin/bash
set -e

# Install Docker
curl -fsSL https://get.docker.com | sh
systemctl enable docker

${TLS_SETUP}

# Login to ACR
docker login ${ACR_SERVER} -u ${ACR_USERNAME} -p '${ACR_PASSWORD}'

# Redirect port 443 → 9090 so the app doesn't need root
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9090

# Persist iptables across reboots
apt-get install -y iptables-persistent
netfilter-persistent save

# Run STUN server with TLS certs mounted
docker run -d \
    --name stun-server \
    --restart always \
    --network host \
    -v ${CERT_DIR}:${CERT_DIR}:ro \
    -e STUN_PORT=3478 \
    -e SIGNAL_PORT=9090 \
    -e REALM=keylessh \
    -e EXTERNAL_IP=\$(curl -s ifconfig.me) \
    -e TURN_SECRET=${TURN_SECRET} \
    -e TLS_CERT_PATH=${CERT_DIR}/cert.pem \
    -e TLS_KEY_PATH=${CERT_DIR}/key.pem \
    ${ACR_SERVER}/${IMAGE_NAME}:latest
CLOUDINIT
)

# Create VM
echo "Creating VM..."
az vm create \
    --resource-group $RESOURCE_GROUP \
    --name $VM_NAME \
    --image Ubuntu2404 \
    --size $VM_SIZE \
    --admin-username azureuser \
    --generate-ssh-keys \
    --public-ip-sku Standard \
    --custom-data <(echo "$CLOUD_INIT") \
    --output table

# Get public IP
PUBLIC_IP=$(az vm show \
    --resource-group $RESOURCE_GROUP \
    --name $VM_NAME \
    --show-details \
    --query publicIps -o tsv)

# Open ports: HTTPS/WSS (443), STUN/TURN UDP+TCP (3478), HTTP (80 for ACME challenges)
echo "Opening firewall ports..."
az vm open-port --resource-group $RESOURCE_GROUP --name $VM_NAME --port 443 --priority 1001 --output none
az vm open-port --resource-group $RESOURCE_GROUP --name $VM_NAME --port 3478 --protocol Udp --priority 1002 --output none
az vm open-port --resource-group $RESOURCE_GROUP --name $VM_NAME --port 3478 --protocol Tcp --priority 1003 --output none
az vm open-port --resource-group $RESOURCE_GROUP --name $VM_NAME --port 80 --priority 1004 --output none

# Determine host for output
if [ -n "$DOMAIN" ]; then
    HOST="$DOMAIN"
else
    HOST="$PUBLIC_IP"
fi

# Save deployment info for the WAF deploy script to consume
DEPLOY_ENV_FILE="$(dirname "$0")/../../.stun-deploy.env"
cat > "$DEPLOY_ENV_FILE" <<EOF
# Auto-generated by stun-server deploy — $(date -u +%Y-%m-%dT%H:%M:%SZ)
STUN_SERVER_URL=wss://$HOST
ICE_SERVERS=stun:$HOST:3478
TURN_SERVER=turn:$HOST:3478
TURN_SECRET=$TURN_SECRET
STUN_PUBLIC_IP=$PUBLIC_IP
EOF

echo ""
if [ -n "$DOMAIN" ]; then
    echo "=== Deployment Complete ==="
    echo ""
    echo ">>> Point your DNS A record for $DOMAIN to $PUBLIC_IP <<<"
else
    echo "=== Deployment Complete (Self-Signed TLS) ==="
    echo ""
    echo "NOTE: Self-signed cert — WAFs need NODE_TLS_REJECT_UNAUTHORIZED=0."
    echo "Browser users must visit https://$PUBLIC_IP and accept the cert"
    echo "before WebRTC signaling will work."
fi
echo ""
echo "Public IP:    $PUBLIC_IP"
echo "Signaling:    wss://$HOST"
echo "STUN:         stun:$HOST:3478"
echo "TURN:         turn:$HOST:3478"
echo "Health:       https://$HOST/health"
echo "TURN Secret:  $TURN_SECRET"
echo ""
echo "Saved to $DEPLOY_ENV_FILE"
echo ""
echo "Deploy WAFs with:"
echo "  BACKEND_URL=http://your-app:3000 ./waf/azure/deploy.sh"
echo "  (it will auto-read STUN config from .stun-deploy.env)"
echo ""
echo "SSH: ssh azureuser@$PUBLIC_IP"
