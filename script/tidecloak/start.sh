sudo docker run \
 --name mytidecloak \
 -d \
 -v .:/opt/keycloak/data/h2 \
 -p 8080:8080 \
 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
 -e KC_BOOTSTRAP_ADMIN_PASSWORD=password \
 -e KC_HOSTNAME=http://localhost:8080 \
 -e SYSTEM_HOME_ORK=https://sork1.tideprotocol.com \
 -e USER_HOME_ORK=https://sork1.tideprotocol.com \
 -e THRESHOLD_T=3 \
 -e THRESHOLD_N=5 \
 -e PAYER_PUBLIC=20000011d6a0e8212d682657147d864b82d10e92776c15ead43dcfdc100ebf4dcfe6a8 \
 tideorg/tidecloak-stg-dev:latest

export SCRIPT_DIR=$(dirname "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)")
export TIDECLOAK_LOCAL_URL=http://localhost:8080
mkdir ../../data
bash ./init-tidecloak.sh

