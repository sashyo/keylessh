sudo docker run \
 --name tidecloakp \
  -d \
  -v .:/opt/keycloak/data/h2 \
  -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=password \
  tideorg/tidecloak-dev:latest

export SCRIPT_DIR=$(dirname "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)")
export TIDECLOAK_LOCAL_URL=http://localhost:8080
mkdir ../../data
bash ./init-tidecloak.sh

