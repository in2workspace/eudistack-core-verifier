#!/usr/bin/env bash
set -euo pipefail

for variable in CONTAINER_IMAGE CONTAINER_NAME DAST_DB_HOST DAST_DB_PORT \
  DAST_DB_NAME DAST_DB_USERNAME DAST_DB_PASSWORD; do
  if [[ -z "${!variable:-}" ]]; then
    echo "::error::Missing required DAST variable: ${variable}"
    exit 1
  fi
done

config_directory="${PWD}/dev-tools/local-config"
for config_file in clients.yaml trusted-issuers.yaml sso-config.yaml dcql-profiles.yaml; do
  if [[ ! -f "${config_directory}/${config_file}" ]]; then
    echo "::error::Missing required Verifier DAST configuration: ${config_directory}/${config_file}"
    exit 1
  fi
done

jdbc_url="jdbc:postgresql://${DAST_DB_HOST}:${DAST_DB_PORT}/${DAST_DB_NAME}"

docker run -d --name "${CONTAINER_NAME}" \
  --network host \
  -e SERVER_PORT=8080 \
  -e SPRING_DATASOURCE_URL="${jdbc_url}" \
  -e SPRING_DATASOURCE_USERNAME="${DAST_DB_USERNAME}" \
  -e SPRING_DATASOURCE_PASSWORD="${DAST_DB_PASSWORD}" \
  -e SPRING_FLYWAY_URL="${jdbc_url}" \
  -e SPRING_FLYWAY_USER="${DAST_DB_USERNAME}" \
  -e SPRING_FLYWAY_PASSWORD="${DAST_DB_PASSWORD}" \
  -e VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH=/etc/eudistack/verifier/clients.yaml \
  -e VERIFIER_BACKEND_LOCALFILES_TRUSTEDISSUERSPATH=/etc/eudistack/verifier/trusted-issuers.yaml \
  -e VERIFIER_BACKEND_LOCALFILES_SSOCONFIGPATH=/etc/eudistack/verifier/sso-config.yaml \
  -e VERIFIER_BACKEND_LOCALFILES_DCQLPATH=/etc/eudistack/verifier/dcql-profiles.yaml \
  -e VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY=3Cm+63BqBWB7Y/HTa47aD0ZZvsPRIIyxUiGJubKQJR4= \
  -v "${config_directory}:/etc/eudistack/verifier:ro" \
  "${CONTAINER_IMAGE}"
