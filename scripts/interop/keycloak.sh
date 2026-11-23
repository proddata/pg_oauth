#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runtime_dir="$repository/build/interop/keycloak"
compose_file="$repository/tests/interop/keycloak/compose.yml"
pg_image="postgres:19.0-bookworm@sha256:f4859caf96de494e38efa69ed703b08a5bbd9605e152e604f2daec8841c87c41"

mkdir -p "$runtime_dir"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$runtime_dir/tls.key" -out "$runtime_dir/tls.crt" \
    -days 1 -subj "/CN=keycloak" \
    -addext "subjectAltName=DNS:keycloak" >/dev/null 2>&1
chmod 0644 "$runtime_dir/tls.key" "$runtime_dir/tls.crt"
rm -f "$runtime_dir/outage-requested" "$runtime_dir/outage-ready" \
    "$runtime_dir/recovery-requested" "$runtime_dir/recovery-ready"

cleanup() {
    if test -n "${runner_pid-}" && kill -0 "$runner_pid" 2>/dev/null; then
        kill "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
    fi
    make -C "$repository" clean >/dev/null
    KEYCLOAK_INTEROP_DIR="$runtime_dir" \
        docker compose -p pg-oauth-keycloak -f "$compose_file" down --volumes
}
trap cleanup EXIT INT TERM

KEYCLOAK_INTEROP_DIR="$runtime_dir" \
    docker compose -p pg-oauth-keycloak -f "$compose_file" up --detach

docker run --rm \
    --network pg-oauth-keycloak-interop \
    -v "$repository:/workspace" \
    -w /workspace \
    "$pg_image" \
    sh -c 'apt-get update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends build-essential ca-certificates cmake curl libkrb5-dev libcurl4-openssl-dev libssl-dev openssl pkg-config python3-pytest postgresql-server-dev-19 >/dev/null && ./scripts/ci/install-jansson.sh >/dev/null && ./scripts/ci/install-libjwt.sh >/dev/null && make clean >/dev/null && make all tests/integration/oauth_test_client >/dev/null && PG_CONFIG=pg_config VALIDATOR_LIBRARY=/workspace/pg_oauth_validator.so OAUTH_TEST_CLIENT=/workspace/tests/integration/oauth_test_client CACHE_PROBE=/workspace/tests/integration/cache_probe.so KEYCLOAK_CA_FILE=/workspace/build/interop/keycloak/tls.crt KEYCLOAK_TLS_KEY_FILE=/workspace/build/interop/keycloak/tls.key KEYCLOAK_CONTROL_DIR=/workspace/build/interop/keycloak PYTHONPATH=/workspace/tests/integration PYTHONPYCACHEPREFIX=/tmp/pg-oauth-pycache python3 -m pytest -q -o cache_dir=/tmp/pg-oauth-pytest-cache /workspace/tests/interop/keycloak/test_keycloak.py' &
runner_pid=$!

wait_for_signal() {
    signal=$1
    attempts=0
    while test ! -f "$runtime_dir/$signal"; do
        if ! kill -0 "$runner_pid" 2>/dev/null; then
            wait "$runner_pid"
        fi
        attempts=$((attempts + 1))
        if test "$attempts" -ge 6000; then
            echo "error: timed out waiting for $signal" >&2
            return 1
        fi
        sleep 0.1
    done
}

wait_for_signal outage-requested
KEYCLOAK_INTEROP_DIR="$runtime_dir" \
    docker compose -p pg-oauth-keycloak -f "$compose_file" stop keycloak
touch "$runtime_dir/outage-ready"

wait_for_signal recovery-requested
KEYCLOAK_INTEROP_DIR="$runtime_dir" \
    docker compose -p pg-oauth-keycloak -f "$compose_file" start keycloak
touch "$runtime_dir/recovery-ready"

wait "$runner_pid"
