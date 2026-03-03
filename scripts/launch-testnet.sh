#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="docker-compose.testnet.yml"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Generate TLS certificates if they don't exist
if [ ! -f certs/ca.crt ]; then
    echo "Generating TLS certificates..."
    "$SCRIPT_DIR/generate-certs.sh"
else
    echo "TLS certificates already exist in certs/"
fi

echo "Building Umbra Docker image..."
docker compose -f "$COMPOSE_FILE" build

echo "Starting 3-validator testnet..."
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "Testnet is running (mTLS enabled):"
echo "  Validator 1 RPC: https://localhost:9743"
echo "  Health check:    curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://localhost:9743/health"
echo "  Validators:      curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://localhost:9743/validators"
echo "  State:           curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://localhost:9743/state"
echo ""
echo "Stop with: docker compose -f $COMPOSE_FILE down"
echo "Logs with: docker compose -f $COMPOSE_FILE logs -f"
