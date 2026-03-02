#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="docker-compose.testnet.yml"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "Building Umbra Docker image..."
docker compose -f "$COMPOSE_FILE" build

echo "Starting 3-validator testnet..."
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "Testnet is running:"
echo "  Validator 1 RPC: http://localhost:9743"
echo "  Health check:    curl http://localhost:9743/health"
echo "  Validators:      curl http://localhost:9743/validators"
echo "  State:           curl http://localhost:9743/state"
echo ""
echo "Stop with: docker compose -f $COMPOSE_FILE down"
echo "Logs with: docker compose -f $COMPOSE_FILE logs -f"
