#!/bin/bash
# Start cheqd-node localnet with proper network configuration
# This script initializes the cheqd network if not already configured

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CHEQD_NODE_DIR="$PROJECT_ROOT/cheqd-node/docker/localnet"
NETWORK_CONFIG_DIR="$CHEQD_NODE_DIR/network-config"

echo "=========================================="
echo "cheqd-node Network Initialization"
echo "=========================================="

# Check if network configuration already exists
if [ -d "$NETWORK_CONFIG_DIR" ]; then
    echo "✓ Network configuration found at: $NETWORK_CONFIG_DIR"
    echo "  Skipping network generation..."
else
    echo "✗ Network configuration not found"
    echo "  Generating new network configuration..."

    cd "$CHEQD_NODE_DIR"

    # Check if cheqd-noded binary is available
    if ! command -v cheqd-noded &> /dev/null; then
        echo "✗ Error: cheqd-noded binary not found"
        echo "  Please ensure cheqd-node is installed or use Docker to generate config"
        echo ""
        echo "  Alternative: Run network config generation in Docker:"
        echo "  docker run --rm -v $CHEQD_NODE_DIR:/workspace ghcr.io/cheqd/cheqd-node:latest \\"
        echo "    /bin/bash -c 'cd /workspace && ./gen-network-config.sh cheqd-local 4 1 1'"
        exit 1
    fi

    # Generate network configuration
    # Parameters: chain-id validators seeds observers
    ./gen-network-config.sh "cheqd-local" 4 1 1

    echo "✓ Network configuration generated successfully"
fi

echo ""
echo "=========================================="
echo "Starting cheqd-node services..."
echo "=========================================="

cd "$PROJECT_ROOT"

# Start cheqd-node validators, seed, and observer
docker-compose -f docker-compose-cheqd-acapy.yml up -d \
    cheqd-validator-0 \
    cheqd-validator-1 \
    cheqd-validator-2 \
    cheqd-validator-3 \
    cheqd-seed-0 \
    cheqd-observer-0

echo ""
echo "Waiting for cheqd-node network to initialize (30 seconds)..."
sleep 30

# Check validator-0 health
echo ""
echo "Checking cheqd-node health..."
if curl -sf http://localhost:26657/health > /dev/null 2>&1; then
    echo "✓ cheqd-node is healthy"

    # Display network status
    echo ""
    echo "=========================================="
    echo "Network Status"
    echo "=========================================="
    curl -s http://localhost:26657/status | jq '{
        node_info: .result.node_info.moniker,
        network: .result.node_info.network,
        latest_block_height: .result.sync_info.latest_block_height,
        catching_up: .result.sync_info.catching_up
    }' || echo "Status check completed"
else
    echo "⚠ Warning: cheqd-node health check failed"
    echo "  The network may still be initializing..."
fi

echo ""
echo "=========================================="
echo "cheqd-node Network Ready"
echo "=========================================="
echo ""
echo "Available endpoints:"
echo "  • RPC:      http://localhost:26657"
echo "  • REST API: http://localhost:1317"
echo "  • gRPC:     localhost:9090"
echo ""
echo "Next steps:"
echo "  1. Start DID services: ./scripts/start-did-services.sh"
echo "  2. Start ACA-Py agents: ./scripts/start-acapy-agents.sh"
echo "  3. Or start everything: docker-compose -f docker-compose-cheqd-acapy.yml up -d"
echo ""
