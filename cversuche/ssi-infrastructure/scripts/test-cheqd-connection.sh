#!/bin/bash

# Test cheqd Network Connection from ACA-Py Agents
# Tests connectivity between ACA-Py agents and cheqd infrastructure
# Network: ssi-network (172.20.0.0/16)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

echo ""
echo "================================================"
echo "  cheqd Network Connection Test for ACA-Py"
echo "================================================"
echo ""

# Test 1: cheqd Validator-0 RPC
print_test "Testing cheqd Validator-0 RPC endpoint..."
if curl -s --max-time 5 http://localhost:26657/status | jq -e '.result.sync_info.catching_up == false' > /dev/null 2>&1; then
    print_success "Validator-0 RPC is healthy and synced"
else
    print_error "Validator-0 RPC failed or not synced"
fi

# Test 2: cheqd REST API
print_test "Testing cheqd REST API endpoint..."
if curl -s --max-time 5 http://localhost:1317/cosmos/base/tendermint/v1beta1/node_info > /dev/null 2>&1; then
    print_success "cheqd REST API is accessible"
else
    print_error "cheqd REST API failed"
fi

# Test 3: DID Resolver
print_test "Testing DID Resolver service..."
if curl -s --max-time 5 http://localhost:8080/1.0/identifiers/did:cheqd:testnet:zF7rhDBfUt9d1gJPjx7s1J > /dev/null 2>&1; then
    print_success "DID Resolver is accessible"
else
    print_error "DID Resolver failed"
fi

# Test 4: DID Registrar
print_test "Testing DID Registrar service..."
if curl -s --max-time 5 http://localhost:9080/1.0/methods | jq -e '.methods | length > 0' > /dev/null 2>&1; then
    print_success "DID Registrar is accessible"
    METHODS=$(curl -s http://localhost:9080/1.0/methods | jq -r '.methods[]' | tr '\n' ', ' | sed 's/,$//')
    print_info "Supported DID methods: $METHODS"
else
    print_error "DID Registrar failed"
fi

echo ""
echo "--- ACA-Py Agent Connectivity Tests ---"
echo ""

# Test 5: Issuer Agent
print_test "Testing Issuer Agent (port 8021)..."
if curl -s --max-time 5 http://localhost:8021/status/ready > /dev/null 2>&1; then
    print_success "Issuer Agent is ready"

    # Check if cheqd plugin is loaded
    if curl -s http://localhost:8021/status | jq -e '.' > /dev/null 2>&1; then
        print_info "Issuer Agent status endpoint accessible"
    fi
else
    print_error "Issuer Agent is not responding"
fi

# Test 6: Holder Agent
print_test "Testing Holder Agent (port 8031)..."
if curl -s --max-time 5 http://localhost:8031/status/ready > /dev/null 2>&1; then
    print_success "Holder Agent is ready"

    if curl -s http://localhost:8031/status | jq -e '.' > /dev/null 2>&1; then
        print_info "Holder Agent status endpoint accessible"
    fi
else
    print_error "Holder Agent is not responding"
fi

# Test 7: Verifier Agent
print_test "Testing Verifier Agent (port 8041)..."
if curl -s --max-time 5 http://localhost:8041/status/ready > /dev/null 2>&1; then
    print_success "Verifier Agent is ready"

    if curl -s http://localhost:8041/status | jq -e '.' > /dev/null 2>&1; then
        print_info "Verifier Agent status endpoint accessible"
    fi
else
    print_error "Verifier Agent is not responding"
fi

echo ""
echo "--- Database Connectivity Tests ---"
echo ""

# Test 8: PostgreSQL
print_test "Testing PostgreSQL database..."
if docker exec -it ssi-infrastructure-postgres-acapy-1 pg_isready -U acapy -d acapy_wallets > /dev/null 2>&1; then
    print_success "PostgreSQL database is ready"
else
    print_warning "PostgreSQL check failed (may need different container name)"
fi

echo ""
echo "================================================"
echo "  Connection Test Summary"
echo "================================================"
echo ""
print_info "Infrastructure Services:"
echo "  • cheqd Validator-0: http://localhost:26657"
echo "  • DID Resolver:      http://localhost:8080"
echo "  • DID Registrar:     http://localhost:9080"
echo ""
print_info "ACA-Py Agent Admin APIs:"
echo "  • Issuer:            http://localhost:8021"
echo "  • Holder:            http://localhost:8031"
echo "  • Verifier:          http://localhost:8041"
echo ""
print_info "Next Steps:"
echo "  1. Check agent logs: docker logs ssi-infrastructure-acapy-issuer-1"
echo "  2. Monitor status:   ./scripts/status.sh"
echo "  3. View all logs:    docker compose logs -f"
echo ""
