#!/bin/bash
# Wait for all services to be ready before proceeding
# This script checks health endpoints and waits for services to be available

set -euo pipefail

TIMEOUT=300  # 5 minutes total timeout
INTERVAL=5   # Check every 5 seconds

echo "=========================================="
echo "Waiting for Services to be Ready"
echo "=========================================="

# Function to wait for HTTP endpoint
wait_for_http() {
    local url=$1
    local service_name=$2
    local elapsed=0

    echo -n "Waiting for $service_name at $url "

    while [ $elapsed -lt $TIMEOUT ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo " ✓ Ready (${elapsed}s)"
            return 0
        fi
        echo -n "."
        sleep $INTERVAL
        elapsed=$((elapsed + INTERVAL))
    done

    echo " ✗ Timeout after ${TIMEOUT}s"
    return 1
}

# Function to wait for PostgreSQL
wait_for_postgres() {
    local host=$1
    local port=$2
    local user=$3
    local db=$4
    local service_name=$5
    local elapsed=0

    echo -n "Waiting for $service_name "

    while [ $elapsed -lt $TIMEOUT ]; do
        if pg_isready -h "$host" -p "$port" -U "$user" -d "$db" > /dev/null 2>&1; then
            echo " ✓ Ready (${elapsed}s)"
            return 0
        fi
        # Fallback to docker exec if pg_isready not available on host
        if docker exec postgres-acapy pg_isready -U "$user" -d "$db" > /dev/null 2>&1; then
            echo " ✓ Ready (${elapsed}s)"
            return 0
        fi
        echo -n "."
        sleep $INTERVAL
        elapsed=$((elapsed + INTERVAL))
    done

    echo " ✗ Timeout after ${TIMEOUT}s"
    return 1
}

# Array to track failures
declare -a failed_services=()

echo ""
echo "1. Checking cheqd-node network..."
echo "------------------------------"

if ! wait_for_http "http://localhost:26657/health" "cheqd-validator-0 RPC"; then
    failed_services+=("cheqd-validator-0")
fi

if ! wait_for_http "http://localhost:1317/cosmos/base/tendermint/v1beta1/node_info" "cheqd-validator-0 REST API"; then
    failed_services+=("cheqd-rest-api")
fi

echo ""
echo "2. Checking DID services..."
echo "------------------------------"

if ! wait_for_http "http://localhost:8080/1.0/identifiers/did:cheqd:testnet:zF7rhDBfUt9d1gJPjx7s1J" "DID Resolver"; then
    failed_services+=("did-resolver")
fi

if ! wait_for_http "http://localhost:9080/1.0/methods" "DID Registrar"; then
    failed_services+=("did-registrar")
fi

echo ""
echo "3. Checking PostgreSQL database..."
echo "------------------------------"

if ! wait_for_postgres "localhost" "5432" "acapy" "acapy_wallets" "PostgreSQL"; then
    failed_services+=("postgres")
fi

echo ""
echo "4. Checking ACA-Py agents..."
echo "------------------------------"

if ! wait_for_http "http://localhost:8021/status/ready" "ACA-Py Issuer"; then
    failed_services+=("acapy-issuer")
fi

if ! wait_for_http "http://localhost:8031/status/ready" "ACA-Py Holder"; then
    failed_services+=("acapy-holder")
fi

if ! wait_for_http "http://localhost:8041/status/ready" "ACA-Py Verifier"; then
    failed_services+=("acapy-verifier")
fi

echo ""
echo "=========================================="

# Check if any services failed
if [ ${#failed_services[@]} -eq 0 ]; then
    echo "✓ All Services Ready"
    echo "=========================================="
    echo ""
    echo "Service Endpoints:"
    echo "  cheqd-node RPC:      http://localhost:26657"
    echo "  cheqd-node REST:     http://localhost:1317"
    echo "  DID Resolver:        http://localhost:8080"
    echo "  DID Registrar:       http://localhost:9080"
    echo "  PostgreSQL:          localhost:5432"
    echo "  ACA-Py Issuer:       http://localhost:8021"
    echo "  ACA-Py Holder:       http://localhost:8031"
    echo "  ACA-Py Verifier:     http://localhost:8041"
    echo ""
    echo "You can now run the Jupyter notebook!"
    echo "  jupyter notebook ssi_workflow_cheqd.ipynb"
    echo ""
    exit 0
else
    echo "✗ Some Services Failed to Start"
    echo "=========================================="
    echo ""
    echo "Failed services:"
    for service in "${failed_services[@]}"; do
        echo "  • $service"
    done
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check logs: docker-compose -f docker-compose-cheqd-acapy.yml logs [service]"
    echo "  2. Check status: docker-compose -f docker-compose-cheqd-acapy.yml ps"
    echo "  3. Restart services: docker-compose -f docker-compose-cheqd-acapy.yml restart"
    echo ""
    exit 1
fi
