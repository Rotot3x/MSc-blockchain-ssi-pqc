#!/bin/bash
# Initialize ACA-Py agents with DIDs on cheqd ledger
# This script creates DIDs for each agent using the cheqd DID method

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "ACA-Py Agent Initialization"
echo "=========================================="

# Agent endpoints
ISSUER_ADMIN="http://localhost:8021"
HOLDER_ADMIN="http://localhost:8031"
VERIFIER_ADMIN="http://localhost:8041"

# Function to create DID on cheqd for an agent
create_did_cheqd() {
    local admin_url=$1
    local agent_name=$2

    echo ""
    echo "Creating did:cheqd for $agent_name..."
    echo "------------------------------"

    # Create DID with PQC key type
    local response=$(curl -s -X POST "${admin_url}/did/cheqd/create" \
        -H "Content-Type: application/json" \
        -d '{
            "options": {
                "network": "testnet",
                "methodSpecificIdAlgo": "uuid",
                "verificationMethod": [{
                    "type": "ML-DSA-65-2024",
                    "purposes": ["authentication", "assertionMethod", "capabilityInvocation"]
                }],
                "service": []
            }
        }')

    # Extract DID from response
    local did=$(echo "$response" | jq -r '.did // .result.did // empty')

    if [ -z "$did" ] || [ "$did" == "null" ]; then
        echo "⚠ Failed to create did:cheqd, falling back to did:key..."

        # Fallback to did:key with Ed25519
        response=$(curl -s -X POST "${admin_url}/wallet/did/create" \
            -H "Content-Type: application/json" \
            -d '{
                "method": "key",
                "options": {
                    "key_type": "ed25519"
                }
            }')

        did=$(echo "$response" | jq -r '.result.did // .did // empty')
    fi

    if [ -n "$did" ] && [ "$did" != "null" ]; then
        echo "✓ Created DID: $did"

        # Set as public DID
        curl -s -X POST "${admin_url}/wallet/did/public" \
            -H "Content-Type: application/json" \
            -d "{\"did\": \"$did\"}" > /dev/null 2>&1 || true

        echo "✓ Set as public DID"

        # Return DID
        echo "$did"
    else
        echo "✗ Failed to create DID for $agent_name"
        return 1
    fi
}

# Function to check agent status
check_agent_status() {
    local admin_url=$1
    local agent_name=$2

    echo -n "Checking $agent_name status... "

    local status=$(curl -sf "${admin_url}/status/ready" || echo "FAILED")

    if [ "$status" != "FAILED" ]; then
        echo "✓ Ready"
        return 0
    else
        echo "✗ Not ready"
        return 1
    fi
}

echo ""
echo "1. Checking agent availability..."
echo "------------------------------"

check_agent_status "$ISSUER_ADMIN" "Issuer" || {
    echo "✗ Issuer agent not available"
    exit 1
}

check_agent_status "$HOLDER_ADMIN" "Holder" || {
    echo "✗ Holder agent not available"
    exit 1
}

check_agent_status "$VERIFIER_ADMIN" "Verifier" || {
    echo "✗ Verifier agent not available"
    exit 1
}

echo ""
echo "2. Creating DIDs for agents..."
echo "------------------------------"

# Create DIDs for each agent
ISSUER_DID=$(create_did_cheqd "$ISSUER_ADMIN" "Issuer")
HOLDER_DID=$(create_did_cheqd "$HOLDER_ADMIN" "Holder")
VERIFIER_DID=$(create_did_cheqd "$VERIFIER_ADMIN" "Verifier")

echo ""
echo "=========================================="
echo "Agent Initialization Complete"
echo "=========================================="
echo ""
echo "Agent DIDs:"
echo "  Issuer:   $ISSUER_DID"
echo "  Holder:   $HOLDER_DID"
echo "  Verifier: $VERIFIER_DID"
echo ""
echo "These DIDs are now ready to use in the SSI workflow!"
echo ""
echo "Next steps:"
echo "  1. Run the Jupyter notebook: jupyter notebook ssi_workflow_cheqd.ipynb"
echo "  2. Or use the DIDs directly via Admin API"
echo ""

# Save DIDs to a file for reference
cat > "$SCRIPT_DIR/../.agent-dids" <<EOF
ISSUER_DID=$ISSUER_DID
HOLDER_DID=$HOLDER_DID
VERIFIER_DID=$VERIFIER_DID
EOF

echo "Agent DIDs saved to: .agent-dids"
echo ""
