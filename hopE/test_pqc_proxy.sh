#!/bin/bash
# Test Script für PQC Nginx Reverse Proxy

echo "================================"
echo "PQC Nginx Reverse Proxy Test"
echo "================================"
echo ""

# Farben
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Check if von-webserver-proxy is running
echo "1. Checking if PQC proxy container is running..."
if docker ps | grep -q "von-webserver-pqc-proxy"; then
    echo -e "${GREEN}✓ Container is running${NC}"
else
    echo -e "${RED}✗ Container is NOT running${NC}"
    echo "   Start with: docker-compose up -d von-webserver-proxy"
    exit 1
fi

# 2. Check container health
echo ""
echo "2. Checking container health..."
HEALTH=$(docker inspect --format='{{.State.Health.Status}}' von-webserver-pqc-proxy 2>/dev/null)
if [ "$HEALTH" = "healthy" ]; then
    echo -e "${GREEN}✓ Container is healthy${NC}"
elif [ "$HEALTH" = "starting" ]; then
    echo -e "${YELLOW}⚠ Container is starting (wait a moment)${NC}"
else
    echo -e "${RED}✗ Container health: $HEALTH${NC}"
fi

# 3. Test health endpoint
echo ""
echo "3. Testing health endpoint..."
if curl -k -s -f https://localhost:4433/health > /dev/null 2>&1; then
    RESPONSE=$(curl -k -s https://localhost:4433/health)
    echo -e "${GREEN}✓ Health endpoint responding: $RESPONSE${NC}"
else
    echo -e "${RED}✗ Health endpoint not responding${NC}"
fi

# 4. Test genesis endpoint (if von-network is running)
echo ""
echo "4. Testing genesis endpoint..."
if curl -k -s -f https://localhost:4433/genesis > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Genesis endpoint responding${NC}"
    # Show first line of genesis
    FIRST_LINE=$(curl -k -s https://localhost:4433/genesis | head -1)
    echo "   First line: ${FIRST_LINE:0:60}..."
else
    echo -e "${YELLOW}⚠ Genesis endpoint not responding (von-network running?)${NC}"
fi

# 5. Check SSL/TLS configuration
echo ""
echo "5. Checking PQC configuration..."
echo "   Checking with OQS curl (if available)..."
if docker run --rm --network host openquantumsafe/curl curl -v https://localhost:4433/health 2>&1 | grep -q "SSL connection"; then
    echo -e "${GREEN}✓ PQC SSL connection successful${NC}"

    # Extract KEM algorithm used
    KEM=$(docker run --rm --network host openquantumsafe/curl curl -v https://localhost:4433/health 2>&1 | grep -i "kem\|group" | head -1)
    if [ ! -z "$KEM" ]; then
        echo "   KEM Algorithm: $KEM"
    fi
else
    echo -e "${YELLOW}⚠ Could not test with OQS curl${NC}"
fi

# 6. Show recent logs
echo ""
echo "6. Recent nginx logs (last 5 lines)..."
docker exec von-webserver-pqc-proxy tail -5 /opt/nginx/logs/access.log 2>/dev/null || echo -e "${YELLOW}   (No logs yet)${NC}"

# 7. Environment check
echo ""
echo "7. PQC Configuration..."
DEFAULT_GROUPS=$(docker inspect von-webserver-pqc-proxy | grep -A1 DEFAULT_GROUPS | tail -1 | sed 's/.*"\(.*\)".*/\1/')
echo "   DEFAULT_GROUPS: ${DEFAULT_GROUPS}"

# Summary
echo ""
echo "================================"
echo "Summary:"
echo "   PQC HTTPS: https://localhost:4433"
echo "   Health: https://localhost:4433/health"
echo "   Genesis: https://localhost:4433/genesis"
echo "   Backend: webserver:8000 (VON Network)"
echo "   PQC Algorithms: ML-KEM-768, x25519, ML-KEM-1024"
echo "================================"
echo ""
echo -e "${YELLOW}Note: Browser will show SSL warning (self-signed cert)${NC}"
echo ""
