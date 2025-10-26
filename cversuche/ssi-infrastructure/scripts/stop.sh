#!/bin/bash

# SSI Infrastructure Stop Script
# Gracefully stops the complete cheqd + ACA-Py infrastructure
# Updated for Docker Compose structure with fixed IPs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[STOP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_network() {
    echo -e "${MAGENTA}[NETWORK]${NC} $1"
}

# Detect Docker Compose command
detect_docker_compose() {
    if command -v docker compose &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
    else
        DOCKER_COMPOSE="docker-compose"
    fi
    print_info "Using Docker Compose command: $DOCKER_COMPOSE"
}

# Show running services before stopping
show_running_services() {
    print_status "Currently running services:"
    $DOCKER_COMPOSE ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}"
    echo ""
}

# Gracefully stop services in reverse order
stop_infrastructure_graceful() {
    print_status "Gracefully stopping SSI Infrastructure..."
    print_info "Services will be stopped in reverse dependency order"
    echo ""

    # Stage 1: Stop utility services first
    print_status "Stage 1: Stopping utility services..."
    $DOCKER_COMPOSE stop jupyter
    sleep 2

    # Stage 2: Stop ACA-Py agents
    print_status "Stage 2: Stopping ACA-Py agents..."
    $DOCKER_COMPOSE stop acapy-verifier acapy-holder acapy-issuer
    sleep 3

    # Stage 3: Stop DID services
    print_status "Stage 3: Stopping DID services..."
    $DOCKER_COMPOSE stop did-registrar did-resolver
    sleep 2

    # Stage 4: Stop cheqd blockchain network
    print_status "Stage 4: Stopping cheqd blockchain network..."
    $DOCKER_COMPOSE stop observer-0 seed-0 validator-3 validator-2 validator-1 validator-0
    sleep 3

    # Stage 5: Stop database services last
    print_status "Stage 5: Stopping database services..."
    $DOCKER_COMPOSE stop postgres-acapy
    sleep 2

    print_success "All services stopped gracefully"
}

# Quick stop all services
stop_infrastructure_quick() {
    print_status "Quickly stopping all SSI Infrastructure services..."

    $DOCKER_COMPOSE down

    if [ $? -eq 0 ]; then
        print_success "Infrastructure stopped successfully!"
    else
        print_error "Failed to stop infrastructure"
        exit 1
    fi
}

# Clean up volumes and data
cleanup_volumes() {
    print_warning "⚠️  DESTRUCTIVE OPERATION: Removing all volumes and data"
    print_warning "This will permanently delete:"
    echo "  • All cheqd blockchain data and keys"
    echo "  • All ACA-Py agent wallets and credentials"
    echo "  • All PostgreSQL databases"
    echo "  • All Jupyter notebook data"
    echo "  • All log files"
    echo ""

    read -p "Type 'DELETE' to confirm complete data removal: " -r
    echo

    if [ "$REPLY" = "DELETE" ]; then
        print_status "Removing all containers, volumes, and data..."
        $DOCKER_COMPOSE down -v --remove-orphans

        # Also remove any persistent data directories
        if [ -d "data" ]; then
            print_status "Removing data directories..."
            rm -rf data/*
        fi

        # Clean up logs
        if [ -d "logs" ]; then
            print_status "Cleaning log files..."
            find logs -name "*.log" -delete 2>/dev/null || true
        fi

        print_success "Complete cleanup finished - all data removed"
    else
        print_info "Cleanup cancelled - data preserved"
        return 1
    fi
}

# Remove only containers (preserve data)
cleanup_containers() {
    print_status "Removing containers while preserving data..."
    $DOCKER_COMPOSE down --remove-orphans
    print_success "Containers removed, data volumes preserved"
}

# Remove unused networks
cleanup_networks() {
    print_status "Cleaning up unused networks..."

    # Remove the ssi-network if it exists and has no running containers
    if docker network ls --format "{{.Name}}" | grep -q "ssi-network"; then
        if docker network inspect ssi-network --format "{{len .Containers}}" 2>/dev/null | grep -q "^0$"; then
            docker network rm ssi-network >/dev/null 2>&1 && print_success "Removed ssi-network" || print_info "Network ssi-network still in use"
        else
            print_info "Network ssi-network has active containers, skipping removal"
        fi
    fi

    # Prune unused networks
    docker network prune -f >/dev/null 2>&1 && print_success "Unused networks pruned" || true
}

# Show service status for verification
show_final_status() {
    print_info "Final service status:"

    local running_containers
    running_containers=$($DOCKER_COMPOSE ps -q 2>/dev/null | wc -l)

    if [ "$running_containers" -eq 0 ]; then
        print_success "✓ No containers running"
    else
        print_warning "⚠ Some containers may still be running:"
        $DOCKER_COMPOSE ps
    fi

    echo ""
}

# Show usage
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Stop SSI Infrastructure with various cleanup options"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -q, --quick          Quick stop (docker-compose down)"
    echo "  -g, --graceful       Graceful stop in reverse dependency order (default)"
    echo "  -c, --cleanup        Remove containers only (preserve data)"
    echo "  -C, --cleanup-all    Remove everything including data (DESTRUCTIVE)"
    echo "  -n, --networks       Clean up unused networks"
    echo "  -s, --status         Show current status without stopping"
    echo ""
    echo "Examples:"
    echo "  $0                   # Graceful stop"
    echo "  $0 --quick          # Quick stop"
    echo "  $0 --cleanup        # Stop and remove containers"
    echo "  $0 --cleanup-all    # DESTRUCTIVE: Remove everything"
    echo ""
}

# Main execution
main() {
    echo ""
    echo "================================================"
    echo "     SSI Infrastructure Stop Script v2.0"
    echo "================================================"
    echo ""

    detect_docker_compose

    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -s|--status)
            show_running_services
            exit 0
            ;;
        -q|--quick)
            show_running_services
            stop_infrastructure_quick
            show_final_status
            ;;
        -g|--graceful|"")
            show_running_services
            stop_infrastructure_graceful
            show_final_status
            ;;
        -c|--cleanup)
            show_running_services
            stop_infrastructure_graceful
            cleanup_containers
            show_final_status
            ;;
        -C|--cleanup-all)
            show_running_services
            if cleanup_volumes; then
                cleanup_networks
            fi
            show_final_status
            ;;
        -n|--networks)
            cleanup_networks
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac

    echo ""
    echo "✅ Stop operation completed successfully!"
    echo ""
    echo "📋 Next steps:"
    echo "  Start again:     ./scripts/start.sh"
    echo "  Check status:    ./scripts/status.sh"
    echo "  Full cleanup:    ./scripts/stop.sh --cleanup-all"
    echo ""
}

# Run main function
main "$@"