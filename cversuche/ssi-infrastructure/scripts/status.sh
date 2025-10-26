#!/bin/bash

# SSI Infrastructure Status Script
# Comprehensive monitoring and health checking for the SSI infrastructure
# Shows detailed status of all services with fixed IP addresses

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[STATUS]${NC} $1"
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

print_header() {
    echo -e "${BOLD}${BLUE}$1${NC}"
}

# Detect Docker Compose command
detect_docker_compose() {
    if command -v docker compose &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
    else
        DOCKER_COMPOSE="docker-compose"
    fi
}

# Get container health status with emoji
get_health_status() {
    local container_name="$1"
    local health_status

    if ! docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        echo "❌ Not Running"
        return
    fi

    health_status=$(docker inspect --format="{{.State.Health.Status}}" "$container_name" 2>/dev/null || echo "unknown")

    case "$health_status" in
        "healthy")
            echo "✅ Healthy"
            ;;
        "unhealthy")
            echo "❌ Unhealthy"
            ;;
        "starting")
            echo "🔄 Starting"
            ;;
        "none"|"unknown")
            # No health check defined, check if running
            local state=$(docker inspect --format="{{.State.Status}}" "$container_name" 2>/dev/null || echo "unknown")
            if [ "$state" = "running" ]; then
                echo "🟢 Running"
            else
                echo "🔴 Stopped"
            fi
            ;;
        *)
            echo "⚪ Unknown"
            ;;
    esac
}

# Get container IP address
get_container_ip() {
    local container_name="$1"
    docker inspect --format="{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "$container_name" 2>/dev/null || echo "N/A"
}

# Get container uptime
get_container_uptime() {
    local container_name="$1"
    if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        docker ps --format "{{.Status}}" --filter "name=^${container_name}$" | head -1
    else
        echo "Not running"
    fi
}

# Show individual service status
show_service_status() {
    local service_name="$1"
    local container_name="${COMPOSE_PROJECT_NAME:-ssi-infrastructure}-${service_name}-1"
    local expected_ip="$2"
    local health_status ip_address uptime

    health_status=$(get_health_status "$container_name")
    ip_address=$(get_container_ip "$container_name")
    uptime=$(get_container_uptime "$container_name")

    printf "%-20s %-15s %-15s %-15s %s\n" \
        "$service_name" \
        "$health_status" \
        "${ip_address:-N/A}" \
        "${expected_ip:-N/A}" \
        "$uptime"
}

# Show comprehensive service overview
show_service_overview() {
    print_header "🔍 Service Status Overview"
    echo "================================================================="
    printf "%-20s %-15s %-15s %-15s %s\n" \
        "Service" "Status" "Current IP" "Expected IP" "Uptime"
    echo "================================================================="

    # Database Services
    show_service_status "postgres-acapy" "172.20.3.10"

    echo "-----------------------------------------------------------------"

    # cheqd Blockchain Network
    show_service_status "validator-0" "172.20.1.10"
    show_service_status "validator-1" "172.20.1.11"
    show_service_status "validator-2" "172.20.1.12"
    show_service_status "validator-3" "172.20.1.13"
    show_service_status "seed-0" "172.20.1.20"
    show_service_status "observer-0" "172.20.1.30"

    echo "-----------------------------------------------------------------"

    # DID Services
    show_service_status "did-resolver" "172.20.2.10"
    show_service_status "did-registrar" "172.20.2.20"

    echo "-----------------------------------------------------------------"

    # ACA-Py Agents
    show_service_status "acapy-issuer" "172.20.4.10"
    show_service_status "acapy-holder" "172.20.4.20"
    show_service_status "acapy-verifier" "172.20.4.30"

    echo "-----------------------------------------------------------------"

    # Utility Services
    show_service_status "jupyter" "172.20.5.10"

    echo "================================================================="
    echo ""
}

# Show network information
show_network_info() {
    print_header "🌐 Network Information"
    echo "================================"

    # Check if ssi-network exists
    if docker network ls --format "{{.Name}}" | grep -q "ssi-network"; then
        print_success "ssi-network exists"

        # Show network details
        local subnet gateway
        subnet=$(docker network inspect ssi-network --format "{{range .IPAM.Config}}{{.Subnet}}{{end}}" 2>/dev/null || echo "Unknown")
        gateway=$(docker network inspect ssi-network --format "{{range .IPAM.Config}}{{.Gateway}}{{end}}" 2>/dev/null || echo "Unknown")

        echo "Subnet: $subnet"
        echo "Gateway: $gateway"

        # Count connected containers
        local connected_containers
        connected_containers=$(docker network inspect ssi-network --format "{{len .Containers}}" 2>/dev/null || echo "0")
        echo "Connected containers: $connected_containers"
    else
        print_error "ssi-network not found"
    fi
    echo ""
}

# Show quick health summary
show_health_summary() {
    print_header "📊 Health Summary"
    echo "========================"

    local services=(
        "postgres-acapy"
        "validator-0" "validator-1" "validator-2" "validator-3" "seed-0" "observer-0"
        "did-resolver" "did-registrar"
        "acapy-issuer" "acapy-holder" "acapy-verifier"
        "jupyter"
    )

    local total_services=${#services[@]}
    local healthy_services=0
    local running_services=0
    local failed_services=()

    for service in "${services[@]}"; do
        local container_name="${COMPOSE_PROJECT_NAME:-ssi-infrastructure}-${service}-1"
        local health_status

        if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
            running_services=$((running_services + 1))

            health_status=$(docker inspect --format="{{.State.Health.Status}}" "$container_name" 2>/dev/null || echo "none")
            if [ "$health_status" = "healthy" ] || [ "$health_status" = "none" ]; then
                healthy_services=$((healthy_services + 1))
            else
                failed_services+=("$service")
            fi
        else
            failed_services+=("$service")
        fi
    done

    echo "Total services: $total_services"
    echo "Running services: $running_services"
    echo "Healthy services: $healthy_services"

    if [ ${#failed_services[@]} -gt 0 ]; then
        echo "Failed/Unhealthy services: ${failed_services[*]}"
    fi

    # Show overall status
    if [ $healthy_services -eq $total_services ]; then
        print_success "All services are healthy! ✅"
    elif [ $running_services -eq 0 ]; then
        print_error "No services are running ❌"
    else
        print_warning "Some services need attention ⚠️"
    fi
    echo ""
}

# Show resource usage
show_resource_usage() {
    print_header "💻 Resource Usage"
    echo "========================"

    # Get Docker stats for running containers
    local stats_output
    if stats_output=$(timeout 3s docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null); then
        echo "$stats_output" | grep -E "(NAME|ssi-infrastructure)" || echo "No SSI containers found in stats"
    else
        print_warning "Could not retrieve resource statistics"
    fi
    echo ""
}

# Show external connectivity
show_external_connectivity() {
    print_header "🌍 External Connectivity"
    echo "==============================="

    local endpoints=(
        "DID Resolver:http://localhost:8080/health:did-resolver"
        "DID Registrar:http://localhost:9080/health:did-registrar"
        "Jupyter Labs:http://localhost:8888:jupyter"
        "cheqd RPC:http://localhost:26657/status:validator-0"
        "cheqd REST:http://localhost:1317/cosmos/base/tendermint/v1beta1/node_info:validator-0"
        "ACA-Py Issuer:http://localhost:8021/status/ready:acapy-issuer"
        "ACA-Py Holder:http://localhost:8031/status/ready:acapy-holder"
        "ACA-Py Verifier:http://localhost:8041/status/ready:acapy-verifier"
    )

    for endpoint in "${endpoints[@]}"; do
        local name url service
        name=$(echo "$endpoint" | cut -d: -f1)
        url=$(echo "$endpoint" | cut -d: -f2-)
        url=$(echo "$url" | sed 's/:/ /' | awk '{print $1":"$2":"$3}')
        service=$(echo "$endpoint" | cut -d: -f4)

        # Check if service is running first
        local container_name="${COMPOSE_PROJECT_NAME:-ssi-infrastructure}-${service}-1"
        if ! docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
            printf "%-20s ❌ Service not running\n" "$name"
            continue
        fi

        # Test connectivity
        if curl -s --max-time 3 "$url" >/dev/null 2>&1; then
            printf "%-20s ✅ Accessible at %s\n" "$name" "$url"
        else
            printf "%-20s ⚠️  Not responding at %s\n" "$name" "$url"
        fi
    done
    echo ""
}

# Show logs for a specific service
show_service_logs() {
    local service="$1"
    local lines="${2:-50}"

    print_header "📋 Recent logs for $service (last $lines lines)"
    echo "=============================================="

    if $DOCKER_COMPOSE logs --tail="$lines" "$service" 2>/dev/null; then
        echo ""
    else
        print_error "Could not retrieve logs for $service"
        echo ""
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [options] [service]"
    echo ""
    echo "Monitor SSI Infrastructure status and health"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -q, --quick          Quick status overview only"
    echo "  -l, --logs <service> Show recent logs for specific service"
    echo "  -n, --network        Show network information only"
    echo "  -r, --resources      Show resource usage only"
    echo "  -c, --connectivity   Show external connectivity only"
    echo "  -w, --watch          Watch mode (refresh every 5 seconds)"
    echo ""
    echo "Services for logs:"
    echo "  postgres-acapy, validator-0, validator-1, validator-2, validator-3"
    echo "  seed-0, observer-0, did-resolver, did-registrar"
    echo "  acapy-issuer, acapy-holder, acapy-verifier, jupyter"
    echo ""
    echo "Examples:"
    echo "  $0                        # Full status report"
    echo "  $0 --quick               # Quick overview"
    echo "  $0 --logs validator-0    # Show validator-0 logs"
    echo "  $0 --watch               # Watch mode"
    echo ""
}

# Watch mode (refresh every 5 seconds)
watch_mode() {
    print_info "Watch mode enabled - refreshing every 5 seconds (Ctrl+C to exit)"
    echo ""

    while true; do
        clear
        echo "🔄 SSI Infrastructure Status ($(date))"
        echo "======================================="
        show_health_summary
        show_service_overview
        echo ""
        print_info "Press Ctrl+C to exit watch mode"
        sleep 5
    done
}

# Main execution
main() {
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -q|--quick)
            detect_docker_compose
            show_health_summary
            ;;
        -l|--logs)
            if [ -z "$2" ]; then
                print_error "Please specify a service name for logs"
                show_usage
                exit 1
            fi
            detect_docker_compose
            show_service_logs "$2" "${3:-50}"
            ;;
        -n|--network)
            detect_docker_compose
            show_network_info
            ;;
        -r|--resources)
            detect_docker_compose
            show_resource_usage
            ;;
        -c|--connectivity)
            detect_docker_compose
            show_external_connectivity
            ;;
        -w|--watch)
            detect_docker_compose
            watch_mode
            ;;
        "")
            # Full status report
            detect_docker_compose

            echo ""
            echo "================================================"
            echo "     SSI Infrastructure Status Report v2.0"
            echo "================================================"
            echo ""

            show_health_summary
            show_service_overview
            show_network_info
            show_external_connectivity
            show_resource_usage

            echo ""
            echo "🔧 Management Commands:"
            echo "======================"
            echo "Start:    ./scripts/start.sh"
            echo "Stop:     ./scripts/stop.sh"
            echo "Logs:     $0 --logs <service-name>"
            echo "Watch:    $0 --watch"
            echo ""
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"