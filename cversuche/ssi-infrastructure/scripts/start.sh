#!/bin/bash

# SSI Infrastructure Startup Script
# Starts the complete cheqd + ACA-Py infrastructure with fixed IPs
# Updated for Docker Compose structure without build-services

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
    echo -e "${BLUE}[START]${NC} $1"
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

# Check if Docker and Docker Compose are installed
check_dependencies() {
    print_status "Checking dependencies..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null && ! command -v docker compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    print_success "Dependencies check passed"
}

# Validate configuration files
validate_configuration() {
    print_status "Validating configuration files..."

    # Check if docker-compose.yml exists
    if [ ! -f "docker-compose.yml" ]; then
        print_error "docker-compose.yml not found in current directory"
        echo "Please run this script from the ssi-infrastructure directory"
        exit 1
    fi

    # Check if .env file exists
    if [ ! -f ".env" ]; then
        print_error ".env file not found"
        echo "Please run './scripts/setup.sh' first to create the environment configuration"
        exit 1
    fi

    # Validate docker-compose syntax
    if $DOCKER_COMPOSE config > /dev/null 2>&1; then
        print_success "Docker Compose configuration is valid ✓"
    else
        print_error "Docker Compose configuration has syntax errors"
        echo "Running '$DOCKER_COMPOSE config' for details:"
        $DOCKER_COMPOSE config
        exit 1
    fi

    print_success "Configuration validation completed"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."

    # Create logs directory with subdirectories
    mkdir -p logs/{cheqd,acapy,ssi-services}

    # Create data directories if they don't exist
    mkdir -p data/{cheqd,postgres,jupyter}

    # Set permissions
    chmod 755 logs data 2>/dev/null || true
    chmod -R 755 logs/* 2>/dev/null || true

    print_success "Directory structure created"
}

# Load environment variables
load_environment() {
    print_status "Loading environment variables..."
    if [ -f .env ]; then
        source .env
        print_success "Environment variables loaded"
    else
        print_error ".env file not found"
        echo "Please run './scripts/setup.sh' first"
        exit 1
    fi
}

# Validate network configuration
validate_network_config() {
    print_network "Validating network configuration..."

    # Check if the network subnet conflicts with existing networks
    if docker network ls --format "{{.Name}}" | grep -q "ssi-network"; then
        print_info "ssi-network already exists, will be recreated if needed"
    fi

    print_network "Fixed IP schema will be applied:"
    echo "  📡 cheqd Validators: 172.20.1.10-13 + 172.20.1.20 + 172.20.1.30"
    echo "  🔗 SSI Services: 172.20.2.10-30"
    echo "  🗄️  Database: 172.20.3.10"
    echo "  🤖 ACA-Py Agents: 172.20.4.10-30"
    echo "  📓 Jupyter: 172.20.5.10"
}

# Check if required images exist
check_required_images() {
    print_status "Checking required Docker images..."

    local missing_images=()

    # Check if cheqd-extended image exists
    if ! docker images cheqd-extended:latest --format "{{.Repository}}" | grep -q "cheqd-extended"; then
        missing_images+=("cheqd-extended")
    fi

    if [ ${#missing_images[@]} -gt 0 ]; then
        print_warning "Missing local images: ${missing_images[*]}"
        print_info "Building missing images automatically..."

        # Build only the required images
        for image in "${missing_images[@]}"; do
            case $image in
                "cheqd-extended")
                    print_status "Building cheqd-extended image..."
                    $DOCKER_COMPOSE build cheqd-extended
                    if [ $? -ne 0 ]; then
                        print_error "Failed to build $image"
                        exit 1
                    fi
                    ;;
            esac
        done

        print_success "Required images built successfully"
    else
        print_success "All required local images are available ✓"
    fi
}

# Import cheqd keys
import_keys() {
    print_status "Importing cheqd validator and test account keys..."

    if [ -f "./import-keys.sh" ]; then
        chmod +x ./import-keys.sh
        ./import-keys.sh
        if [ $? -eq 0 ]; then
            print_success "Keys imported successfully"
        else
            print_warning "Key import failed, but continuing..."
        fi
    else
        print_info "import-keys.sh not found, skipping key import"
    fi
}

# Start the infrastructure with staged approach
start_infrastructure() {
    print_status "Starting SSI Infrastructure with fixed IP addresses..."
    print_info "Service composition:"
    echo "  📡 cheqd Network: 6 nodes (validators, seed, observer)"
    echo "  🤖 ACA-Py Agents: 3 agents (issuer, holder, verifier)"
    echo "  🗄️  Database: PostgreSQL for agents"
    echo "  🔗 DID Services: Resolver & Registrar"
    echo "  📓 Jupyter Labs: Interactive workflows"
    echo ""

    # Import keys first
    import_keys

    # Stage 1: Start core infrastructure (database)
    print_status "Stage 1: Starting database services..."
    $DOCKER_COMPOSE up -d postgres-acapy

    if [ $? -ne 0 ]; then
        print_error "Failed to start database services"
        exit 1
    fi

    print_info "Waiting for database to initialize..."
    sleep 10

    # Stage 2: Start cheqd network nodes
    print_status "Stage 2: Starting cheqd blockchain network..."
    $DOCKER_COMPOSE up -d validator-0 validator-1 validator-2 validator-3 seed-0 observer-0

    if [ $? -ne 0 ]; then
        print_error "Failed to start cheqd network"
        exit 1
    fi

    print_info "Waiting for cheqd network to stabilize..."
    sleep 20

    # Stage 3: Start DID services
    print_status "Stage 3: Starting DID services..."
    $DOCKER_COMPOSE up -d did-resolver did-registrar

    if [ $? -ne 0 ]; then
        print_error "Failed to start DID services"
        exit 1
    fi

    print_info "Waiting for DID services to initialize..."
    sleep 10

    # Stage 4: Start ACA-Py agents
    print_status "Stage 4: Starting ACA-Py agents..."
    $DOCKER_COMPOSE up -d acapy-issuer acapy-holder acapy-verifier

    if [ $? -ne 0 ]; then
        print_error "Failed to start ACA-Py agents"
        exit 1
    fi

    # Stage 5: Start remaining services
    print_status "Stage 5: Starting remaining services..."
    $DOCKER_COMPOSE up -d jupyter

    if [ $? -eq 0 ]; then
        print_success "Infrastructure started successfully!"
    else
        print_error "Failed to start remaining services"
        exit 1
    fi
}

# Wait for services to be healthy
wait_for_services() {
    print_status "Waiting for services to become healthy..."

    # List of critical services to check
    local critical_services=(
        "postgres-acapy"
        "validator-0"
        "did-resolver"
        "acapy-issuer"
    )

    # List of all services to monitor
    local all_services=(
        "postgres-acapy"
        "validator-0"
        "validator-1"
        "validator-2"
        "validator-3"
        "seed-0"
        "observer-0"
        "did-resolver"
        "did-registrar"
        "acapy-issuer"
        "acapy-holder"
        "acapy-verifier"
        "jupyter"
    )

    max_attempts=60
    attempt=0

    print_info "Monitoring critical services first..."

    while [ $attempt -lt $max_attempts ]; do
        critical_healthy=true

        for service in "${critical_services[@]}"; do
            if ! docker inspect --format="{{.State.Health.Status}}" "${COMPOSE_PROJECT_NAME:-ssi-infrastructure}-${service}-1" 2>/dev/null | grep -q "healthy"; then
                critical_healthy=false
                break
            fi
        done

        if [ "$critical_healthy" = true ]; then
            print_success "Critical services are healthy!"
            break
        fi

        attempt=$((attempt + 1))
        print_info "Waiting for critical services... ($attempt/$max_attempts)"
        sleep 5
    done

    if [ $attempt -eq $max_attempts ]; then
        print_warning "Some critical services may not be fully healthy yet"
    fi

    # Quick check of all services
    print_info "Checking all service status..."
    local unhealthy_services=()

    for service in "${all_services[@]}"; do
        container_name="${COMPOSE_PROJECT_NAME:-ssi-infrastructure}-${service}-1"
        if ! docker inspect --format="{{.State.Health.Status}}" "$container_name" 2>/dev/null | grep -q "healthy"; then
            if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
                unhealthy_services+=("$service")
            fi
        fi
    done

    if [ ${#unhealthy_services[@]} -eq 0 ]; then
        print_success "All running services are healthy! ✓"
    else
        print_warning "Services still initializing: ${unhealthy_services[*]}"
        print_info "Use './scripts/status.sh' to monitor progress"
    fi
}

# Display service URLs and network information
show_service_urls() {
    print_success "SSI Infrastructure is ready!"
    echo ""
    echo "🌐 Network Information:"
    echo "============================="
    echo "Network: ssi-network (172.20.0.0/16)"
    echo "All services have fixed IP addresses for stable communication"
    echo ""
    echo "🔗 External Service URLs:"
    echo "========================="
    echo "DID Resolver:              http://localhost:8080"
    echo "DID Registrar:             http://localhost:9080"
    echo "Jupyter Labs:              http://localhost:8888"
    echo "  Token: ${JUPYTER_TOKEN:-check .env file}"
    echo ""
    echo "📡 cheqd Blockchain Network:"
    echo "============================"
    echo "Validator 0 RPC:           http://localhost:26657"
    echo "Validator 0 REST:          http://localhost:1317"
    echo "Validator 0 gRPC:          localhost:9090"
    echo ""
    echo "🤖 ACA-Py Agent Admin APIs:"
    echo "============================"
    echo "Issuer Admin API:          http://localhost:8021"
    echo "Holder Admin API:          http://localhost:8031"
    echo "Verifier Admin API:        http://localhost:8041"
    echo ""
    echo "🗄️  Database Access:"
    echo "==================="
    echo "ACA-Py PostgreSQL:         localhost:5432"
    echo "  Database: acapy"
    echo "  Username: acapy"
    echo "  Password: ${ACAPY_DB_PASSWORD:-check .env file}"
    echo ""
    echo "⚡ Management Commands:"
    echo "======================"
    echo "Monitor:  ./scripts/status.sh"
    echo "Stop:     ./scripts/stop.sh"
    echo "Logs:     $DOCKER_COMPOSE logs -f [service-name]"
    echo "Status:   $DOCKER_COMPOSE ps"
    echo ""
    echo "📚 Quick Start:"
    echo "==============="
    echo "1. Open Jupyter Labs: http://localhost:8888"
    echo "2. Run the SSI workflow notebook"
    echo "3. Test DID operations via API endpoints"
    echo "4. Monitor with: ./scripts/status.sh"
}

# Show startup options
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Start SSI Infrastructure with fixed IP addresses"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -q, --quick      Quick start (skip health checks)"
    echo "  -v, --verbose    Verbose output"
    echo ""
    echo "The infrastructure includes:"
    echo "  • 6 cheqd blockchain nodes with fixed IPs"
    echo "  • 3 ACA-Py agents (issuer, holder, verifier)"
    echo "  • DID resolver & registrar services"
    echo "  • PostgreSQL database for agents"
    echo "  • Jupyter Labs for workflow demos"
    echo ""
}

# Main execution
main() {
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -q|--quick)
            QUICK_START=true
            ;;
        -v|--verbose)
            VERBOSE=true
            set -x
            ;;
    esac

    echo ""
    echo "================================================"
    echo "    SSI Infrastructure Startup Script v2.0"
    echo "================================================"
    echo ""

    detect_docker_compose
    check_dependencies
    validate_configuration
    create_directories
    load_environment
    validate_network_config
    check_required_images
    start_infrastructure

    if [ "${QUICK_START:-false}" != "true" ]; then
        wait_for_services
    else
        print_info "Quick start mode: skipping health checks"
    fi

    show_service_urls

    echo ""
    echo "✅ Infrastructure startup completed successfully!"
    echo "🚀 Ready for SSI operations"
    echo "📊 Monitor status: ./scripts/status.sh"
    echo ""
}

# Run main function
main "$@"