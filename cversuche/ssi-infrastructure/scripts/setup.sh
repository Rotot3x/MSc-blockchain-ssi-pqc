#!/bin/bash

# SSI Infrastructure Setup Script
# Prepares the environment and validates the setup
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
    echo -e "${BLUE}[SETUP]${NC} $1"
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

# Check system requirements
check_system_requirements() {
    print_status "Checking system requirements..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is required but not installed"
        echo "Please install Docker from: https://docs.docker.com/get-docker/"
        exit 1
    fi

    # Check Docker version
    DOCKER_VERSION=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
    DOCKER_MAJOR=$(echo $DOCKER_VERSION | cut -d. -f1)
    DOCKER_MINOR=$(echo $DOCKER_VERSION | cut -d. -f2)

    if [ "$DOCKER_MAJOR" -lt 20 ] || ([ "$DOCKER_MAJOR" -eq 20 ] && [ "$DOCKER_MINOR" -lt 10 ]); then
        print_warning "Docker version $DOCKER_VERSION detected. Version 20.10+ recommended."
    else
        print_success "Docker version $DOCKER_VERSION ✓"
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! command -v docker compose &> /dev/null; then
        print_error "Docker Compose is required but not installed"
        echo "Please install Docker Compose from: https://docs.docker.com/compose/install/"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running"
        echo "Please start Docker and try again"
        exit 1
    fi

    # Check available memory (minimum 4GB recommended)
    if command -v free &> /dev/null; then
        total_mem=$(free -m | awk 'NR==2{printf "%.0f", $2/1024}')
        if [ "$total_mem" -lt 4 ]; then
            print_warning "Only ${total_mem}GB RAM detected. 4GB+ recommended for optimal performance."
        else
            print_success "Memory: ${total_mem}GB ✓"
        fi
    fi

    # Check available disk space (minimum 10GB recommended)
    available_space=$(df -BG . | awk 'NR==2{print $4}' | sed 's/G//')
    if [ "$available_space" -lt 10 ]; then
        print_warning "Only ${available_space}GB disk space available. 10GB+ recommended."
    else
        print_success "Disk space: ${available_space}GB available ✓"
    fi

    print_success "System requirements check completed"
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

    # Check if .env file exists, create if missing
    if [ ! -f ".env" ]; then
        print_warning ".env file not found, creating from template..."
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_info "Created .env from .env.example"
        else
            create_default_env
        fi
    fi

    # Validate docker-compose syntax
    if $DOCKER_COMPOSE config > /dev/null 2>&1; then
        print_success "Docker Compose configuration is valid ✓"
    else
        print_error "Docker Compose configuration has syntax errors"
        echo "Running 'docker-compose config' for details:"
        $DOCKER_COMPOSE config
        exit 1
    fi

    print_success "Configuration validation completed"
}

# Create default .env file
create_default_env() {
    print_status "Creating default .env file..."

    cat > .env << EOF
# SSI Infrastructure Environment Configuration
# ==============================================

# Database Passwords
ACAPY_DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

# Jupyter Configuration
JUPYTER_TOKEN=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

# cheqd Network Configuration
CHEQD_CHAIN_ID=cheqd
CHEQD_NETWORK_NAME=cheqd-localnet

# DID Registrar Configuration
FEE_PAYER_TESTNET_MNEMONIC="sketch mountain erode window enact net enrich smoke claim kangaroo another visual write meat latin bacon pulp similar forum guilt father state erase bright"

# ACA-Py Agent Configuration
ACAPY_LOG_LEVEL=info
ACAPY_WALLET_KEY_DERIVATION_METHOD=ARGON2I_MOD

# Network Configuration
COMPOSE_PROJECT_NAME=ssi-infrastructure
DOCKER_NETWORK_SUBNET=172.20.0.0/16

# Development Settings
DEBUG_MODE=true
AUTO_ACCEPT_CONNECTIONS=true
AUTO_ACCEPT_CREDENTIALS=true
AUTO_VERIFY_PRESENTATIONS=true

# Service URLs (for reference)
CHEQD_RPC_URL=http://localhost:26657
CHEQD_REST_URL=http://localhost:1317
DID_RESOLVER_URL=http://localhost:8080
DID_REGISTRAR_URL=http://localhost:9080
JUPYTER_URL=http://localhost:8888

# Agent Admin URLs
ISSUER_ADMIN_URL=http://localhost:8021
HOLDER_ADMIN_URL=http://localhost:8031
VERIFIER_ADMIN_URL=http://localhost:8041
EOF

    print_success "Default .env file created with secure passwords"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."

    # Create logs directory
    mkdir -p logs/{cheqd,acapy,ssi-services}

    # Create data directories if they don't exist
    mkdir -p data/{cheqd,postgres,jupyter}

    # Create config backup directory
    mkdir -p backups/config

    # Create notebooks directory for Jupyter
    mkdir -p notebooks

    # Set permissions
    chmod 755 logs data backups notebooks
    chmod -R 755 logs/*

    print_success "Directory structure created ✓"
}

# Validate network configuration
validate_network_config() {
    print_network "Validating network configuration..."

    # Check if the network subnet conflicts with existing networks
    if docker network ls --format "{{.Name}}" | grep -q "ssi-network"; then
        print_warning "ssi-network already exists, will be recreated if needed"
    fi

    # Check if subnet 172.20.0.0/16 is available
    if docker network ls --format "{{.Name}}" | xargs -I {} docker network inspect {} 2>/dev/null | grep -q "172.20.0.0/16"; then
        print_warning "Subnet 172.20.0.0/16 may be in use by another network"
    else
        print_success "Network subnet 172.20.0.0/16 available ✓"
    fi

    print_network "Fixed IP schema will be applied:"
    echo "  📡 cheqd Validators: 172.20.1.10-13 + 172.20.1.20 + 172.20.1.30"
    echo "  🔗 SSI Services: 172.20.2.10-30"
    echo "  🗄️  Database: 172.20.3.10"
    echo "  🤖 ACA-Py Agents: 172.20.4.10-30"
    echo "  📓 Jupyter: 172.20.5.10"
}

# Check required images
check_required_images() {
    print_status "Checking required Docker images..."

    local missing_images=()

    # Check if cheqd-extended image exists
    if ! docker images cheqd-extended:latest --format "{{.Repository}}" | grep -q "cheqd-extended"; then
        missing_images+=("cheqd-extended")
    fi

    # Check external images that should be available
    local external_images=(
        "ghcr.io/cheqd/cheqd-node:latest"
        "ghcr.io/cheqd/did-resolver:latest"
        "universalregistrar/uni-registrar-web:latest"
        "ghcr.io/cheqd/did-registrar:production-latest"
        "postgres:15-alpine"
        "jupyter/scipy-notebook:latest"
        "ghcr.io/openwallet-foundation/acapy-agent:py3.12-1.3.0"
    )

    print_info "Checking external images availability..."
    for image in "${external_images[@]}"; do
        if docker manifest inspect "$image" >/dev/null 2>&1; then
            print_success "✓ $image (available for pull)"
        else
            print_warning "⚠ $image (may not be accessible)"
        fi
    done

    if [ ${#missing_images[@]} -gt 0 ]; then
        print_warning "Missing local images: ${missing_images[*]}"
        print_info "Run './scripts/build.sh' to build missing images"
    else
        print_success "All required local images are available ✓"
    fi
}

# Generate or update secrets
generate_secrets() {
    print_status "Generating secure passwords and tokens..."

    # Only update if placeholders or weak passwords are found
    if grep -q "acapy_secret\|ssi_workflow_token\|changeme" .env 2>/dev/null; then
        print_info "Updating weak default passwords..."

        # Generate strong passwords
        ACAPY_DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        JUPYTER_TOKEN=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

        # Update .env file
        sed -i "s/ACAPY_DB_PASSWORD=.*/ACAPY_DB_PASSWORD=${ACAPY_DB_PASSWORD}/" .env
        sed -i "s/JUPYTER_TOKEN=.*/JUPYTER_TOKEN=${JUPYTER_TOKEN}/" .env

        print_success "Secure passwords generated and saved to .env"
    else
        print_info "Existing passwords in .env appear secure, keeping them"
    fi
}

# Make scripts executable
make_scripts_executable() {
    print_status "Making scripts executable..."

    chmod +x scripts/*.sh 2>/dev/null || true
    chmod +x import-keys.sh 2>/dev/null || true

    if [ -f "scripts/start.sh" ]; then
        chmod +x scripts/start.sh
        print_success "✓ scripts/start.sh"
    fi

    if [ -f "scripts/stop.sh" ]; then
        chmod +x scripts/stop.sh
        print_success "✓ scripts/stop.sh"
    fi

    if [ -f "scripts/build.sh" ]; then
        chmod +x scripts/build.sh
        print_success "✓ scripts/build.sh"
    fi

    if [ -f "scripts/status.sh" ]; then
        chmod +x scripts/status.sh
        print_success "✓ scripts/status.sh"
    fi

    print_success "Scripts are now executable"
}

# Pull external images
pull_external_images() {
    print_status "Pulling external Docker images..."
    print_info "This may take several minutes depending on your internet connection..."

    # List of external images to pre-pull
    local images=(
        "ghcr.io/cheqd/cheqd-node:latest"
        "ghcr.io/cheqd/did-resolver:latest"
        "universalregistrar/uni-registrar-web:latest"
        "ghcr.io/cheqd/did-registrar:production-latest"
        "postgres:15-alpine"
        "jupyter/scipy-notebook:latest"
        "ghcr.io/openwallet-foundation/acapy-agent:py3.12-1.3.0"
    )

    local failed_pulls=()

    for image in "${images[@]}"; do
        print_info "Pulling $image..."
        if docker pull "$image" >/dev/null 2>&1; then
            print_success "✓ $image"
        else
            failed_pulls+=("$image")
            print_warning "✗ Failed to pull $image"
        fi
    done

    if [ ${#failed_pulls[@]} -eq 0 ]; then
        print_success "All external images pulled successfully"
    else
        print_warning "Some images failed to pull: ${failed_pulls[*]}"
        print_info "They will be pulled automatically when starting services"
    fi
}

# Run setup validation
validate_setup() {
    print_status "Running final setup validation..."

    # Test docker-compose configuration
    if $DOCKER_COMPOSE config > /dev/null 2>&1; then
        print_success "✓ Docker Compose configuration is valid"
    else
        print_error "✗ Docker Compose configuration has errors"
        exit 1
    fi

    # Check if we can create networks
    if docker network create test-ssi-network --subnet 172.21.0.0/16 >/dev/null 2>&1; then
        docker network rm test-ssi-network >/dev/null 2>&1
        print_success "✓ Network creation permissions"
    else
        print_warning "⚠ Limited network creation permissions"
    fi

    print_success "Setup validation completed successfully"
}

# Show next steps
show_next_steps() {
    echo ""
    echo "🎉 Setup completed successfully!"
    echo ""
    echo "📋 SSI Infrastructure Overview:"
    echo "=============================="
    echo "• 6 cheqd blockchain nodes (validators, seed, observer)"
    echo "• 3 ACA-Py agents (issuer, holder, verifier)"
    echo "• DID resolver & registrar services"
    echo "• PostgreSQL database for agents"
    echo "• Jupyter Labs for workflow demos"
    echo ""
    echo "🌐 Network Configuration:"
    echo "========================"
    echo "• Network: ssi-network (172.20.0.0/16)"
    echo "• cheqd nodes: 172.20.1.x"
    echo "• SSI services: 172.20.2.x"
    echo "• Database: 172.20.3.x"
    echo "• ACA-Py agents: 172.20.4.x"
    echo "• Utilities: 172.20.5.x"
    echo ""
    echo "🚀 Next Steps:"
    echo "=============="
    echo "1. Build images (if using local ACA-Py):"
    echo "   ./scripts/build.sh"
    echo ""
    echo "2. Start the infrastructure:"
    echo "   ./scripts/start.sh"
    echo ""
    echo "3. Monitor services:"
    echo "   ./scripts/status.sh"
    echo ""
    echo "4. Access services:"
    echo "   • Jupyter Labs: http://localhost:8888"
    echo "   • DID Resolver: http://localhost:8080"
    echo "   • DID Registrar: http://localhost:9080"
    echo "   • ACA-Py Issuer: http://localhost:8021"
    echo ""
    echo "5. Stop when done:"
    echo "   ./scripts/stop.sh"
    echo ""
    echo "📚 Important Files:"
    echo "=================="
    echo "• .env - Environment configuration"
    echo "• docker-compose.yml - Service definitions"
    echo "• config/ - Service configurations"
    echo "• scripts/ - Management scripts"
    echo ""
}

# Main execution
main() {
    echo ""
    echo "=================================================="
    echo "     SSI Infrastructure Setup Script v2.0"
    echo "=================================================="
    echo ""

    detect_docker_compose
    check_system_requirements
    validate_configuration
    create_directories
    validate_network_config
    check_required_images
    make_scripts_executable
    generate_secrets
    pull_external_images
    validate_setup
    show_next_steps

    echo ""
    echo "✅ Setup completed successfully!"
    echo "🚀 Ready to build: ./scripts/build.sh"
    echo "🌟 Ready to start: ./scripts/start.sh"
    echo ""
}

# Run main function
main "$@"