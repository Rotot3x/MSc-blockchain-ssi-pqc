#!/bin/bash

# SSI Infrastructure Build Script
# Builds local images for the SSI infrastructure
# Updated for new Docker Compose structure with fixed IPs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[BUILD]${NC} $1"
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

# Detect Docker Compose command
detect_docker_compose() {
    if command -v docker compose &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
    else
        DOCKER_COMPOSE="docker-compose"
    fi
    print_info "Using Docker Compose command: $DOCKER_COMPOSE"
}

# Build cheqd extended image
build_cheqd_extended() {
    print_status "Building cheqd-extended image with jq..."

    # Ensure docker directory exists
    mkdir -p docker

    # Create the extended cheqd image build definition if it doesn't exist
    if [ ! -f docker/Dockerfile.cheqd-extended ]; then
        cat > docker/Dockerfile.cheqd-extended << EOF
# Extended cheqd image with jq for better health checks
FROM ghcr.io/cheqd/cheqd-node:latest

# Switch to root to install packages
USER root

# Install jq for JSON parsing in health checks
RUN apk add --no-cache jq

# Switch back to cheqd user
USER cheqd

# Keep the original entrypoint
ENTRYPOINT ["node-start"]
EOF
    fi

    # Build the image directly with docker build
    if docker build -t cheqd-extended:latest -f docker/Dockerfile.cheqd-extended docker/; then
        print_success "cheqd-extended image built successfully"
        return 0
    else
        print_error "Failed to build cheqd-extended image"
        return 1
    fi
}

# Build ACA-Py base image
build_acapy_base() {
    print_status "Building acapy-base image from local source..."
    print_info "This may take several minutes..."

    # Check if we have ACA-Py source code in parent directory
    if [ ! -f "../docker/Dockerfile" ]; then
        print_warning "ACA-Py source not found in parent directory"
        print_info "Using pre-built ACA-Py image instead..."
        if docker pull ghcr.io/openwallet-foundation/acapy-agent:py3.12-1.3.0; then
            docker tag ghcr.io/openwallet-foundation/acapy-agent:py3.12-1.3.0 acapy-base:latest
            print_success "acapy-base image tagged from official image"
        else
            print_error "Failed to pull official ACA-Py image"
            return 1
        fi
        return 0
    fi

    # Build the image directly with docker build
    if docker build -t acapy-base:latest \
        --build-arg python_version=3.12 \
        --build-arg acapy_version=1.3.2 \
        -f ../docker/Dockerfile ..; then
        print_success "acapy-base image built successfully"
        return 0
    else
        print_error "Failed to build acapy-base image"
        return 1
    fi
}

# Build ACA-Py SSI demo image
build_acapy_ssi_demo() {
    print_status "Building acapy-ssi-demo image with plugins..."
    print_info "This may take several minutes..."

    # Check if we have ACA-Py demo Dockerfile in parent directory
    if [ ! -f "../docker/Dockerfile.demo" ]; then
        print_warning "ACA-Py demo Dockerfile not found in parent directory"
        print_info "Using acapy-base image as acapy-ssi-demo..."
        if docker images acapy-base:latest --format "{{.Repository}}" | grep -q "acapy-base"; then
            docker tag acapy-base:latest acapy-ssi-demo:latest
            print_success "acapy-ssi-demo image tagged from acapy-base"
        else
            print_error "acapy-base image not found. Build acapy-base first."
            return 1
        fi
        return 0
    fi

    # Check if acapy-base exists
    if ! docker images acapy-base:latest --format "{{.Repository}}" | grep -q "acapy-base"; then
        print_error "acapy-base image not found. Build acapy-base first."
        return 1
    fi

    # Build the image directly with docker build
    if docker build -t acapy-ssi-demo:latest \
        --build-arg from_image=acapy-base:latest \
        --build-arg all_extras=1 \
        -f ../docker/Dockerfile.demo ..; then
        print_success "acapy-ssi-demo image built successfully"
        return 0
    else
        print_error "Failed to build acapy-ssi-demo image"
        return 1
    fi
}

# Show available images
show_images() {
    print_status "Checking built images..."
    echo ""
    echo "🐳 Built SSI Infrastructure Images:"
    echo "=================================="

    # Check cheqd-extended
    if docker images cheqd-extended:latest --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" | grep -v REPOSITORY; then
        echo "✅ cheqd-extended: Available"
    else
        echo "❌ cheqd-extended: Not found"
    fi

    # Check acapy-base
    if docker images acapy-base:latest --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" | grep -v REPOSITORY; then
        echo "✅ acapy-base: Available"
    else
        echo "❌ acapy-base: Not found"
    fi

    # Check acapy-ssi-demo
    if docker images acapy-ssi-demo:latest --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" | grep -v REPOSITORY; then
        echo "✅ acapy-ssi-demo: Available"
    else
        echo "❌ acapy-ssi-demo: Not found"
    fi

    echo ""
    print_info "External images will be pulled automatically on first start"
    echo ""
}

# Build options
build_all() {
    print_status "Building all SSI Infrastructure images..."

    local failed=0

    # Build cheqd-extended
    if ! build_cheqd_extended; then
        failed=1
    fi

    # Build acapy-base
    if ! build_acapy_base; then
        failed=1
    fi

    # Build acapy-ssi-demo (depends on acapy-base)
    if ! build_acapy_ssi_demo; then
        failed=1
    fi

    if [ $failed -eq 0 ]; then
        print_success "All images built successfully!"
        return 0
    else
        print_error "Some images failed to build"
        return 1
    fi
}

# Build specific image
build_specific() {
    case "$1" in
        cheqd|cheqd-extended)
            build_cheqd_extended
            ;;
        acapy-base|base)
            build_acapy_base
            ;;
        acapy-ssi-demo|demo|ssi)
            build_acapy_ssi_demo
            ;;
        *)
            print_error "Unknown image: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Show usage
show_usage() {
    echo "Usage: $0 [options] [image]"
    echo ""
    echo "Build SSI Infrastructure Docker images"
    echo ""
    echo "Options:"
    echo "  -a, --all        Build all images (default)"
    echo "  -l, --list       List built images"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Specific images:"
    echo "  cheqd            Build cheqd-extended image only"
    echo "  acapy-base       Build acapy-base image only"
    echo "  acapy-ssi-demo   Build acapy-ssi-demo image only"
    echo ""
    echo "Examples:"
    echo "  $0               # Build all images"
    echo "  $0 --all         # Build all images"
    echo "  $0 cheqd         # Build only cheqd-extended"
    echo "  $0 --list        # List built images"
    echo ""
}

# Main execution
main() {
    echo ""
    echo "================================================"
    echo "    SSI Infrastructure Build Script v2.0"
    echo "================================================"
    echo ""

    detect_docker_compose

    case "${1:-all}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -l|--list)
            show_images
            exit 0
            ;;
        -a|--all|all|"")
            if build_all; then
                show_images
                echo ""
                echo "✅ Build completed successfully!"
                echo ""
                echo "Next steps:"
                echo "1. Start infrastructure: ./scripts/start.sh"
                echo "2. Monitor status: ./scripts/status.sh"
                echo ""
            else
                echo ""
                echo "❌ Build failed!"
                echo "Check the error messages above for details."
                exit 1
            fi
            ;;
        *)
            if build_specific "$1"; then
                show_images
                echo ""
                echo "✅ Build completed successfully!"
                echo ""
            else
                echo ""
                echo "❌ Build failed!"
                exit 1
            fi
            ;;
    esac
}

# Run main function
main "$@"