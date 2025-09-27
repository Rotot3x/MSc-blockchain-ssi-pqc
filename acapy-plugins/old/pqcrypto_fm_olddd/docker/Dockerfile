# Production Docker image for PQCrypto_FM plugin
FROM ghcr.io/openwallet-foundation/acapy:py3.12-1.3-lts

# Metadata
LABEL maintainer="OpenWallet Foundation <info@openwallet.foundation>"
LABEL description="ACA-Py with PQCrypto_FM - Post-Quantum Cryptography Support"
LABEL version="1.0.0"

# Switch to root for system installations
USER root

# Install system dependencies for liboqs and performance optimization
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    ninja-build \
    libssl-dev \
    liboqs-dev \
    pkg-config \
    # Performance optimization libraries
    libblas-dev \
    liblapack-dev \
    # Hardware acceleration support
    gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs from source with optimizations
ARG LIBOQS_VERSION=0.10.1
RUN git clone --branch=${LIBOQS_VERSION} --depth=1 \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_ENABLE_KEM_KYBER=ON \
        -DOQS_ENABLE_SIG_DILITHIUM=ON \
        -DOQS_ENABLE_SIG_SPHINCS=ON \
        -DOQS_USE_OPENSSL=ON \
        -DOQS_SPEED_USE_ARM_PMU=OFF \
        -GNinja \
    && cmake --build /tmp/liboqs/build --parallel $(nproc) \
    && cmake --build /tmp/liboqs/build --target install \
    && ldconfig \
    && rm -rf /tmp/liboqs

# Set library paths for runtime
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# Copy plugin source
COPY . /tmp/pqcrypto_fm

# Install PQCrypto_FM plugin and dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir \
        liboqs-python>=0.12.0 \
        pqcrypto>=0.3.0 \
        cryptography>=41.0.0 \
    && pip install --no-cache-dir /tmp/pqcrypto_fm \
    && rm -rf /tmp/pqcrypto_fm

# Copy configuration files
COPY docker/default.yml /etc/acapy/default.yml
COPY docker/integration.yml /etc/acapy/integration.yml

# Create directories for demo integration
RUN mkdir -p /etc/acapy/demo \
    && mkdir -p /var/log/acapy

# Switch back to acapy user for security
USER $user

# Expose standard ACA-Py ports
EXPOSE 8020 8021

# Environment variables for PQC optimization
ENV OQS_CPU_EXTENSIONS=auto
ENV ACAPY_ARG_FILE=/etc/acapy/default.yml
ENV ACAPY_WALLET_TYPE=askar-anoncreds
ENV ACAPY_PLUGIN=pqcrypto_fm.v1_0

# Health check with PQC validation
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8021/status && \
      curl -f http://localhost:8021/pqc/algorithms || exit 1

# Default command with PQC plugin
CMD ["aca-py", "start", \
     "--arg-file", "/etc/acapy/default.yml", \
     "--plugin", "pqcrypto_fm.v1_0", \
     "--wallet-type", "askar-anoncreds"]