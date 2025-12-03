# Production Docker image for PQCrypto_FM plugin
FROM ghcr.io/openwallet-foundation/acapy:py3.12-1.3-lts

LABEL maintainer="OpenWallet Foundation <info@openwallet.foundation>"
LABEL description="ACA-Py with PQCrypto_FM - Post-Quantum Cryptography Support"
LABEL version="1.0.0"

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential cmake git ninja-build libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs
ARG LIBOQS_VERSION=0.10.1
RUN git clone --branch=${LIBOQS_VERSION} --depth=1 \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_ENABLE_KEM_KYBER=ON \
        -DOQS_ENABLE_SIG_DILITHIUM=ON \
        -GNinja \
    && cmake --build /tmp/liboqs/build --parallel $(nproc) \
    && cmake --build /tmp/liboqs/build --target install \
    && ldconfig \
    && rm -rf /tmp/liboqs

ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Copy plugin source
COPY . /tmp/pqcrypto_fm

# Install plugin and dependencies
RUN pip install --no-cache-dir \
    liboqs-python>=0.12.0 \
    pqcrypto>=0.3.0 \
    && pip install --no-cache-dir /tmp/pqcrypto_fm \
    && rm -rf /tmp/pqcrypto_fm

COPY docker/default.yml /etc/acapy/default.yml

USER $user

EXPOSE 8020 8021

ENV ACAPY_ARG_FILE=/etc/acapy/default.yml
ENV ACAPY_WALLET_TYPE=askar-anoncreds
ENV ACAPY_PLUGIN=pqcrypto_fm.v1_0

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8021/status || exit 1

CMD ["aca-py", "start", \
     "--arg-file", "/etc/acapy/default.yml", \
     "--plugin", "pqcrypto_fm.v1_0", \
     "--wallet-type", "askar-anoncreds"]