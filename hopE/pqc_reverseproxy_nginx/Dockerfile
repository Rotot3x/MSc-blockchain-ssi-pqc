# Nginx with OpenSSL 3.5.4 (LTS) + OQS Provider for Post-Quantum Cryptography
# Based on: https://github.com/open-quantum-safe/oqs-demos/blob/main/nginx/Dockerfile
#
# Customizations:
# - OpenSSL 3.5.4 (LTS with Security Fixes)
# - Uses custom certificates (mounted via volume)
# - ML-KEM-768 Key Exchange enabled

# Define build arguments for version tags, installation paths, and configurations
ARG ALPINE_VERSION=3.21
ARG OPENSSL_TAG=openssl-3.5.4
ARG LIBOQS_TAG=0.13.0
ARG OQSPROVIDER_TAG=0.9.0
ARG NGINX_VERSION=1.28.0
ARG BASEDIR="/opt"
ARG INSTALLDIR=${BASEDIR}/nginx

# Specify supported signature and key encapsulation mechanisms (KEM) algorithms
ARG SIG_ALG="mldsa65"
ARG DEFAULT_GROUPS=X25519MLKEM768:mlkem768:x25519:mlkem1024

# Stage 1: Build - Compile and assemble all necessary components and dependencies
FROM alpine:${ALPINE_VERSION} AS intermediate
ARG OPENSSL_TAG
ARG LIBOQS_TAG
ARG OQSPROVIDER_TAG
ARG NGINX_VERSION
ARG BASEDIR
ARG INSTALLDIR
ARG SIG_ALG
ARG DEFAULT_GROUPS
ARG OSSLDIR=${BASEDIR}/openssl/.openssl

# Install required build tools and system dependencies
RUN apk update && apk --no-cache add \
    build-base linux-headers libtool \
    automake autoconf make cmake ninja \
    openssl openssl-dev git wget pcre-dev

# Download and prepare source files needed for the build process
WORKDIR /opt
RUN git clone --depth 1 --branch ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs \
    && git clone --depth 1 --branch ${OQSPROVIDER_TAG} https://github.com/open-quantum-safe/oqs-provider.git \
    && git clone --depth 1 --branch ${OPENSSL_TAG} https://github.com/openssl/openssl.git \
    && wget -q nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar -zxf nginx-${NGINX_VERSION}.tar.gz \
    && rm nginx-${NGINX_VERSION}.tar.gz

# Build and install OpenSSL with shared libraries (for curl and nginx)
WORKDIR /opt/openssl
RUN ./Configure --prefix=${OSSLDIR} \
                --openssldir=${OSSLDIR}/ssl \
                shared \
                enable-fips \
    && make -j"$(nproc)" \
    && make install_sw install_ssldirs

# Configure OpenSSL to support the oqs-provider
RUN cp /opt/openssl/apps/openssl.cnf ${OSSLDIR}/ssl/ && \
    sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" ${OSSLDIR}/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" ${OSSLDIR}/ssl/openssl.cnf && \
    sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" ${OSSLDIR}/ssl/openssl.cnf && \
    sed -i "s/HOME\t\t\t= ./HOME\t\t= .\nDEFAULT_GROUPS\t= ${DEFAULT_GROUPS}/g" ${OSSLDIR}/ssl/openssl.cnf

# Build and install liboqs
WORKDIR /opt/liboqs/build
RUN cmake -G"Ninja"  \
    -DOQS_DIST_BUILD=ON  \
    -DBUILD_SHARED_LIBS=OFF  \
    -DCMAKE_INSTALL_PREFIX="${INSTALLDIR}" ..  \
    && ninja -j"$(nproc)" && ninja install

# Build and install Nginx with shared OpenSSL
WORKDIR /opt/nginx-${NGINX_VERSION}
RUN ./configure --prefix=${INSTALLDIR} \
    --with-debug --with-http_ssl_module  \
    --with-cc-opt="-I${OSSLDIR}/include" \
    --with-ld-opt="-L${OSSLDIR}/lib64 -Wl,-rpath,${OSSLDIR}/lib64" \
    --without-http_gzip_module && \
    make -j"$(nproc)" && make install

# Build and install OQS provider
WORKDIR /opt/oqs-provider
RUN ln -s "/opt/nginx/include/oqs" "${OSSLDIR}/include" && \
    rm -rf build && \
    cmake -DCMAKE_BUILD_TYPE=Debug \
          -DOPENSSL_ROOT_DIR="${OSSLDIR}" \
          -DCMAKE_PREFIX_PATH="${INSTALLDIR}" \
          -S . -B build && \
    cmake --build build && \
    MODULESDIR=$(find "${OSSLDIR}" -name ossl-modules -type d | head -1) && \
    export MODULESDIR && \
    cp build/lib/oqsprovider.so "${MODULESDIR}" && \
    rm -rf "${INSTALLDIR:?}/lib64"

# Build curl with shared OpenSSL 3.5.4
ARG CURL_VERSION=8.11.1
WORKDIR /opt
RUN wget -q https://curl.se/download/curl-${CURL_VERSION}.tar.gz && \
    tar -zxf curl-${CURL_VERSION}.tar.gz && \
    rm curl-${CURL_VERSION}.tar.gz

WORKDIR /opt/curl-${CURL_VERSION}
RUN LDFLAGS="-Wl,-rpath,${OSSLDIR}/lib64 -L${OSSLDIR}/lib64" \
    PKG_CONFIG_PATH="${OSSLDIR}/lib64/pkgconfig" \
    ./configure \
    --prefix=${INSTALLDIR} \
    --with-openssl=${OSSLDIR} \
    --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
    --disable-manual \
    --disable-ldap \
    --disable-ldaps \
    --without-libpsl \
    --without-zlib \
    --without-brotli \
    --without-zstd && \
    make -j"$(nproc)" && \
    make install

# Minimize image size by stripping binaries
WORKDIR ${INSTALLDIR}
ENV PATH="${INSTALLDIR}/sbin:${INSTALLDIR}/bin:${OSSLDIR}/bin:${PATH}"

RUN set -ex && \
    strip "${OSSLDIR}/lib64/"*.a \
          "${OSSLDIR}/lib64/ossl-modules/oqsprovider.so" \
          "${INSTALLDIR}/sbin/"* \
          "${INSTALLDIR}/bin/curl" \
          "${OSSLDIR}/bin/openssl" && \
    mkdir -p certs

# Stage 2: Runtime - Create a lightweight image with essential binaries and configurations
FROM alpine:${ALPINE_VERSION}
ARG INSTALLDIR
ARG BASEDIR
ARG OSSLDIR=${BASEDIR}/openssl/.openssl

# Install runtime dependencies
RUN apk update && apk --no-cache add pcre-dev ca-certificates

# Copy compiled artifacts and configuration from the intermediate stage
COPY --from=intermediate ${INSTALLDIR} ${INSTALLDIR}
COPY --from=intermediate ${OSSLDIR} ${OSSLDIR}

# Link logs to Docker collector
RUN set -ex && \
    mkdir -p "${INSTALLDIR}/logs" && \
    ln -sf /dev/stdout "${INSTALLDIR}/logs/access.log" && \
    ln -sf /dev/stderr "${INSTALLDIR}/logs/error.log"

# # Expose HTTPS port
# EXPOSE 443

# Set OpenSSL configuration environment
# From Nginx 1.25.2: "nginx does not try to load OpenSSL configuration if the
# --with-openssl option was used to build OpenSSL and the OPENSSL_CONF
# environment variable is not set." Hence we must explicitly set OPENSSL_CONF.
ENV PATH="${INSTALLDIR}/sbin:${INSTALLDIR}/bin:${OSSLDIR}/bin:${PATH}" \
    OPENSSL_CONF="${OSSLDIR}/ssl/openssl.cnf" \
    DEFAULT_GROUPS="X25519MLKEM768:mlkem768:x25519:mlkem1024"

# Create non-root user and update permissions
RUN addgroup -g 1000 -S oqs \
 && adduser --uid 1000 -S oqs -G oqs \
 && chown -R oqs:oqs "${INSTALLDIR}"

# Run as non-root user
USER oqs
WORKDIR ${INSTALLDIR}

STOPSIGNAL SIGTERM
CMD ["nginx", "-c", "nginx-conf/nginx.conf", "-g", "daemon off;"]
