#!/bin/bash

# PQC-enabled run_demo script for ACA-Py
# This version integrates PQCrypto_FM plugin for quantum-safe SSI workflows

shopt -s nocasematch

cd $(dirname $0)

# PQC Configuration Variables
PQC_ENABLED=${PQC_ENABLED:-1}
PQC_PLUGIN="pqcrypto_fm.v1_0"
PQC_DEFAULT_KEM_ALG=${PQC_DEFAULT_KEM_ALG:-"Kyber768"}
PQC_DEFAULT_SIG_ALG=${PQC_DEFAULT_SIG_ALG:-"Dilithium3"}
PQC_HYBRID_MODE=${PQC_HYBRID_MODE:-true}
PQC_SECURITY_LEVEL=${PQC_SECURITY_LEVEL:-3}

RESOLUTION="$1"
# Check if RESOLUTION is not provided or not a valid option
if [ -z "$RESOLUTION" ] || [ "$RESOLUTION" != "build" -a "$RESOLUTION" != "run" ]; then
  echo "Resolution not specified or invalid."
  AGENT="$1"  # If RESOLUTION is not provided or invalid, assume argument is AGENT
else
  shift  # Shift only if RESOLUTION is provided and valid
  AGENT="$1"
fi
shift  # Shift again to remove AGENT from the arguments
ARGS=""

TRACE_ENABLED=""
TRACE_TAG=acapy.events
if ! [ -z "$TRACE_TARGET_URL" ]; then
  TRACE_TARGET=http://${TRACE_TARGET_URL}/
else
  TRACE_TARGET=log
fi
WEBHOOK_TARGET=""
if [ -z "$DOCKER_NET" ]; then
  DOCKER_NET="bridge"
fi
DOCKER_VOL=""

# Set default platform to linux/amd64 when running on Arm based MAC
if [[ $OSTYPE == 'darwin'* ]]; then
  architecture=$(uname -m)
  if [[ "${architecture}" == 'arm'* ]] || [[ "${architecture}" == 'aarch'* ]]; then
    export DOCKER_DEFAULT_PLATFORM=linux/amd64
  fi
fi

# PQC-specific argument parsing
j=1
for i in "$@"
do
  ((j++))
  # Demo agent with --multitenant requires the ../log dir to exist and write access to it
  if [ ! -d "../log" ]; then
    mkdir ../log && chmod -R uga+rws ../log
    DOCKER_VOL="${DOCKER_VOL} -v /$(pwd)/../log:/home/aries/log"
  fi
  if [ ! -z "$SKIP" ]; then
    SKIP=""
    continue
  fi
  case $i in
  --pqc)
    PQC_ENABLED=1
    echo "🔒 PQC Mode: ENABLED"
    continue
  ;;
  --no-pqc)
    PQC_ENABLED=0
    echo "⚠️  PQC Mode: DISABLED"
    continue
  ;;
  --pqc-hybrid)
    PQC_HYBRID_MODE=true
    echo "🔗 PQC Hybrid Mode: ENABLED"
    continue
  ;;
  --pqc-only)
    PQC_HYBRID_MODE=false
    echo "🛡️  PQC-Only Mode: ENABLED"
    continue
  ;;
  --pqc-level)
    PQC_SECURITY_LEVEL=${!j}
    echo "🔐 PQC Security Level: ${PQC_SECURITY_LEVEL}"
    SKIP=1
    continue
  ;;
  --pqc-kem)
    PQC_DEFAULT_KEM_ALG=${!j}
    echo "🔑 PQC KEM Algorithm: ${PQC_DEFAULT_KEM_ALG}"
    SKIP=1
    continue
  ;;
  --pqc-sig)
    PQC_DEFAULT_SIG_ALG=${!j}
    echo "✍️ PQC Signature Algorithm: ${PQC_DEFAULT_SIG_ALG}"
    SKIP=1
    continue
  ;;
  --events)
    if [ "${AGENT}" = "performance" ]; then
      echo -e "\nIgnoring the \"--events\" option when running the ${AGENT} agent.\n"
    else
      EVENTS=1
    fi
    continue
  ;;
    --self-attested)
      SELF_ATTESTED=1
      continue
    ;;
    --trace-log)
      TRACE_ENABLED=1
      TRACE_TARGET=log
      TRACE_TAG=acapy.events
      continue
    ;;
    --trace-http)
      TRACE_ENABLED=1
      TRACE_TARGET=http://${TRACE_TARGET_URL}/
      TRACE_TAG=acapy.events
      continue
    ;;
    --webhook-url)
      WEBHOOK_TARGET=http://${WEBHOOK_URL}
      continue
    ;;
    --debug-ptvsd)
      ENABLE_PTVSD=1
      continue
    ;;
    --debug-pycharm)
      ENABLE_PYDEVD_PYCHARM=1
      continue
    ;;
    --debug-pycharm-controller-port)
      PYDEVD_PYCHARM_CONTROLLER_PORT=${!j}
      SKIP=1
      continue
    ;;
    --debug-pycharm-agent-port)
      PYDEVD_PYCHARM_AGENT_PORT=${!j}
      SKIP=1
      continue
    ;;
  --timing)
    if [ "$(ls -ld ../log | grep dr..r..rwx)" == "" ]; then
      echo "Error: To use the --timing parameter, the directory '../log' must exist and all users must be able to write to it."
      echo "For example, to create the directory and then set the permissions use: 'mkdir ../log; chmod uga+rws ../log'"
      exit 1
    fi
    continue
  ;;
  --bg)
    if [ "${AGENT}" = "alice" ] || [ "${AGENT}" = "faber" ] || [ "${AGENT}" = "acme" ]; then
      DOCKER_OPTS="-d"
      echo -e "\nRunning in ${AGENT} in the background. Note that you cannot use the command line console in this mode."
      echo To see the logs use: \"docker logs ${AGENT}\".
      echo While viewing logs, hit CTRL-C to return to the command line.
      echo To stop the agent, use: \"docker stop ${AGENT}\". The docker environment will
      echo -e "be removed on stop.\n\n"
    else
      echo The "bg" option \(for running docker in detached mode\) is only for agents Alice, Faber and Acme.
      echo Ignoring...
    fi
    continue
  ;;
  --help)
    cat <<EOF

Usage:
   ./run_demo <resolution> <agent> [OPTIONS]

   - <resolution> is one of the docker option to build or run.
   - <agent> is one of alice, faber, acme, performance.
   
   🔒 PQC Options:
      --pqc - enable Post-Quantum Cryptography (default: enabled)
      --no-pqc - disable PQC and use classical cryptography
      --pqc-hybrid - enable hybrid PQC+Classical mode (default: enabled)
      --pqc-only - use only PQC algorithms (no classical fallback)
      --pqc-level <1-5> - set NIST security level (default: 3)
      --pqc-kem <algorithm> - set KEM algorithm (default: Kyber768)
      --pqc-sig <algorithm> - set signature algorithm (default: Dilithium3)
   
   📊 Standard Options:
      --events - display webhook events from the ACA-Py agent
      --timing - display timing at the end of the run
      --bg - run the agent in the background
      --trace-log - log trace events to the standard log file
      --trace-http - log trace events to an http endpoint
      --self-attested - include a self-attested attribute in the proof request/response
      --webhook-url - send events to an http endpoint
      
   🧪 Debug Options:
      --debug-pycharm-agent-port <port>
      --debug-pycharm-controller-port <port>
      --debug-pycharm
      --debug-ptvsd

   🚀 PQC Examples:
      ./run_demo run faber --pqc --pqc-level 5    # Maximum security
      ./run_demo run alice --pqc-hybrid           # Hybrid mode
      ./run_demo run acme --pqc-only              # PQC-only mode

EOF
    exit 0
  ;;
  esac
  ARGS="${ARGS:+$ARGS }$i"
done

# Display PQC configuration
if [ "$PQC_ENABLED" = "1" ]; then
  echo ""
  echo "🔒 ===== PQC Configuration ====="
  echo "   Plugin: ${PQC_PLUGIN}"
  echo "   KEM Algorithm: ${PQC_DEFAULT_KEM_ALG}"
  echo "   Signature Algorithm: ${PQC_DEFAULT_SIG_ALG}"
  echo "   Hybrid Mode: ${PQC_HYBRID_MODE}"
  echo "   Security Level: ${PQC_SECURITY_LEVEL}"
  echo "   Quantum-Safe: ✅ ENABLED"
  echo "================================"
  echo ""
fi

if [ -z "$RESOLUTION" ]; then
  echo "Resolution not specified."
elif [ "$RESOLUTION" = "build" ]; then
  DOCKER_RESOLUTION="build"
  echo "Agent will be build."
elif [ "$RESOLUTION" = "run" ]; then
  DOCKER_RESOLUTION="run"
  echo "Agent will be run."
else
  echo "You can utilize the 'build' option to build the agent or the 'run' option to run the agent."
fi

if [ "$AGENT" = "faber" ]; then
  AGENT_MODULE="faber"
  AGENT_PORT=8020
  AGENT_PORT_RANGE=8020-8029
  # PQC-specific configuration for Faber (University Issuer)
  if [ "$PQC_ENABLED" = "1" ]; then
    PQC_AGENT_ROLE="issuer"
    PQC_AGENT_SIG_ALG="Dilithium3"  # Strong signatures for credential issuance
    PQC_AGENT_KEM_ALG="Kyber768"
  fi
elif [ "$AGENT" = "alice" ]; then
  AGENT_MODULE="alice"
  AGENT_PORT=8030
  AGENT_PORT_RANGE=8030-8039
  # PQC-specific configuration for Alice (Student Holder)
  if [ "$PQC_ENABLED" = "1" ]; then
    PQC_AGENT_ROLE="holder"
    PQC_AGENT_SIG_ALG="Dilithium2"  # Fast signatures for holder operations
    PQC_AGENT_KEM_ALG="Kyber768"    # Standard KEM for secure communication
  fi
elif [ "$AGENT" = "acme" ]; then
  AGENT_MODULE="acme"
  AGENT_PORT=8040
  AGENT_PORT_RANGE=8040-8049
  # PQC-specific configuration for Acme (Corporate Verifier)
  if [ "$PQC_ENABLED" = "1" ]; then
    PQC_AGENT_ROLE="verifier"
    PQC_AGENT_SIG_ALG="Dilithium3"  # Strong verification capabilities
    PQC_AGENT_KEM_ALG="Kyber768"
  fi
elif [ "$AGENT" = "performance" ]; then
  AGENT_MODULE="performance"
  AGENT_PORT=8050
  AGENT_PORT_RANGE=8050-8069
  # PQC Performance testing configuration
  if [ "$PQC_ENABLED" = "1" ]; then
    PQC_AGENT_ROLE="performance"
    PQC_AGENT_SIG_ALG="Kyber512"    # Fast algorithms for performance testing
    PQC_AGENT_KEM_ALG="Kyber512"
    PQC_SECURITY_LEVEL=1            # Lower security for speed
  fi
else
  echo "Please specify which agent you want to run. Choose from 'faber', 'alice', 'acme', or 'performance'."
  exit 1
fi

# Allow override for agent ports
if [ ! -z "$AGENT_PORT_OVERRIDE" ]; then
  AGENT_PORT=$AGENT_PORT_OVERRIDE
  AGENT_PORT_END=$(expr $AGENT_PORT_OVERRIDE + 9)
  AGENT_PORT_RANGE="$AGENT_PORT-$AGENT_PORT_END"
fi

# Build the agent image with PQC support
if [ -z "$DOCKER_RESOLUTION" ] || [ "$DOCKER_RESOLUTION" = "build" ]; then
  echo "🔨 Preparing PQC-enabled agent image..."
  
  # Build base ACA-Py image
  docker build -t acapy-base -f ../docker/Dockerfile .. || exit 1
  
  # Build PQC-enabled demo image
  if [ "$PQC_ENABLED" = "1" ]; then
    echo "🔒 Building PQC-enabled demo image..."
    # Create PQC-enabled Dockerfile
    cat > ../docker/Dockerfile.demo.pqc << 'EOF'
ARG from_image=acapy-base
FROM ${from_image}

USER root

# Install system dependencies for liboqs
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    ninja-build \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs from source
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
        -GNinja \
    && cmake --build /tmp/liboqs/build --parallel $(nproc) \
    && cmake --build /tmp/liboqs/build --target install \
    && ldconfig \
    && rm -rf /tmp/liboqs

# Set library paths
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Install PQC Python dependencies
RUN pip install --no-cache-dir \
    liboqs-python>=0.12.0 \
    pqcrypto>=0.3.0

# Copy PQCrypto_FM plugin (assuming it's in the acapy-plugins directory)
COPY demo/pqcrypto_fm /home/aries/pqcrypto_fm
RUN pip install --no-cache-dir /home/aries/pqcrypto_fm

# Copy demo scripts
COPY demo/runners /home/aries
RUN chmod +x /home/aries/*.py

USER $user

# Set PQC environment variables
ENV ACAPY_PQC_ENABLED=1
ENV ACAPY_WALLET_TYPE=askar-anoncreds
ENV ACAPY_PLUGIN=pqcrypto_fm.v1_0

ENTRYPOINT ["/bin/bash", "/home/aries/default_entrypoint.sh"]
EOF
    
    docker build -t faber-alice-demo-pqc -f ../docker/Dockerfile.demo.pqc --build-arg from_image=acapy-base .. || exit 1
    DEMO_IMAGE="faber-alice-demo-pqc"
  else
    # Use standard demo image
    docker build -t faber-alice-demo -f ../docker/Dockerfile.demo --build-arg from_image=acapy-base .. || exit 1
    DEMO_IMAGE="faber-alice-demo"
  fi
fi

if [ "$DOCKER_RESOLUTION" = "build" ]; then
  exit 1
else
  echo "You can utilize the 'build' option to build the agent or the 'run' option to run the agent."
fi

# Docker host detection (unchanged from original)
if [ ! -z "$DOCKERHOST" ]; then
  export RUNMODE="docker"
elif [ -z "${PWD_HOST_FQDN}" ]; then
  . /dev/stdin <<<"$(cat <(curl -s --raw https://raw.githubusercontent.com/bcgov/DITP-DevOps/main/code/snippets/getDockerHost))"
  export DOCKERHOST=$(getDockerHost)
  export RUNMODE="docker"
else
  PWD_HOST="${PWD_HOST_FQDN}"
  if [ "$PWD_HOST_FQDN" = "labs.play-with-docker.com" ]; then
    export ETH_CONFIG="eth1"
  elif [ "$PWD_HOST_FQDN" = "play-with-docker.vonx.io" ]; then
    export ETH_CONFIG="eth0"
  else
    export ETH_CONFIG="eth0"
  fi
  MY_HOST=`ifconfig ${ETH_CONFIG} | grep inet | cut -d':' -f2 | cut -d' ' -f1 | sed 's/\./\-/g'`
  export DOCKERHOST="ip${MY_HOST}-${SESSION_ID}-{PORT}.direct.${PWD_HOST_FQDN}"
  export RUNMODE="pwd"
fi

# Enhanced tunnel detection with PQC endpoints
if [ "$RUNMODE" == "docker" ]; then
  echo "Checking for devtunnel and ngrok endpoints"
  JQ=${JQ:-`which jq`}
  if [ -x "$JQ" ]; then
    DEVTUNNEL_BIN=$(which devtunnel 2>/dev/null)
    if [ -x "$DEVTUNNEL_BIN" ]; then
      echo "Checking dev tunnel for acapy-demo..."
      DEVTUNNEL_RESPONSE=$($DEVTUNNEL_BIN list --json 2>/dev/null)
      if echo "$DEVTUNNEL_RESPONSE" | $JQ --exit-status . >/dev/null 2>&1; then
        DEVTUNNEL_ID=$(echo "$DEVTUNNEL_RESPONSE" | $JQ -r '(.tunnels // [])[] | select(.description // empty | test("acapy-demo"; "i")) | .tunnelId // empty' | head -n 1)
        if [ ! -z "$DEVTUNNEL_ID" ]; then
          DEVTUNNEL_SHOW=$($DEVTUNNEL_BIN show "$DEVTUNNEL_ID" --json 2>/dev/null)
          if echo "$DEVTUNNEL_SHOW" | $JQ --exit-status . >/dev/null 2>&1; then
            DT_AGENT_ENDPOINT=$(echo "$DEVTUNNEL_SHOW" | $JQ -r '.tunnel.ports[] | select(.portNumber==8020) | .portUri // empty')
            DT_WEBHOOK_ENDPOINT=$(echo "$DEVTUNNEL_SHOW" | $JQ -r '.tunnel.ports[] | select(.portNumber==8022) | .portUri // empty')
            DT_TAILS_ENDPOINT=$(echo "$DEVTUNNEL_SHOW" | $JQ -r '.tunnel.ports[] | select(.portNumber==6543) | .portUri // empty')
            # PQC-specific endpoint
            DT_PQC_ENDPOINT=$(echo "$DEVTUNNEL_SHOW" | $JQ -r '.tunnel.ports[] | select(.portNumber==8025) | .portUri // empty')
            
            if [ -z "$AGENT_ENDPOINT" ] && [ ! -z "$DT_AGENT_ENDPOINT" ]; then
              export AGENT_ENDPOINT=$DT_AGENT_ENDPOINT
              echo "Setting dev tunnel agent endpoint [$AGENT_ENDPOINT]"
            fi
            if [ -z "$WEBHOOK_TARGET" ] && [ ! -z "$DT_WEBHOOK_ENDPOINT" ]; then
              export WEBHOOK_TARGET=${DT_WEBHOOK_ENDPOINT%/}/webhooks
              echo "Setting dev tunnel webhooks endpoint [$WEBHOOK_TARGET]"
            fi
            if [ -z "$PUBLIC_TAILS_URL" ] && [ ! -z "$DT_TAILS_ENDPOINT" ]; then
              export PUBLIC_TAILS_URL=$DT_TAILS_ENDPOINT
              echo "Setting dev tunnel tails-server endpoint [$PUBLIC_TAILS_URL]"
            fi
            if [ "$PQC_ENABLED" = "1" ] && [ ! -z "$DT_PQC_ENDPOINT" ]; then
              export PQC_ENDPOINT=$DT_PQC_ENDPOINT
              echo "🔒 Setting dev tunnel PQC endpoint [$PQC_ENDPOINT]"
            fi
          fi
        fi
      fi
    fi
    
    # Enhanced ngrok detection for PQC
    NGROK_RESPONSE=$(curl --silent localhost:4040/api/tunnels)
    if [ ! -z "$NGROK_RESPONSE" ] && echo "$NGROK_RESPONSE" | $JQ --exit-status . >/dev/null 2>&1; then
      if [ -z "$AGENT_ENDPOINT" ]; then
        NGROK_ENDPOINT=$(echo "$NGROK_RESPONSE" | $JQ -r '.tunnels[0].public_url // empty')
        NAMED_ENDPOINT=$(echo "$NGROK_RESPONSE" | $JQ -r '.tunnels[] | select(.name=="acapy-agent") | .public_url // empty')
        if ! [ -z "$NAMED_ENDPOINT" ]; then
          NGROK_ENDPOINT=$NAMED_ENDPOINT
        fi
        if [ ! -z "$NGROK_ENDPOINT" ]; then
          export AGENT_ENDPOINT=$NGROK_ENDPOINT
          echo "Detected ngrok agent endpoint [$AGENT_ENDPOINT]"
        fi
      fi
      
      if [ -z "$WEBHOOK_TARGET" ]; then
        NAMED_ENDPOINT=$(echo "$NGROK_RESPONSE" | $JQ -r '.tunnels[] | select(.name=="acapy-webhooks") | .public_url // empty')
        if [ ! -z "$NAMED_ENDPOINT" ]; then
          export WEBHOOK_TARGET=${NAMED_ENDPOINT}/webhooks
          echo "Detected ngrok webhooks endpoint [$WEBHOOK_TARGET]"
        fi
      fi
      
      # PQC-specific ngrok endpoint
      if [ "$PQC_ENABLED" = "1" ] && [ -z "$PQC_ENDPOINT" ]; then
        NAMED_ENDPOINT=$(echo "$NGROK_RESPONSE" | $JQ -r '.tunnels[] | select(.name=="acapy-pqc") | .public_url // empty')
        if [ ! -z "$NAMED_ENDPOINT" ]; then
          export PQC_ENDPOINT=${NAMED_ENDPOINT}
          echo "🔒 Detected ngrok PQC endpoint [$PQC_ENDPOINT]"
        fi
      fi
    fi
  fi
fi

echo "DOCKERHOST=$DOCKERHOST"

# Enhanced Docker environment variables with PQC configuration
DOCKER_ENV="-e LOG_LEVEL=${LOG_LEVEL} -e RUNMODE=${RUNMODE} -e DOCKERHOST=${DOCKERHOST}"

# Standard environment variables
if ! [ -z "$AGENT_PORT" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e AGENT_PORT=${AGENT_PORT}"
fi
if ! [ -z "$POSTGRES" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e POSTGRES=1 -e RUST_BACKTRACE=1"
fi
if ! [ -z "$LEDGER_URL" ]; then
  GENESIS_URL="${LEDGER_URL}/genesis"
  DOCKER_ENV="${DOCKER_ENV} -e LEDGER_URL=${LEDGER_URL}"
fi
if ! [ -z "$GENESIS_URL" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e GENESIS_URL=${GENESIS_URL}"
fi
if ! [ -z "$AGENT_ENDPOINT" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e AGENT_ENDPOINT=${AGENT_ENDPOINT}"
fi
if ! [ -z "$EVENTS" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e EVENTS=1"
fi
if ! [ -z "$SELF_ATTESTED" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e SELF_ATTESTED=${SELF_ATTESTED}"
fi
if ! [ -z "$TRACE_TARGET" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e TRACE_TARGET=${TRACE_TARGET}"
  DOCKER_ENV="${DOCKER_ENV} -e TRACE_TAG=${TRACE_TAG}"
  DOCKER_ENV="${DOCKER_ENV} -e TRACE_ENABLED=${TRACE_ENABLED}"
fi
if ! [ -z "$WEBHOOK_TARGET" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e WEBHOOK_TARGET=${WEBHOOK_TARGET}"
fi

# PQC-specific environment variables
if [ "$PQC_ENABLED" = "1" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e ACAPY_PQC_ENABLED=1"
  DOCKER_ENV="${DOCKER_ENV} -e ACAPY_PLUGIN=${PQC_PLUGIN}"
  DOCKER_ENV="${DOCKER_ENV} -e ACAPY_WALLET_TYPE=askar-anoncreds"
  DOCKER_ENV="${DOCKER_ENV} -e PQC_DEFAULT_KEM_ALG=${PQC_DEFAULT_KEM_ALG}"
  DOCKER_ENV="${DOCKER_ENV} -e PQC_DEFAULT_SIG_ALG=${PQC_DEFAULT_SIG_ALG}"
  DOCKER_ENV="${DOCKER_ENV} -e PQC_HYBRID_MODE=${PQC_HYBRID_MODE}"
  DOCKER_ENV="${DOCKER_ENV} -e PQC_SECURITY_LEVEL=${PQC_SECURITY_LEVEL}"
  DOCKER_ENV="${DOCKER_ENV} -e PQC_AGENT_ROLE=${PQC_AGENT_ROLE}"
  
  # Agent-specific PQC configuration
  if ! [ -z "$PQC_AGENT_SIG_ALG" ]; then
    DOCKER_ENV="${DOCKER_ENV} -e PQC_AGENT_SIG_ALG=${PQC_AGENT_SIG_ALG}"
  fi
  if ! [ -z "$PQC_AGENT_KEM_ALG" ]; then
    DOCKER_ENV="${DOCKER_ENV} -e PQC_AGENT_KEM_ALG=${PQC_AGENT_KEM_ALG}"
  fi
  if ! [ -z "$PQC_ENDPOINT" ]; then
    DOCKER_ENV="${DOCKER_ENV} -e PQC_ENDPOINT=${PQC_ENDPOINT}"
  fi
fi

# Additional environment variables (unchanged)
if ! [ -z "$ACAPY_DEBUG_WEBHOOKS" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e ACAPY_DEBUG_WEBHOOKS=${ACAPY_DEBUG_WEBHOOKS}"
fi
if ! [ -z "$TAILS_NETWORK" ]; then
  DOCKER_NET="${TAILS_NETWORK}"
  DOCKER_ENV="${DOCKER_ENV} -e TAILS_NETWORK=${TAILS_NETWORK}"
  DOCKER_ENV="${DOCKER_ENV} -e TAILS_NGROK_NAME=ngrok-tails-server"
fi
if ! [ -z "$PUBLIC_TAILS_URL" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e PUBLIC_TAILS_URL=${PUBLIC_TAILS_URL}"
fi
if ! [ -z "$TAILS_FILE_COUNT" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e TAILS_FILE_COUNT=${TAILS_FILE_COUNT}"
fi
if ! [ -z "$ACAPY_ARG_FILE" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e ACAPY_ARG_FILE=${ACAPY_ARG_FILE}"
fi

# Enhanced demo extra agent args with PQC configuration
if [ "$PQC_ENABLED" = "1" ]; then
  PQC_EXTRA_ARGS="--plugin ${PQC_PLUGIN} --wallet-type askar-anoncreds"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.enable_demo_mode=true"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.hybrid_mode=${PQC_HYBRID_MODE}"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.default_kem_algorithm=${PQC_DEFAULT_KEM_ALG}"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.default_sig_algorithm=${PQC_DEFAULT_SIG_ALG}"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.min_security_level=${PQC_SECURITY_LEVEL}"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.use_askar_anoncreds=true"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.enable_pqc_for_credentials=true"
  PQC_EXTRA_ARGS="${PQC_EXTRA_ARGS} --plugin-config-value ${PQC_PLUGIN}.enable_pqc_for_proofs=true"
  
  if [ -z "$DEMO_EXTRA_AGENT_ARGS" ]; then
    DEMO_EXTRA_AGENT_ARGS="${PQC_EXTRA_ARGS}"
  else
    DEMO_EXTRA_AGENT_ARGS="${DEMO_EXTRA_AGENT_ARGS} ${PQC_EXTRA_ARGS}"
  fi
fi

if ! [ -z "$DEMO_EXTRA_AGENT_ARGS" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e DEMO_EXTRA_AGENT_ARGS=\"${DEMO_EXTRA_AGENT_ARGS}\""
fi

# Debug environment variables
if ! [ -z "${ENABLE_PYDEVD_PYCHARM}" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e ENABLE_PYDEVD_PYCHARM=${ENABLE_PYDEVD_PYCHARM} -e PYDEVD_PYCHARM_CONTROLLER_PORT=${PYDEVD_PYCHARM_CONTROLLER_PORT} -e PYDEVD_PYCHARM_AGENT_PORT=${PYDEVD_PYCHARM_AGENT_PORT}"
fi

echo "DOCKER_ENV=$DOCKER_ENV"

# Determine which Docker image to use
if [ "$PQC_ENABLED" = "1" ]; then
  DOCKER_IMAGE="faber-alice-demo-pqc"
else
  DOCKER_IMAGE="faber-alice-demo"
fi

# Windows compatibility
if [ "$OSTYPE" = "msys" ]; then
  DOCKER="winpty docker"
fi
DOCKER=${DOCKER:-docker}

# Enhanced Docker run command with PQC support
echo ""
if [ "$PQC_ENABLED" = "1" ]; then
  echo "🚀 Starting PQC-enabled ${AGENT} agent..."
  echo "🔒 Quantum-Safe SSI Workflow: ACTIVE"
else
  echo "🚀 Starting classical ${AGENT} agent..."
fi
echo ""

$DOCKER run --name $AGENT --rm -it ${DOCKER_OPTS} \
    --network=${DOCKER_NET} \
    -p 0.0.0.0:$AGENT_PORT_RANGE:$AGENT_PORT_RANGE \
    ${DOCKER_VOL} \
    $(if [ "$DOCKER_RESOLUTION" = "run" ]; then
      echo "-v $(pwd)/../acapy_agent:/home/aries/acapy_agent \
      -v $(pwd)/../scripts:/home/aries/scripts \
      -v $(pwd)/../demo:/home/aries/demo"
    fi) \
    $DOCKER_ENV \
    $DOCKER_IMAGE $AGENT_MODULE --port $AGENT_PORT $ARGS

# Post-run PQC status
if [ "$PQC_ENABLED" = "1" ]; then
  echo ""
  echo "🎉 PQC-enabled ${AGENT} agent completed!"
  echo "✅ Quantum-Safe SSI operations performed"
  echo ""
fi