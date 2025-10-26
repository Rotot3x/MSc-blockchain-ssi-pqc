# Local ACA-Py Build Guide

This infrastructure uses **locally built ACA-Py images** instead of pulling from remote registries.

## How It Works

The setup automatically builds ACA-Py from the local source code in the parent directory (`../`), similar to how the demo system works:

1. **Base Image**: `acapy-base:latest` - Built from `../docker/Dockerfile`
2. **Demo Image**: `acapy-ssi-demo:latest` - Built from `../docker/Dockerfile.demo`

## Build Process

### Automatic Build
The setup and start scripts automatically handle building:

```bash
# Builds images during setup
./scripts/setup.sh

# Checks for images and builds if missing
./scripts/start.sh
```

### Manual Build
You can also build images manually:

```bash
# Build all ACA-Py images
./scripts/build.sh

# Or build specific images
docker compose build acapy-base
docker compose build acapy-ssi-demo
```

## Build Context

The Docker build context is set to the parent directory (`../`) to access:
- `/acapy_agent` - ACA-Py source code
- `/docker/Dockerfile` - Base image definition
- `/docker/Dockerfile.demo` - Demo image with plugins
- `/scripts` - Utility scripts
- `/demo` - Demo files

## Volume Mounts

The running containers also mount local source for development:
- `../acapy_agent:/home/aries/acapy_agent:ro`
- `../scripts:/home/aries/scripts:ro`
- `../demo:/home/aries/demo:ro`

This allows for:
- Hot reloading of code changes
- Local development workflow
- Plugin development and testing

## Build Arguments

The following build arguments are used:

### acapy-base
- `python_version: "3.12"`
- `acapy_version: "1.1.0"`

### acapy-ssi-demo
- `from_image: acapy-base:latest`
- `all_extras: 1` - Installs all ACA-Py extras

## Troubleshooting

### Build Failures
```bash
# Clean up failed builds
docker system prune -f

# Rebuild from scratch
docker compose build --no-cache acapy-base acapy-ssi-demo
```

### Missing Dependencies
Make sure the parent directory contains:
- `pyproject.toml`
- `poetry.lock`
- `acapy_agent/` directory
- `docker/` directory

### Permission Issues
```bash
# Fix permissions if needed
sudo chown -R $USER:$USER ../acapy_agent
```

## Comparison to Demo

This setup is inspired by `./demo/run_demo` which builds:
1. `acapy-base` from `../docker/Dockerfile`
2. `faber-alice-demo` from `../docker/Dockerfile.demo`

Our setup builds:
1. `acapy-base` (same as demo)
2. `acapy-ssi-demo` (our customized version)

## Benefits

- **No Registry Dependencies**: No need to pull from ghcr.io
- **Local Development**: Work with local source code
- **Plugin Support**: Full plugin development environment
- **Consistent Builds**: Same environment as demo system