#!/usr/bin/env bash
set -euo pipefail

# FirmAE run.sh expects $USER to be set
export USER="${USER:-root}"
export HOME="${HOME:-/root}"

FIRMWARE_PATH="${1:-}"
MODE="${2:-auto}"

if [[ -z "$FIRMWARE_PATH" ]]; then
    echo "Usage: entrypoint.sh <firmware_path> [mode]"
    exit 1
fi

# Start PostgreSQL (required by FirmAE)
if command -v pg_isready &>/dev/null; then
    service postgresql start 2>/dev/null || true
    # Wait for PostgreSQL to be ready
    for i in $(seq 1 10); do
        pg_isready -q && break
        sleep 1
    done
fi

case "$MODE" in
    firmae)
        if [[ -x /opt/FirmAE/run.sh ]]; then
            cd /opt/FirmAE
            ./run.sh -c auto "$FIRMWARE_PATH"
        else
            echo "FirmAE not installed at /opt/FirmAE"
            exit 1
        fi
        ;;
    qemu-user)
        # QEMU user-mode fallback handled by Python
        echo "QEMU user-mode: use Python module directly"
        ;;
    auto|*)
        if [[ -x /opt/FirmAE/run.sh ]]; then
            cd /opt/FirmAE
            ./run.sh -c auto "$FIRMWARE_PATH" || echo "FirmAE boot failed, try qemu-user"
        else
            echo "No FirmAE, falling back to basic inspection"
        fi
        ;;
esac
