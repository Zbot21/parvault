#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Neighborhood Cloud — 1-Command Hetzner Cloud Bootstrapper (< $50-$95/month)
# ==============================================================================
# Prerequisites:
#   1. Install Hetzner CLI (`winget install HetznerCloud.CLI` or `apt install hcloud-cli`)
#   2. Set `export HCLOUD_TOKEN="your-api-token"`
#   3. Run `./deploy/control-plane/provision-hetzner.sh`
# ==============================================================================

if [ -z "${HCLOUD_TOKEN:-}" ]; then
  echo "ERROR: Please set HCLOUD_TOKEN=<your-hetzner-api-token> first."
  exit 1
fi

SSH_KEY_NAME="${SSH_KEY_NAME:-default}"
IMAGE="ubuntu-24.04"
SERVER_TYPE="cax11" # 2 vCPU ARM64, 4 GB RAM, 40 GB NVMe, 20 TB free traffic (~$4.15/mo!)

echo "[1/3] Provisioning Primary Control-Plane + Grafana + Website + Seed Node #1 (ash / US-East)..."
hcloud server create \
  --name "parvault-control-01" \
  --type "$SERVER_TYPE" \
  --image "$IMAGE" \
  --location "ash" \
  --ssh-key "$SSH_KEY_NAME"

echo "[2/3] Provisioning Regional Zero-Trust Seed Anchors (US-West, EU-Central, EU-North, APAC)..."
declare -A LOCATIONS=(
  ["parvault-seed-us-west"]="hil"
  ["parvault-seed-eu-central"]="fsn1"
  ["parvault-seed-eu-north"]="hel1"
  ["parvault-seed-apac"]="sin"
)

for NAME in "${!LOCATIONS[@]}"; do
  LOC="${LOCATIONS[$NAME]}"
  hcloud server create \
    --name "$NAME" \
    --type "$SERVER_TYPE" \
    --image "$IMAGE" \
    --location "$LOC" \
    --ssh-key "$SSH_KEY_NAME" &
done
wait

echo "[3/3] Provisioned servers:"
hcloud server list
