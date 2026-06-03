#!/usr/bin/env bash
set -euo pipefail

SSH_HOST="${SSH_HOST:-192.168.10.41}"
SSH_USER="${SSH_USER:-s4il0r}"
IDENTITY_FILE="${IDENTITY_FILE:-$HOME/Documents/Programming/beelink-cleanup/homelab}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_DIR="/tmp/li-sec-agent-k8s"

echo "==> Upload manifests"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" "mkdir -p ${REMOTE_DIR}"
scp -i "$IDENTITY_FILE" -r "${REPO_ROOT}/infra/k8s/staging/"* "${SSH_USER}@${SSH_HOST}:${REMOTE_DIR}/"

echo "==> Apply"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" \
  "kubectl apply -k ${REMOTE_DIR} && kubectl -n secagent-staging get pods,svc"

echo "Qwen: http://${SSH_HOST}:31434/api/tags"
