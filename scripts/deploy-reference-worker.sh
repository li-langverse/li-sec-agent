#!/usr/bin/env bash
# Build reference-worker image on blackpearl, import to k3s, apply manifests.
set -euo pipefail

SSH_HOST="${SSH_HOST:-192.168.10.41}"
SSH_USER="${SSH_USER:-s4il0r}"
IDENTITY_FILE="${IDENTITY_FILE:-$HOME/Documents/Programming/beelink-cleanup/homelab}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_DIR="/tmp/li-sec-agent-reference-worker"
IMAGE="li-sec-agent-reference-worker:staging"

echo "==> Upload repo for image build"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" "mkdir -p ${REMOTE_DIR}"
tar -C "${REPO_ROOT}" -cf - \
  Dockerfile.reference-worker package.json package-lock.json tsconfig.json scripts eval \
  | ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" "tar -C ${REMOTE_DIR} -xf -"

echo "==> Build image on blackpearl"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" \
  "cd ${REMOTE_DIR} && docker build -f Dockerfile.reference-worker -t ${IMAGE} ."

echo "==> Import to k3s containerd"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" \
  "docker save ${IMAGE} | sudo k3s ctr images import -"

echo "==> Upload + apply k8s manifests"
scp -i "$IDENTITY_FILE" -r "${REPO_ROOT}/infra/k8s/reference-worker/"* \
  "${SSH_USER}@${SSH_HOST}:${REMOTE_DIR}/k8s/"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" \
  "kubectl apply -k ${REMOTE_DIR}/k8s/ && kubectl -n secagent-staging get cronjob,pvc"

echo "==> Manual test job"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" \
  "kubectl -n secagent-staging delete job reference-corpus-expander-manual --ignore-not-found && \
   kubectl -n secagent-staging create job --from=cronjob/reference-corpus-expander reference-corpus-expander-manual"

echo "Waiting for job..."
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" \
  "kubectl -n secagent-staging wait --for=condition=complete job/reference-corpus-expander-manual --timeout=600s || true"

echo "==> Job logs"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" \
  "kubectl -n secagent-staging logs job/reference-corpus-expander-manual --tail=80"

echo "==> Corpus stats on PVC (via debug pod)"
ssh -i "$IDENTITY_FILE" "${SSH_USER}@${SSH_HOST}" bash -s <<'REMOTE'
kubectl -n secagent-staging run ref-corpus-inspect --rm -i --restart=Never \
  --image=busybox:1.36 --overrides='{"spec":{"containers":[{"name":"inspect","image":"busybox:1.36","command":["sh","-c","ls -la /data/corpus && wc -c /data/corpus/corpus-latest.json 2>/dev/null; cat /data/corpus/worker-state.json 2>/dev/null"],"volumeMounts":[{"name":"c","mountPath":"/data/corpus"}]}],"volumes":[{"name":"c","persistentVolumeClaim":{"claimName":"reference-corpus-pvc"}}]}}' \
  2>/dev/null || true
REMOTE
