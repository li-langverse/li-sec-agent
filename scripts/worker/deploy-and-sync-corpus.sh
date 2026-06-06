#!/usr/bin/env bash
set -euo pipefail

REMOTE_DIR="/tmp/li-sec-agent-reference-worker"
IMAGE="li-sec-agent-reference-worker:staging"

mkdir -p "${REMOTE_DIR}"
tar -C "${REMOTE_DIR}" -xf /tmp/ref-worker-src.tar
cd "${REMOTE_DIR}"

echo "==> Build reference-worker image"
docker build -f Dockerfile.reference-worker -t "${IMAGE}" .

echo "==> Import to k3s"
docker save "${IMAGE}" | sudo k3s ctr images import -

echo "==> Apply k8s manifests"
kubectl apply -k infra/k8s/reference-worker/

echo "==> Sync corpus files to PVC"
kubectl -n secagent-staging delete pod ref-corpus-sync --ignore-not-found
kubectl apply -f /tmp/inspect-corpus-pod.yaml
# reuse inspect pod as a holder; copy files in via tar mount trick
kubectl -n secagent-staging delete pod ref-corpus-sync --ignore-not-found

cat >/tmp/ref-corpus-sync-pod.yaml <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: ref-corpus-sync
  namespace: secagent-staging
spec:
  nodeSelector:
    kubernetes.io/hostname: blackpearl
  restartPolicy: Never
  containers:
    - name: sync
      image: busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      volumeMounts:
        - name: c
          mountPath: /data/corpus
  volumes:
    - name: c
      persistentVolumeClaim:
        claimName: reference-corpus-pvc
YAML

kubectl apply -f /tmp/ref-corpus-sync-pod.yaml
kubectl -n secagent-staging wait --for=condition=Ready pod/ref-corpus-sync --timeout=60s

mkdir -p /tmp/corpus-files
tar -xf /tmp/corpus-sync.tar -C /tmp/corpus-files
for f in corpus-v1.json manifest.json synthetic-expanded.json ossf-subset.json primevul-subset.json; do
  kubectl -n secagent-staging cp "/tmp/corpus-files/${f}" "ref-corpus-sync:/data/corpus/${f}"
done
cp -f /tmp/corpus-files/corpus-v1.json /tmp/corpus-files/corpus-latest.json
cp -f /tmp/corpus-files/manifest.json /tmp/corpus-files/manifest-latest.json
kubectl -n secagent-staging cp /tmp/corpus-files/corpus-latest.json ref-corpus-sync:/data/corpus/corpus-latest.json
kubectl -n secagent-staging cp /tmp/corpus-files/manifest-latest.json ref-corpus-sync:/data/corpus/manifest-latest.json

CASES=$(python3 -c "import json; print(json.load(open('/tmp/corpus-files/manifest.json'))['stats']['total_cases'])")
cat >/tmp/worker-state.json <<EOF
{
  "target_cases": 5000,
  "current_cases": ${CASES},
  "ossf_limit": 218,
  "target_extra": 3700,
  "mitre_offset": 25,
  "cycle": 6,
  "finished": true,
  "last_run": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
kubectl -n secagent-staging cp /tmp/worker-state.json ref-corpus-sync:/data/corpus/worker-state.json
kubectl -n secagent-staging delete pod ref-corpus-sync --ignore-not-found

echo "==> Corpus synced: ${CASES} cases"
kubectl -n secagent-staging run ref-corpus-inspect --rm -i --restart=Never \
  --image=busybox:1.36 \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"blackpearl"},"containers":[{"name":"inspect","image":"busybox:1.36","command":["sh","-c","wc -c /data/corpus/corpus-v1.json; cat /data/corpus/worker-state.json"],"volumeMounts":[{"name":"c","mountPath":"/data/corpus"}]}],"volumes":[{"name":"c","persistentVolumeClaim":{"claimName":"reference-corpus-pvc"}}]}}' \
  || true

echo "==> Trigger manual expansion job (verify +0 skip finished)"
kubectl -n secagent-staging delete job reference-corpus-expander-manual --ignore-not-found
kubectl -n secagent-staging create job --from=cronjob/reference-corpus-expander reference-corpus-expander-manual
kubectl -n secagent-staging wait --for=condition=complete job/reference-corpus-expander-manual --timeout=600s || true
kubectl -n secagent-staging logs job/reference-corpus-expander-manual --tail=40
