#!/usr/bin/env bash
set -euo pipefail

CASES=5064
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

kubectl -n secagent-staging delete pod ref-corpus-sync --ignore-not-found
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
kubectl -n secagent-staging cp /tmp/worker-state.json ref-corpus-sync:/data/corpus/worker-state.json
kubectl -n secagent-staging delete pod ref-corpus-sync --ignore-not-found

kubectl -n secagent-staging delete pod ref-corpus-inspect --ignore-not-found
kubectl apply -f /tmp/inspect-corpus-pod.yaml
kubectl -n secagent-staging wait --for=condition=Ready pod/ref-corpus-inspect --timeout=60s
kubectl -n secagent-staging logs ref-corpus-inspect
kubectl -n secagent-staging delete pod ref-corpus-inspect --ignore-not-found

echo "==> Manual expansion job (expect skip_finished)"
kubectl -n secagent-staging delete job reference-corpus-expander-manual --ignore-not-found
kubectl -n secagent-staging create job --from=cronjob/reference-corpus-expander reference-corpus-expander-manual
kubectl -n secagent-staging wait --for=condition=complete job/reference-corpus-expander-manual --timeout=120s || true
kubectl -n secagent-staging logs job/reference-corpus-expander-manual --tail=20
