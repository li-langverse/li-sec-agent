# SecAgent staging (blackpearl / k3s)

Namespace: `secagent-staging`

## Components

| Workload | Service (cluster) | Node | LAN NodePort |
|----------|-------------------|------|--------------|
| Qwen (Ollama) | `http://qwen-ollama.secagent-staging.svc.cluster.local:11434` | **engine** | `:31434` |
| Worker | `secagent-worker:8787` | any | `:30787` |

OpenAI-compatible API: `http://qwen-ollama:11434/v1/chat/completions`

## Qwen scheduling (GPU)

Pinned to node **`engine`** (`kubernetes.io/hostname: engine`, `gpu=nvidia`, `runtimeClassName: nvidia`, `nvidia.com/gpu: 1`).

| Node | GPU | Notes |
|------|-----|-------|
| **engine** | 1 | Default — homelab training node |
| desktop | 1 | WSL2; change hostname in deployment if needed |
| blackpearl | 0 | Control plane only — do not schedule Qwen here |

To change target node, edit `qwen-ollama.deployment.yaml`:

```yaml
nodeSelector:
  kubernetes.io/hostname: engine   # or desktop
  gpu: nvidia
```

## Telemetry env

From `configmap.yaml`: `SECAGENT_ORG_ID`, `SECAGENT_TIER`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`.

## Apply

```powershell
.\scripts\deploy-staging.ps1
```

## Verify Qwen

```bash
kubectl -n secagent-staging get pods -o wide
kubectl -n secagent-staging logs deploy/qwen-ollama --tail=30
curl -s http://192.168.10.33:31434/api/tags
```
