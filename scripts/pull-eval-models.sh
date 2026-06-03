#!/usr/bin/env bash
# Pull Qwen eval models on secagent-staging qwen-ollama pod (via blackpearl SSH).
set -euo pipefail

SSH_HOST="${SSH_HOST:-blackpearl}"
NS="${NS:-secagent-staging}"

MODELS=(
  "qwen2.5-coder:3b"
  "qwen3.5:9b"
  "qwen2.5-coder:14b"
  "qwen3:14b"
)

echo "==> Pulling models on ${SSH_HOST} (${NS}/qwen-ollama)"
for model in "${MODELS[@]}"; do
  echo "--- ${model}"
  ssh "${SSH_HOST}" "kubectl -n ${NS} exec deploy/qwen-ollama -- ollama pull ${model}" || \
    echo "WARN: ${model} pull failed"
done

echo "==> Attempt qwen3.5:27b (expected OOM on RTX 3060 12GB)"
ssh "${SSH_HOST}" "kubectl -n ${NS} exec deploy/qwen-ollama -- ollama pull qwen3.5:27b" || \
  echo "Expected: qwen3.5:27b does not fit 12GB VRAM"

echo "==> Installed models"
ssh "${SSH_HOST}" "kubectl -n ${NS} exec deploy/qwen-ollama -- ollama list"
