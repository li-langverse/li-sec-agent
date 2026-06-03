# Deploy li-sec-agent to blackpearl staging (k3s)
# Usage: .\scripts\deploy-staging.ps1 [-SshHost 192.168.10.41] [-DryRun]

param(
  [string]$SshHost = "192.168.10.41",
  [string]$SshUser = "s4il0r",
  [string]$IdentityFile = "$env:USERPROFILE\Documents\Programming\beelink-cleanup\homelab",
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$StagingPath = Join-Path $RepoRoot "infra\k8s\staging"
$RemoteDir = "/tmp/li-sec-agent-k8s"

Write-Host "==> Packaging kustomize overlay from $StagingPath"
if (-not (Test-Path $StagingPath)) {
  throw "Missing staging manifests: $StagingPath"
}

$sshArgs = @(
  "-i", $IdentityFile,
  "-o", "StrictHostKeyChecking=accept-new",
  "${SshUser}@${SshHost}"
)

if ($DryRun) {
  Write-Host "[dry-run] Would rsync and kubectl apply -k $RemoteDir"
  exit 0
}

Write-Host "==> Uploading manifests to ${SshHost}:${RemoteDir}"
ssh @sshArgs "mkdir -p $RemoteDir"
scp -i $IdentityFile -r "$StagingPath\*" "${SshUser}@${SshHost}:${RemoteDir}/"

Write-Host "==> Applying manifests"
ssh @sshArgs "kubectl apply -k $RemoteDir && kubectl -n secagent-staging rollout status deployment/qwen-ollama --timeout=600s || true"
ssh @sshArgs @"
echo '--- pods ---'
kubectl -n secagent-staging get pods -o wide
echo '--- services ---'
kubectl -n secagent-staging get svc
echo '--- qwen health (in-cluster) ---'
kubectl -n secagent-staging run curl-qwen --rm -i --restart=Never --image=curlimages/curl:8.12.1 --command -- curl -sf http://qwen-ollama:11434/api/tags || echo 'qwen not ready yet'
"@

Write-Host "Done. Qwen NodePort: http://${SshHost}:31434/api/tags"
