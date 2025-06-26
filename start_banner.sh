#!/bin/bash

# start_banner.sh: One-command launcher for BannerGrapV2 in Minikube WSL2
# Usage: ./start_banner.sh <BannerGrap args>

# 1. Ensure Minikube is running
if ! minikube status &> /dev/null; then
  echo "[+] Starting Minikube..."
  minikube start --driver=docker
fi

# 2. Point Docker CLI to Minikube's daemon
eval "$(minikube docker-env)"

# 3. Build or rebuild Docker image
echo "[+] Building Docker image in Minikube..."
docker build -t bannerv2 .

# 4. Clean up any old job
echo "[+] Cleaning up old Kubernetes Job..."
kubectl delete job bannerv2-job --ignore-not-found

# 5. Deploy Job with provided arguments
if [ $# -lt 1 ]; then
  echo "Usage: $0 <BannerGrapV2 args>"
  echo "Example: $0 198.51.100.10 443 --proto https --threads 50 --o output.json"
  exit 1
fi

# Convert all CLI args into valid YAML format
ARGS_YAML=""
for arg in "$@"; do
  ARGS_YAML+="\"$arg\", "
done
ARGS_YAML=${ARGS_YAML%, }

# Apply the Kubernetes Job
echo "[+] Deploying new banner scan Job with args: $@"
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: bannerv2-job
spec:
  backoffLimit: 0
  template:
    metadata:
      labels:
        app: bannerv2
    spec:
      restartPolicy: Never
      containers:
        - name: bannerv2
          image: bannerv2
          imagePullPolicy: Never
          args: [$ARGS_YAML]
EOF

# 6. Wait for completion and show logs
echo "[*] Waiting for completion..."
kubectl wait --for=condition=complete job/bannerv2-job --timeout=120s

echo "[*] Logs from banner scan Job:"
kubectl logs job/bannerv2-job

# Optional: cleanup after execution

