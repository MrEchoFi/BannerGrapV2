#!/bin/bash

# Check if at least one arg is provided
if [ $# -lt 1 ]; then
  echo "Usage: $0 <BannerGrapV2 args>"
  echo "Example: $0 198.51.100.10 443 --proto https --threads 50 --o output.json"
  exit 1
fi

# Delete previous job
echo "[+] Deleting previous job if it exists..."
kubectl delete job bannerv2-job --ignore-not-found

# Convert all arguments to YAML array format
ARGS_YAML=""
for arg in "$@"; do
  ARGS_YAML+="\"$arg\", "
done
ARGS_YAML=${ARGS_YAML%, }  # Remove trailing comma and space

# Deploy Kubernetes Job with passed args
echo "[+] Deploying new job..."
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
          args: [${ARGS_YAML}]
EOF

# Wait for pod to spin up and complete
echo "[*] Waiting for pod to be ready..."
sleep 2
POD_NAME=$(kubectl get pods -l job-name=bannerv2-job -o jsonpath="{.items[0].metadata.name}")

echo "[*] Waiting for completion..."
kubectl wait --for=condition=complete pod/$POD_NAME --timeout=90s || echo "[!] Pod timed out"

# Show logs from scan
echo "[*] Output from $POD_NAME"
kubectl logs $POD_NAME

# Uncomment below to auto-cleanup after execution
# echo "[*] Cleaning up job..."

