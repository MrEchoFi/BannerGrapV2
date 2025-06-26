#!/bin/bash
eval "$(minikube docker-env)"                     # ← add this

echo "[+] Deleting previous job..."
kubectl delete job bannerv2-job --ignore-not-found

echo "[+] Building image in Minikube..."
docker build -t bannerv2 .

echo "[+] Deploying job..."
kubectl apply -f bannerv2-job.yaml

# ...rest of script unchanged...

