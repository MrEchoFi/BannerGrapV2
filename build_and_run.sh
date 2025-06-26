#!/bin/bash
docker build -t bannerv2 .
kubectl delete job bannerv2-job --ignore-not-found
kubectl apply -f bannerv2-job.yaml
