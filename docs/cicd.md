# 🚀 CI/CD Integration Guide

## Overview
Integrate BannerGrapV2 into your CI/CD pipelines for automated security scanning and vulnerability detection.

## GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install BannerGrapV2
        run: |
          git clone https://github.com/MrEchoFi/BannerGrapV2.git
          cd BannerGrapV2
          go build -o bannergrapv2 .
      
      - name: Run Security Scan
        run: ./BannerGrapV2/bannergrapv2 -f targets.txt -proto https -o scan-results.json
      
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICAL=$(jq '[.[] | select(.vulnerabilities[] | contains("Critical"))] | length' scan-results.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Critical vulnerabilities found!"
            exit 1
          fi
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: scan-results.json
```

## GitLab CI/CD

```yaml
stages:
  - scan
  - report

security_scan:
  stage: scan
  image: golang:1.21
  script:
    - git clone https://github.com/MrEchoFi/BannerGrapV2.git
    - cd BannerGrapV2 && go build -o bannergrapv2 .
    - ./bannergrapv2 -f ../targets.txt -proto https -o scan-results.json
    - |
      CRITICAL=$(jq '[.[] | select(.vulnerabilities[] | contains("Critical"))] | length' scan-results.json)
      [ "$CRITICAL" -gt 0 ] && exit 1 || exit 0
  artifacts:
    paths:
      - scan-results.json
    expire_in: 30 days
```

## Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Setup') {
            steps {
                sh 'git clone https://github.com/MrEchoFi/BannerGrapV2.git'
                sh 'cd BannerGrapV2 && go build -o bannergrapv2 .'
            }
        }
        stage('Scan') {
            steps {
                sh './BannerGrapV2/bannergrapv2 -f targets.txt -proto https -o scan-results.json'
            }
        }
        stage('Analyze') {
            steps {
                script {
                    def critical = sh(
                        script: "jq '[.[] | select(.vulnerabilities[] | contains(\"Critical\"))] | length' scan-results.json",
                        returnStdout: true
                    ).trim()
                    if (critical.toInteger() > 0) {
                        error("Critical vulnerabilities detected!")
                    }
                }
            }
        }
    }
    post {
        always {
            archiveArtifacts 'scan-results.json'
        }
    }
}
```

## Docker Integration

```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
RUN git clone https://github.com/MrEchoFi/BannerGrapV2.git
RUN cd BannerGrapV2 && go build -o bannergrapv2 .
ENTRYPOINT ["./BannerGrapV2/bannergrapv2"]
```

## Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-scan
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: bannergrapv2
            image: bannergrapv2:latest
            args: ["-f", "/config/targets.txt", "-proto", "https", "-o", "/results/scan.json"]
          restartPolicy: OnFailure
```

## Best Practices

1. **Secret Management**: Store targets and credentials in CI secrets
2. **Fail Fast**: Exit pipeline on critical vulnerabilities
3. **Scheduled Scans**: Run daily/weekly automated scans
4. **Notifications**: Alert teams on failures
5. **Artifact Storage**: Keep scan results for compliance

## Pre-Deployment Scanning

```bash
#!/bin/bash
echo "[*] Pre-deployment security scan..."
bannergrapv2 -f production-targets.txt -proto https -o pre-deploy.json

CRITICAL=$(jq '[.[] | select(.vulnerabilities[] | contains("Critical"))] | length' pre-deploy.json)
if [ "$CRITICAL" -gt 0 ]; then
    echo "ERROR: Deployment blocked - critical vulnerabilities detected!"
    exit 1
fi
echo "[+] Security check passed - proceeding with deployment"
```

## Post-Deployment Verification

```bash
#!/bin/bash
echo "[*] Post-deployment verification..."
sleep 30  # Wait for services to stabilize
bannergrapv2 -f production-targets.txt -proto https -o post-deploy.json
diff pre-deploy.json post-deploy.json > deployment-diff.txt
echo "[+] Verification complete"
```
