#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname "$0")/certs"
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$(dirname "$0")/certs/key.pem" \
  -out    "$(dirname "$0")/certs/cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "Self-signed cert written to caddy/certs/."
echo "For production, replace with a real cert (e.g. Let's Encrypt via Certbot)."
