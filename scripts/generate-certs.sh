#!/usr/bin/env bash
set -euo pipefail

# Generate self-signed TLS certificates for Umbra testnet.
# Creates a CA, server certificate (with SANs for Docker service names),
# and a client certificate for faucet/wallet mTLS.

CERT_DIR="${1:-$(dirname "$0")/../certs}"
DAYS=3650
KEY_BITS=2048

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "Generating certificates in $(pwd) ..."

# --- CA ---
if [ ! -f ca.key ]; then
    openssl genrsa -out ca.key "$KEY_BITS" 2>/dev/null
    openssl req -new -x509 -days "$DAYS" -key ca.key -out ca.crt \
        -subj "/CN=Umbra Testnet CA" 2>/dev/null
    echo "  CA certificate created (ca.key, ca.crt)"
else
    echo "  CA certificate already exists, skipping"
fi

# --- Server certificate (validators) ---
cat > server.ext <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_dn
prompt = no

[req_dn]
CN = umbra-validator

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = validator-1
DNS.2 = validator-2
DNS.3 = validator-3
DNS.4 = localhost
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

openssl genrsa -out server.key "$KEY_BITS" 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -config server.ext 2>/dev/null
openssl x509 -req -days "$DAYS" -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -extensions v3_req -extfile server.ext 2>/dev/null
rm -f server.csr server.ext
echo "  Server certificate created (server.key, server.crt)"

# --- Client certificate (faucet / wallet) ---
openssl genrsa -out client.key "$KEY_BITS" 2>/dev/null
openssl req -new -key client.key -out client.csr \
    -subj "/CN=umbra-client" 2>/dev/null
openssl x509 -req -days "$DAYS" -in client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt 2>/dev/null
rm -f client.csr
echo "  Client certificate created (client.key, client.crt)"

rm -f ca.srl
echo "Done. Certificates are in $(pwd)"
