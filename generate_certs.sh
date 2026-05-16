#!/bin/bash
# Generate CA and server certificates for the FSS secure implementation.
# The CA private key is generated under certs/ for signing only and should not
# be included in submissions unless the assignment explicitly asks for it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "Generating CA key..."
openssl genrsa -out ca_key.pem 2048

echo "Generating CA self-signed certificate..."
openssl req -new -x509 -days 3650 -key ca_key.pem -out ca_cert.pem \
  -subj "/C=US/ST=Colorado/L=Denver/O=FSS-CA/CN=FSS-Root-CA"

echo "Generating server key..."
openssl genrsa -out server_key.pem 2048

echo "Generating server certificate signing request..."
openssl req -new -key server_key.pem -out server.csr \
  -subj "/C=US/ST=Colorado/L=Denver/O=FSS-Server/CN=10.0.8.2"

cat > server_ext.cnf <<EOF
[v3_req]
subjectAltName = IP:10.0.8.2
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

echo "Signing server certificate with CA..."
openssl x509 -req -days 365 -in server.csr \
  -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -out server_cert.pem \
  -extfile server_ext.cnf -extensions v3_req

echo "Verifying..."
openssl verify -CAfile ca_cert.pem server_cert.pem
openssl x509 -in server_cert.pem -noout -ext subjectAltName

echo "Copying runtime certificate files..."
cp server_cert.pem "$SCRIPT_DIR/server_root/home/server/server_cert.pem"
cp server_key.pem "$SCRIPT_DIR/server_root/home/server/server_key.pem"
cp ca_cert.pem "$SCRIPT_DIR/server_root/home/server/ca_cert.pem"
cp ca_cert.pem "$SCRIPT_DIR/client_root/home/client/ca_cert.pem"

echo "Removing non-runtime private key and serial artifacts from certs/..."
rm -f ca_key.pem server_key.pem ca_cert.srl server_ext.cnf

echo ""
echo "Done. Runtime certs copied into client_root and server_root."
