#!/bin/bash
# Generate CA and server certificates for the FSS secure implementation

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
subjectAltName = IP:10.0.8.2
EOF

echo "Signing server certificate with CA..."
openssl x509 -req -days 365 -in server.csr \
  -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -out server_cert.pem \
  -extfile server_ext.cnf

echo "Verifying..."
openssl verify -CAfile ca_cert.pem server_cert.pem

echo ""
echo "Done. Copy files as follows:"
echo "  server_cert.pem -> server_root/home/server/server_cert.pem"
echo "  server_key.pem  -> server_root/home/server/server_key.pem"
echo "  ca_cert.pem     -> server_root/home/server/ca_cert.pem"
echo "  ca_cert.pem     -> client_root/home/client/ca_cert.pem"
