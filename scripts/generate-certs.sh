#!/bin/bash
set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAYS_VALID=365

echo "=== MASQUE Certificate Generation Script ==="
echo "Output directory: $CERT_DIR"
echo ""

# CA証明書の生成
echo "[1/5] Generating CA key and certificate..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096

openssl req -new -x509 -days $DAYS_VALID -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=JP/ST=Tokyo/L=Tokyo/O=MASQUE-Dev/OU=CA/CN=MASQUE-Root-CA"

echo "✓ CA certificate generated"
echo ""

# Relay Server証明書の生成
echo "[2/5] Generating Relay Server certificate..."
openssl genrsa -out "$CERT_DIR/relay-server.key" 2048

openssl req -new -key "$CERT_DIR/relay-server.key" \
    -out "$CERT_DIR/relay-server.csr" \
    -subj "/C=JP/ST=Tokyo/L=Tokyo/O=MASQUE-Dev/OU=Relay/CN=relay-server"

# SAN (Subject Alternative Name) 設定ファイル
cat > "$CERT_DIR/relay-server.ext" <<EOF
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = relay
DNS.2 = relay-server
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.28.0.10
IP.3 = 0.0.0.0
EOF

openssl x509 -req -in "$CERT_DIR/relay-server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/relay-server.crt" \
    -days $DAYS_VALID -extfile "$CERT_DIR/relay-server.ext"

rm "$CERT_DIR/relay-server.csr" "$CERT_DIR/relay-server.ext"
echo "✓ Relay Server certificate generated"
echo ""

# Client 1証明書の生成
echo "[3/5] Generating Client 1 certificate..."
openssl genrsa -out "$CERT_DIR/client-1.key" 2048

openssl req -new -key "$CERT_DIR/client-1.key" \
    -out "$CERT_DIR/client-1.csr" \
    -subj "/C=JP/ST=Tokyo/L=Tokyo/O=MASQUE-Dev/OU=Client/CN=client-1"

cat > "$CERT_DIR/client-1.ext" <<EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "$CERT_DIR/client-1.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client-1.crt" \
    -days $DAYS_VALID -extfile "$CERT_DIR/client-1.ext"

rm "$CERT_DIR/client-1.csr" "$CERT_DIR/client-1.ext"
echo "✓ Client 1 certificate generated"
echo ""

# Client 2証明書の生成
echo "[4/5] Generating Client 2 certificate..."
openssl genrsa -out "$CERT_DIR/client-2.key" 2048

openssl req -new -key "$CERT_DIR/client-2.key" \
    -out "$CERT_DIR/client-2.csr" \
    -subj "/C=JP/ST=Tokyo/L=Tokyo/O=MASQUE-Dev/OU=Client/CN=client-2"

cat > "$CERT_DIR/client-2.ext" <<EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "$CERT_DIR/client-2.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client-2.crt" \
    -days $DAYS_VALID -extfile "$CERT_DIR/client-2.ext"

rm "$CERT_DIR/client-2.csr" "$CERT_DIR/client-2.ext"
echo "✓ Client 2 certificate generated"
echo ""

# 権限設定
echo "[5/5] Setting permissions..."
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "Generated files:"
ls -lh "$CERT_DIR"/*.{crt,key} 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo "Verification:"
echo "  CA cert:"
openssl x509 -in "$CERT_DIR/ca.crt" -noout -subject -dates | sed 's/^/    /'
echo "  Relay cert:"
openssl x509 -in "$CERT_DIR/relay-server.crt" -noout -subject -dates | sed 's/^/    /'
echo "  Client 1 cert:"
openssl x509 -in "$CERT_DIR/client-1.crt" -noout -subject -dates | sed 's/^/    /'
echo "  Client 2 cert:"
openssl x509 -in "$CERT_DIR/client-2.crt" -noout -subject -dates | sed 's/^/    /'
echo ""
echo "✓ All certificates ready for use"
