#!/usr/bin/env bash
# Simple repository scan for private key material.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

echo "[key-scan] private key markers outside .git:"
private_key_pattern='BEGIN (RSA |EC |OPENSSH )?PRIVATE'
private_key_pattern="${private_key_pattern} KEY"
matches="$(grep -RIl --exclude-dir=.git --exclude='*.zip' -E "$private_key_pattern" . || true)"

if [ -z "$matches" ]; then
  echo "  none"
else
  printf '%s\n' "$matches" | sed 's#^\./#  #'
fi

if find . -path ./.git -prune -o \( -name ca_key.pem -o -name ca_private_key.pem \) -print | grep -q .; then
  echo "[key-scan] WARNING: CA private key file is present."
else
  echo "[key-scan] OK: no CA private key file found."
fi

if printf '%s\n' "$matches" | grep -q './server_root/home/server/server_key.pem'; then
  echo "[key-scan] NOTE: class demo server key is present because server.py requires it at runtime."
fi

exit 0
