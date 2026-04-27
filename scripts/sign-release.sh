#!/bin/bash
set -e
KEY="${RELEASE_KEY:-$HOME/projects/ssh-keys/release-keys/nexguard-release-ed25519.pem}"
[ -f "$KEY" ] || { echo "missing release key: $KEY"; exit 1; }
[ -f "$1" ] || { echo "usage: $0 <binary>"; exit 1; }
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$1" -out "$1.sig.bin"
xxd -p -c 256 < "$1.sig.bin" > "$1.sig"
rm -f "$1.sig.bin"
echo "signed: $1.sig"
