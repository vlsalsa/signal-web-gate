#!/usr/bin/env bash
# Writes a raw 32-byte HMAC key. Refuses to overwrite an existing file.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets
(set -o noclobber; openssl rand 32 > secrets/session_key)
printf '%s\n' 'Created secrets/session_key; set ownership before starting Compose.'
