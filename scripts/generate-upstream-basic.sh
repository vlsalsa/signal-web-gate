#!/usr/bin/env bash
# Use the SAME username in UPSTREAM_USER. No credentials go on the command line.
set -euo pipefail
cd "$(dirname "$0")/.."
user=${1:-signal}
if [[ ! "$user" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo 'Username must contain only letters, digits, underscore or hyphen.' >&2
  exit 2
fi
umask 077
mkdir -p secrets
if [[ -e secrets/upstream_password || -e secrets/upstream_basic ]]; then
  echo 'Refusing to overwrite upstream credentials.' >&2
  exit 1
fi
password=$(openssl rand -hex 32)
(set -o noclobber; printf '%s' "$password" > secrets/upstream_password)
(set -o noclobber; printf '%s:%s' "$user" "$password" | openssl base64 -A > secrets/upstream_basic)
unset password
printf '%s\n' 'Created both upstream files; set ownership before starting Compose.'
