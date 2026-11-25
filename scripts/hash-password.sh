#!/usr/bin/env bash
# Prompts without echo and pipes the password to `signal-gate -hash-stdin`.
# Uses ./bin/signal-gate (or $GATE_BINARY) if present, otherwise the image
# built by `docker compose build signal-gate`, run with no network.
set -euo pipefail
cd "$(dirname "$0")/.."
binary=${GATE_BINARY:-./bin/signal-gate}
if [[ -x "$binary" ]]; then
  hasher=("$binary" -hash-stdin)
elif command -v docker >/dev/null && docker image inspect signal-web-gate:local >/dev/null 2>&1; then
  hasher=(docker run --rm -i --network none signal-web-gate:local -hash-stdin)
else
  echo 'Run: docker compose build signal-gate (or build bin/signal-gate) first.' >&2
  exit 2
fi
umask 077
mkdir -p secrets
[[ ! -e secrets/gate_password.argon2 ]] || { echo 'Refusing to overwrite password hash.' >&2; exit 1; }
IFS= read -r -s -p 'Gate password: ' password </dev/tty
printf '\n' >/dev/tty
IFS= read -r -s -p 'Confirm password: ' confirm </dev/tty
printf '\n' >/dev/tty
[[ -n "$password" && "$password" == "$confirm" ]] || { echo 'Empty password or mismatch.' >&2; exit 1; }
# Generate before creating the destination so a failed hash leaves no empty file.
hash=$(printf '%s' "$password" | "${hasher[@]}")
unset password confirm
(set -o noclobber; printf '%s\n' "$hash" > secrets/gate_password.argon2)
unset hash
printf '%s\n' 'Created secrets/gate_password.argon2; set ownership before starting Compose.'
