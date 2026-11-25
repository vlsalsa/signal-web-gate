#!/usr/bin/env bash
# Guided setup for a Mac (Docker Desktop) or a Linux PC.
#
#   bash scripts/setup.sh            first-time setup (safe to run again)
#   bash scripts/setup.sh password   change the gate password (signs out all browsers)
#   bash scripts/setup.sh unlock     clear a password-page lockout (too many wrong tries)
#   bash scripts/setup.sh jpeg       make JPEG the default video encoder (for Menlo-style browsers)
#
# It asks a few questions, writes .env, creates ./secrets, builds the gate image,
# stores your password only as an argon2id hash, and starts the stack.
# Nothing you type is echoed or written to shell history.
set -euo pipefail
cd "$(dirname "$0")/.."

bold=$'\033[1m'; green=$'\033[32m'; red=$'\033[31m'; yellow=$'\033[33m'; reset=$'\033[0m'
if [[ ! -t 1 ]]; then bold='' green='' red='' yellow='' reset=''; fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s== %s ==%s\n' "$bold" "$*" "$reset"; }
ok()   { printf '%s  OK%s  %s\n' "$green" "$reset" "$*"; }
warn() { printf '%s  !!%s  %s\n' "$yellow" "$reset" "$*"; }
die()  { printf '\n%sSTOPPED:%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }

ask() { # ask VAR "Question" [default]
  local __var=$1 __q=$2 __def=${3:-} __ans
  if [[ -n "$__def" ]]; then
    IFS= read -r -p "$__q [$__def]: " __ans </dev/tty || true
    __ans=${__ans:-$__def}
  else
    IFS= read -r -p "$__q: " __ans </dev/tty || true
  fi
  # Trim surrounding spaces and stray quotes from pasted values.
  __ans=$(printf '%s' "$__ans" | sed -e 's/^[[:space:]"'"'"']*//' -e 's/[[:space:]"'"'"']*$//')
  printf -v "$__var" '%s' "$__ans"
}
ask_secret() { # ask_secret VAR "Prompt"
  local __var=$1 __q=$2 __ans
  IFS= read -r -s -p "$__q: " __ans </dev/tty || true
  printf '\n' >/dev/tty
  printf -v "$__var" '%s' "$__ans"
}
yes_no() { # yes_no "Question" default(y/n)
  local a; IFS= read -r -p "$1 [$2]: " a </dev/tty || true; a=${a:-$2}
  [[ "$a" =~ ^[Yy] ]]
}

compose() { docker compose "$@"; }

# ------------------------------------------------------------------ checks
check_docker() {
  step "1/6  Checking Docker"
  command -v docker >/dev/null 2>&1 || die "Docker isn't installed (or Terminal can't find it).
  Install Docker Desktop from https://www.docker.com/products/docker-desktop/ , open it once,
  wait until it says it's running, then close and reopen Terminal and run this again."
  docker info >/dev/null 2>&1 || die "Docker is installed but not running.
  Open Docker Desktop, wait for 'Engine running' (green) at the bottom left, then run this again."
  docker compose version >/dev/null 2>&1 || die "'docker compose' is missing. Update Docker Desktop and try again."
  command -v openssl >/dev/null 2>&1 || die "openssl is missing. On Linux install it with your package manager."
  ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) is running"
  local os; os=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)
  # SIGNAL_SETUP_MODE=desktop|native overrides the guess (e.g. for Colima or Rancher Desktop).
  if [[ "${SIGNAL_SETUP_MODE:-}" == desktop ]] || [[ "${SIGNAL_SETUP_MODE:-}" != native && \
       ( "$(uname -s)" == Darwin || "$os" == *"Docker Desktop"* || "$os" == *OrbStack* ) ]]; then
    desktop=1; ok "Docker runs in a VM ($os): using compose.desktop.yml"
  else
    desktop=0; ok "Native Linux Docker ($os)"
  fi
  if [[ "$(uname -m)" == arm64 || "$(uname -m)" == aarch64 ]]; then
    warn "This computer has an ARM (Apple-silicon) chip. The Signal image is x86-64 only, so"
    warn "Docker emulates it. In Docker Desktop > Settings > General, keep"
    warn "'Use Rosetta for x86_64/amd64 emulation on Apple Silicon' turned on."
  fi
  case "$PWD" in
    */Library/Mobile\ Documents/*|*/Dropbox/*|*/OneDrive*|*/Google\ Drive/*)
      warn "This folder looks cloud-synced ($PWD)."
      warn "Your secrets would be uploaded. Move the folder to your home folder (e.g. ~/signal-web-gate)."
      yes_no "Continue anyway?" n || exit 1 ;;
  esac
  if [[ "$(uname -s)" == Darwin && ( "$PWD" == "$HOME/Desktop"* || "$PWD" == "$HOME/Documents"* ) ]]; then
    warn "Desktop and Documents may be synced to iCloud. ~/signal-web-gate is a safer place."
  fi
}

# ------------------------------------------------------------------ .env
set_env() { # set_env KEY VALUE  (in .env, replacing the line)
  local key=$1 val=$2 tmp
  tmp=$(mktemp .env.tmp.XXXXXX)
  if grep -q "^${key}=" .env; then
    awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{print k "=" v; next} {print}' .env > "$tmp"
  else
    cat .env > "$tmp"; printf '%s=%s\n' "$key" "$val" >> "$tmp"
  fi
  cat "$tmp" > .env; rm -f "$tmp"
}
get_env() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }

configure_env() {
  step "2/6  Your settings (.env)"
  if [[ -f .env ]] && ! grep -q 'REPLACE_WITH\|YOUR_TEAM\|signal\.example\.com' .env; then
    say "You already have a .env file:"
    grep -E '^(GATE_ORIGIN|GATE_TEAM|GATE_ALLOWED_EMAIL|TZ)=' .env | sed 's/^/    /'
    if yes_no "Keep these settings?" y; then ensure_compose_file; ok "Kept .env"; return; fi
  fi
  [[ -f .env ]] || cp .env.example .env
  chmod 600 .env

  local host team aud email tz
  say "Answer with what you copied from Cloudflare (see the walkthrough, steps 4-6)."
  while :; do
    ask host "1) Your Signal web address, e.g. signal.example.com"
    host=${host#https://}; host=${host#http://}; host=${host%%/*}; host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
    [[ "$host" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]] && break
    warn "That doesn't look like a web address. Type only the name, like signal.example.com"
  done
  while :; do
    ask team "2) Your Cloudflare team name (the NAME in NAME.cloudflareaccess.com)"
    team=${team#https://}; team=${team%%/*}; team=${team%.cloudflareaccess.com}; team=$(printf '%s' "$team" | tr '[:upper:]' '[:lower:]')
    [[ "$team" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] && break
    warn "Use just the team name, for example: myfamily"
  done
  while :; do
    ask aud "3) The Application Audience (AUD) tag of your Access application"
    [[ "$aud" =~ ^[A-Za-z0-9]{32,128}$ ]] && break
    warn "The AUD tag is a long string of letters and numbers (usually 64). Copy it again."
  done
  while :; do
    ask email "4) Email address(es) allowed in (comma-separated, same as the Access policy)"
    email=$(printf '%s' "$email" | tr -d ' ' | tr '[:upper:]' '[:lower:]')
    [[ "$email" =~ ^[^@,]+@[^@,]+\.[^@,]+(,[^@,]+@[^@,]+\.[^@,]+)*$ ]] && break
    warn "That doesn't look like an email address."
  done
  tz=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' || true)
  [[ "$tz" =~ ^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*$ ]] || tz=Etc/UTC
  ask tz "5) Time zone" "$tz"

  set_env GATE_ORIGIN "https://$host"
  set_env GATE_TEAM "https://$team.cloudflareaccess.com"
  set_env GATE_AUD "$aud"
  set_env GATE_ALLOWED_EMAIL "$email"
  set_env TZ "$tz"
  ensure_compose_file
  ok "Saved .env"
}
add_compose_files() { # add_compose_files FILE... : keep what's listed, add any missing
  local cur f out=docker-compose.yml
  local -a have want
  cur=$(get_env COMPOSE_FILE)
  IFS=':;' read -r -a have <<< "$cur"
  want=("${have[@]+"${have[@]}"}" "$@")
  for f in "${want[@]+"${want[@]}"}"; do
    f=${f//[[:space:]]/}
    [[ -n "$f" && "$f" != docker-compose.yml ]] || continue
    case ":$out:" in *":$f:"*) ;; *) out="$out:$f" ;; esac
  done
  [[ "$out" == "$cur" ]] || set_env COMPOSE_FILE "$out"
}
ensure_compose_file() {
  if [[ "$desktop" == 1 ]]; then add_compose_files compose.desktop.yml; fi
}

# ------------------------------------------------------------------ secrets
make_secrets() {
  step "3/6  Secrets (saved in ./secrets, never uploaded)"
  umask 077
  mkdir -p secrets; chmod 700 secrets
  if [[ -s secrets/session_key ]]; then ok "Session key already exists"; else
    rm -f secrets/session_key; ./scripts/generate-session-key.sh >/dev/null; ok "Created a session key"; fi
  if [[ -s secrets/upstream_password && -s secrets/upstream_basic ]]; then ok "Internal Signal login already exists"; else
    rm -f secrets/upstream_password secrets/upstream_basic
    ./scripts/generate-upstream-basic.sh "$(get_env UPSTREAM_USER | sed 's/^$/signal/')" >/dev/null
    ok "Created the internal Signal login"; fi
  if [[ -s secrets/tunnel_token ]] && yes_no "A tunnel token is already saved. Keep it?" y; then ok "Kept tunnel token"; else
    local tok
    say "Go to the Cloudflare tab from walkthrough step 6, copy the install command again, and paste it here"
    say "(or paste just the token)."
    say "Nothing will appear while you paste. That's normal. Press Return when done."
    while :; do
      ask_secret tok "Tunnel token"
      tok=$(printf '%s' "$tok" | tr -s ' \t' '\n' | grep -E '^eyJ[A-Za-z0-9+/_=-]{40,}$' | tail -1 || true)
      [[ -n "$tok" ]] && break
      warn "That wasn't a tunnel token. It is one long line starting with eyJ. Try again."
    done
    rm -f secrets/tunnel_token
    (set -o noclobber; printf '%s' "$tok" > secrets/tunnel_token); unset tok
    ok "Saved the tunnel token"
  fi
}

build_gate() {
  step "4/6  Building the password gate (first time: a few minutes)"
  compose build signal-gate || die "The build failed. Check your internet connection and run this again."
  ok "Built signal-web-gate:local"
}

set_password() {
  local force=${1:-0}
  step "5/6  Your gate password"
  if [[ -s secrets/gate_password.argon2 && "$force" != 1 ]]; then ok "A password is already set (use: bash scripts/setup.sh password)"; return; fi
  docker image inspect signal-web-gate:local >/dev/null 2>&1 || build_gate
  say "Choose a password for the dark Signal password page. Use at least 12 characters."
  say "Typing won't show on screen. Store it in a password manager."
  local pw pw2 hash
  while :; do
    ask_secret pw "New gate password"
    ask_secret pw2 "Type it again"
    if [[ "$pw" != "$pw2" ]]; then warn "They didn't match. Try again."; continue; fi
    if (( ${#pw} < 12 )); then warn "Too short. Use 12 or more characters."; continue; fi
    break
  done
  hash=$(printf '%s' "$pw" | docker run --rm -i --network none signal-web-gate:local -hash-stdin) \
    || die "Hashing failed."
  unset pw pw2
  # shellcheck disable=SC2016 # literal prefix
  [[ "$hash" == '$argon2id$'* ]] || die "Unexpected hash output."
  umask 077
  rm -f secrets/gate_password.argon2
  (set -o noclobber; printf '%s\n' "$hash" > secrets/gate_password.argon2); unset hash
  ok "Saved the password as an argon2id hash"
}

fix_permissions() {
  if [[ "$desktop" == 1 ]]; then
    # Docker Desktop's VM can't see host ownership; the ./secrets folder itself stays
    # private (0700, in your home folder) and the files are readable inside containers.
    chmod 700 secrets; chmod 444 secrets/*
  else
    say "Setting file ownership for the containers (needs your computer password for sudo)."
    mkdir -p config state
    sudo chown 3006:3006 secrets/session_key secrets/upstream_basic secrets/gate_password.argon2 state
    sudo chown 65532:65532 secrets/tunnel_token
    sudo chown 0:0 secrets/upstream_password
    sudo chmod 0400 secrets/*
    sudo chown "$(get_env PUID | sed 's/^$/3005/'):$(get_env PGID | sed 's/^$/3005/')" config
  fi
}
unlock_for_edit() { # files must be writable by us to replace them
  if [[ "$desktop" == 1 ]]; then chmod u+w secrets/* 2>/dev/null || true
  else sudo chown "$(id -u):$(id -g)" secrets/* 2>/dev/null || true; sudo chmod 600 secrets/* 2>/dev/null || true; fi
}

start_stack() {
  step "6/6  Starting Signal"
  compose up -d || die "Docker couldn't start the stack. See the walkthrough's troubleshooting."
  say "Waiting for the gate to report healthy (up to 3 minutes)..."
  local id status
  id=$(compose ps -q signal-gate)
  for _ in $(seq 1 36); do
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || echo missing)
    [[ "$status" == healthy ]] && break
    sleep 5
  done
  if [[ "$status" == healthy ]]; then ok "Password gate is healthy"; else
    warn "The gate isn't healthy yet (status: $status). Recent gate log:"
    compose logs --tail 15 signal-gate || true
  fi
  if compose logs signal-tunnel 2>&1 | grep -q 'Registered tunnel connection'; then
    ok "Cloudflare Tunnel is connected"
  else
    warn "The tunnel hasn't connected yet. If this stays, check the token. Recent tunnel log:"
    compose logs --tail 10 signal-tunnel 2>&1 | sed -E 's#eyJ[A-Za-z0-9+/_=-]+#[token hidden]#g' || true
  fi
  printf '\n%sAll set.%s\n' "$bold" "$reset"
  say "Next, if you haven't yet: add the tunnel route in Cloudflare (walkthrough step 8)."
  say "Then open $(get_env GATE_ORIGIN), sign in with the emailed code, enter your gate password,"
  say "and scan the QR code with Signal on your phone (Settings > Linked devices)."
  say "The first start can take a minute or two before Signal appears."
}

unlock_gate() {
  step "Unlocking the password page"
  local img src stamp
  img=$(compose config --images 2>/dev/null | grep 'linuxserver/signal' | head -1)
  [[ -n "$img" ]] || die "Couldn't find the Signal image name. Run the full setup first."
  docker image inspect "$img" >/dev/null 2>&1 || compose pull signal-web
  if [[ "$desktop" == 1 ]]; then
    src=signal-web-gate_gate-state
    docker volume inspect "$src" >/dev/null 2>&1 || die "No gate-state volume yet. Run the full setup first."
  else
    src="$PWD/state"
    [[ -d "$src" ]] || die "No ./state folder yet. Run the full setup first."
  fi
  stamp=$(date +%Y%m%d-%H%M%S)
  compose stop signal-gate
  # A throwaway container with no network edits the lockout file as the gate's user (3006).
  docker run --rm --network none --user 3006:3006 --entrypoint /bin/sh \
    -v "$src:/state" "$img" -c '
      set -e; umask 077
      if [ -s /state/lockout.json ]; then cp /state/lockout.json "/state/lockout.json.bak-$1"; echo "  Backed up the old lock list as lockout.json.bak-$1"; fi
      printf "{}" > /state/lockout.json.tmp && mv /state/lockout.json.tmp /state/lockout.json
      ls -1t /state/lockout.json.bak-* 2>/dev/null | tail -n +6 | while read -r f; do rm -f "$f"; done
    ' unlock "$stamp" || { compose start signal-gate; die "Couldn't clear the lock list."; }
  compose start signal-gate
  ok "Unlocked. You can sign in again (your password is unchanged)."
}

enable_jpeg() {
  step "Making JPEG the default video encoder"
  ensure_compose_file
  add_compose_files compose.jpeg.yml
  ok "COMPOSE_FILE=$(get_env COMPOSE_FILE)"
  # Recreates only signal-web; the linked Signal profile is kept.
  compose up -d --no-deps signal-web || die "Docker couldn't restart Signal."
  if docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$(compose ps -q signal-web)" | grep -q '^SELKIES_ENCODER=jpeg'; then
    ok "Signal now starts with JPEG. Reload the Signal page in your browser."
  else
    warn "Signal restarted, but the JPEG setting isn't visible in the container. Check compose.jpeg.yml."
  fi
}

desktop=0
main() {
  if [[ "${1:-}" == password ]]; then
    check_docker
    [[ -f .env ]] || die "Run the full setup first: bash scripts/setup.sh"
    unlock_for_edit
    set_password 1
    # A new session key signs out every browser that used the old password.
    rm -f secrets/session_key; ./scripts/generate-session-key.sh >/dev/null
    fix_permissions
    compose restart signal-gate
    ok "Password changed. Every browser is signed out and needs the new password."
    exit 0
  fi
  if [[ "${1:-}" == unlock ]]; then
    check_docker
    [[ -f .env ]] || die "Run the full setup first: bash scripts/setup.sh"
    unlock_gate
    exit 0
  fi
  if [[ "${1:-}" == jpeg ]]; then
    check_docker
    [[ -f .env ]] || die "Run the full setup first: bash scripts/setup.sh"
    enable_jpeg
    exit 0
  fi
  [[ -z "${1:-}" ]] || die "Unknown option '$1'. Use no option, 'password', 'unlock' or 'jpeg'."
  say "${bold}Signal web gate setup${reset}  (press Ctrl+C at any time to stop; it's safe to rerun)"
  check_docker
  configure_env
  [[ -d secrets ]] && unlock_for_edit
  make_secrets
  build_gate
  set_password
  fix_permissions
  start_stack
}
main "$@"
