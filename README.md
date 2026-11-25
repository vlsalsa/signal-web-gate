# signal-web-gate

Run [Signal Desktop](https://signal.org/download/) in a browser, privately, behind
Cloudflare Access **and** a second, self-hosted password page.

It is a small Docker Compose stack:

| Service | Image | Role |
|---|---|---|
| `signal-web` | [`lscr.io/linuxserver/signal`](https://docs.linuxserver.io/images/docker-signal/) | Signal Desktop in a web desktop, with its own internal HTTP basic auth |
| `signal-gate` | built from [`gate/`](gate/) | Go reverse proxy: verifies the Cloudflare Access JWT, then asks for a password |
| `signal-tunnel` | [`cloudflare/cloudflared`](https://hub.docker.com/r/cloudflare/cloudflared) | Outbound-only Cloudflare Tunnel; no published ports |

> Not affiliated with Signal, LinuxServer.io or Cloudflare. Running Signal Desktop
> on a server means your messages live on that server. Read [Caveats](#caveats).

## Architecture

```mermaid
flowchart LR
    B[Browser] -->|HTTPS| CF[Cloudflare edge<br/>Access: email OTP policy]
    CF -->|Cf-Access-Jwt-Assertion| T[signal-tunnel<br/>cloudflared]
    subgraph Docker host - no published ports
      subgraph signal-edge network
        T -->|http://signal-gate:8080| G[signal-gate]
      end
      subgraph signal-app network
        G -->|Basic auth injected<br/>HTTP + websockets| S[signal-web<br/>:3000]
      end
    end
    G -. fetches public keys .-> K[(team.cloudflareaccess.com<br/>/cdn-cgi/access/certs)]
```

- The tunnel is only on `signal-edge`, so it can reach the gate and never Signal directly.
- Signal is only on `signal-app`, so the gate is the only way in.
- The connector dials out to Cloudflare; nothing listens on your router or host.

Each request goes through these steps:
1. Cloudflare Access signs you in (email one-time PIN, or another IdP you allow).
2. The gate verifies the Access JWT itself: it does not trust Cloudflare headers blindly.
3. Without a valid gate session, it shows the password page. On success it sets a signed
   session cookie.
4. It strips Cloudflare and auth headers and cookies, injects the internal basic auth and
   proxies HTTP and websockets to `signal-web`.

## Requirements

- Docker Engine with the Compose v2 plugin, on x86-64 or arm64. The pinned digests are
  multi-arch indexes; check that your platform is included.
- A domain on Cloudflare, and a Cloudflare Zero Trust organization (the free plan works).
- `openssl` and `bash` for the helper scripts.

## Cloudflare setup

The dashboard moves things around; the names below are current as of late 2026.

1. **Create a tunnel.** In Zero Trust go to **Networks → Tunnels → Create a tunnel →
   Cloudflared**. Name it, pick Docker, copy only the **token**, and save it as
   `secrets/tunnel_token`. Don't run the suggested `docker run` command.
2. **Add a public hostname** to the tunnel, e.g. `signal.example.com`, with service
   `HTTP` → `signal-gate:8080`.
3. **Create an Access application.** Go to **Access → Applications → Add → Self-hosted**
   for the same hostname, then:
   - **Identity:** enable **One-time PIN**, plus any IdP you trust.
   - **Policy:** action *Allow*, include *Emails* → only the address(es) you will allow.
   - Set a session duration you're comfortable with.
4. **Copy the AUD tag** from the application's overview into `GATE_AUD`.
5. **Find your team domain** under **Settings → Custom Pages** (or in the Access login
   URL), e.g. `https://YOUR_TEAM.cloudflareaccess.com`. That's `GATE_TEAM`. It must match
   the token's `iss` exactly.

Put the email addresses from the Access policy in `GATE_ALLOWED_EMAIL`. The gate enforces
them again, so a broadened Access policy alone does not let anyone in.

## Quick start

```bash
git clone https://github.com/vlsalsa/signal-web-gate.git
cd signal-web-gate
cp .env.example .env          # fill in GATE_TEAM, GATE_AUD, GATE_ALLOWED_EMAIL, GATE_ORIGIN

# Secrets (all land in ./secrets, which is git-ignored).
./scripts/generate-session-key.sh
./scripts/generate-upstream-basic.sh signal      # same name as UPSTREAM_USER in .env
docker compose build signal-gate
./scripts/hash-password.sh                        # prompts twice, no echo
# Save your tunnel token (from step 1 above) without putting it in shell history:
read -rs TOKEN && printf '%s' "$TOKEN" > secrets/tunnel_token && unset TOKEN

# Ownership: the gate runs as 3006, cloudflared as 65532 (its image default) and
# signal-web as PUID/PGID (default 3005). Compose bind-mounts secret files with their host
# ownership, so each file must be readable only by the container that uses it.
mkdir -p config state
sudo chown 3006:3006 secrets/session_key secrets/upstream_basic secrets/gate_password.argon2 state
sudo chown 65532:65532 secrets/tunnel_token
sudo chown 0:0 secrets/upstream_password    # read by signal-web's init as root
sudo chmod 0400 secrets/*
sudo chown 3005:3005 config                 # match PUID/PGID

docker compose up -d
docker compose ps
```

Then open `https://signal.example.com`:
1. Complete the Cloudflare sign-in.
2. Enter your password on the dark **Signal** page.
3. Link Signal Desktop from your phone (**Settings → Linked devices**) using the QR code.

To change the password, delete `secrets/gate_password.argon2`, run `hash-password.sh`
again, fix ownership, and run `docker compose restart signal-gate`.

### Configuration

Every gate flag can also be set with a `GATE_*` environment variable. For example,
`-allowed-email` becomes `GATE_ALLOWED_EMAIL`. If both are set, the command-line flag wins.

| Flag / env | Meaning |
|---|---|
| `-team` / `GATE_TEAM` | Access team URL; must equal the JWT `iss` |
| `-aud` / `GATE_AUD` (or `-aud-file`) | Access application AUD tag |
| `-allowed-email` / `GATE_ALLOWED_EMAIL` | Allowed email, or a comma-separated list |
| `-origin` / `GATE_ORIGIN` | Public origin, e.g. `https://signal.example.com` (exact match) |
| `-upstream` / `GATE_UPSTREAM` | Upstream URL (default `http://signal-web:3000`) |
| `-password-file` | argon2id PHC string |
| `-session-key-file` | ≥32-byte HMAC key |
| `-upstream-basic-file` | `base64(user:pass)` for `signal-web` |
| `-state-dir` | Writable dir for lockout state |
| `-session-ttl` | Session lifetime (default `12h`) |
| `-cookie-samesite` | `lax` (default) or `strict` |
| `-hash-stdin` | Read a password on stdin, print an argon2id hash, and exit |
| `-verify-stdin FILE` | Check a password on stdin against a hash file |
| `-healthcheck` | Probe the local health endpoint (used by Compose) |

## Security model

- **Access JWT verification.**
  - The gate checks `Cf-Access-Jwt-Assertion` with **RS256 only** against the team's
    published keys, which it caches and refreshes on an unknown `kid`.
  - It checks `iss`, `aud`, `exp`, `nbf` and `iat` with 60 s skew, and the `email` claim
    against the allow-list.
  - It never trusts the plain `Cf-Access-Authenticated-User-Email` header.
  - If the keys can't be fetched, it fails closed.
- **Password.**
  - The password is stored only as an **argon2id** PHC hash (default m=64 MiB, t=3, p=1).
    Weak parameters are refused.
  - Checks are serialized, and each failure adds a fixed delay.
- **Lockout.**
  - 5 failures in 15 minutes locks login for 15 minutes.
  - 20 failures in 24 hours is a hard lock.
  - State persists in `state/`, so a restart doesn't reset it.
- **Sessions.**
  - An HMAC-signed, `HttpOnly`, `Secure`, `__Host-` cookie, bound to the Access email,
    with an absolute TTL.
  - Logout clears the cookie. Sessions are stateless, so rotating `secrets/session_key`
    and restarting the gate revokes them all.
- **CSRF and Origin.**
  - Every POST (login and logout) needs `Origin` to equal the configured origin exactly,
    and a double-submit CSRF token.
  - `Origin: null` is rejected.
  - Login redirects only to a fixed target, so there's no open redirect.
- **Referrer-Policy: `same-origin` (a lesson learned).** An earlier version sent
  `Referrer-Policy: no-referrer`. Under that policy, browsers send `Origin: null` on form
  POSTs (Fetch spec, request-origin serialization), so every real login got **403** while
  the unit tests, which set `Origin` by hand, still passed. `same-origin` still sends no
  `Referer` to other sites. `TestFormPagesKeepOriginOnPost` now guards this, and live
  testing needs a real browser.
- **Websockets.**
  - An upgrade without a session gets 401, not a redirect.
  - Cross-site upgrades are refused by an Origin check.
  - Proxied sockets are closed when the session or the Access token expires.
- **Header hygiene.**
  - Incoming `Cf-*`, `Authorization`, `CF_Authorization` and gate cookies are stripped
    before proxying.
  - Responses get CSP, `X-Frame-Options: DENY`, `nosniff` and `no-store`.
  - The gate never logs passwords, cookies, JWTs or keys.
- **Containers.**
  - The gate is built on distroless `nonroot` and runs as uid 3006, read-only, with
    `cap_drop: ALL` and `no-new-privileges`.
  - Every service has memory and CPU limits.
  - Third-party images are pinned by digest.
  - `/__gate/healthz` answers only from loopback.

## Tests

```bash
cd gate
go vet ./...
go test -race -count=1 ./...
```

The 27 tests cover:
- JWT forgery and claim checks (wrong key, alg, iss, aud, email, expiry), and
  unreachable keys failing closed;
- cookie flags and header stripping;
- tampered, expired and wrong-email sessions;
- CSRF and Origin, including `Origin: null`, and that form pages keep a usable Origin;
- open redirects, wrong passwords, lockout and the hard lock, and concurrent guessing;
- websocket auth and closing at expiry;
- direct upstream access without basic auth;
- loopback-only health checks;
- weak hash rejection, hash and verify over stdin, and that no secrets reach the logs;
- the email allow-list and env-var configuration.

Builds are reproducible with the pinned toolchain (`-trimpath -buildvcs=false -buildid=`).

## Caveats

- **This is a personal-scale project.** It has one password, a small allow-list and no
  user database.
- **Your Signal data is on the server.** `config/` holds a linked Signal Desktop profile.
  Anyone with root on the host, or with your backups, can read it. Encrypt the disk,
  restrict backups, and unlink the device from your phone if the host is compromised.
- **Cloudflare is in the path.** It terminates TLS and can see the traffic.
- **iOS and password managers.** With no username field, Safari may show a "save
  password" prompt that looks like a second login. It's harmless.
- **Updates.** Bump the image digests deliberately and re-run the tests. Don't let
  automatic image pruning delete the locally built `signal-web-gate:local` image you'd
  roll back to: tag a known-good build, e.g. `signal-web-gate:rollback`.
- **NAS and appliance platforms.** Use your platform's custom Compose app feature, keep
  `./config`, `./state` and `./secrets` on persistent storage, and use the plain `runc`
  runtime (no GPU is needed).

## License

[MIT](LICENSE)
