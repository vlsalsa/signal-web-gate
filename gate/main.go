// signal-gate: a password-only login page in front of signal-web.
//
// Request flow (every request except /__gate/healthz from loopback):
//  1. Verify the Cloudflare Access JWT (Cf-Access-Jwt-Assertion): RS256 only,
//     key from the team certs, iss, aud, exp/nbf, and email == allowed email.
//     Failure -> 401. The plain email header is never trusted.
//  2. Check the signed session cookie (__Host-sg_session). No/invalid cookie:
//     websocket upgrade -> 401; anything else -> 302 to /__gate/login.
//  3. Proxy to signal-web after stripping every incoming Cf-* and
//     Authorization header and the CF_Authorization / __Host-sg_* cookies,
//     then injecting the upstream basic auth. Websockets are closed when the
//     session (or the Access JWT, whichever is first) expires.
//
// No password, cookie, JWT or key material is ever logged.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	sessionCookie = "__Host-sg_session"
	csrfCookie    = "__Host-sg_csrf"
	loginPath     = "/__gate/login"
	logoutPath    = "/__gate/logout"
	healthPath    = "/__gate/healthz"
	accountPath   = "/__gate/account"
	jwtHeader     = "Cf-Access-Jwt-Assertion"

	minArgonMemKiB = 19456
	minArgonTime   = 2
	maxFormBytes   = 4096
	clockSkew      = 60 * time.Second
)

// ---------------------------------------------------------------- config

type Config struct {
	Listen        string
	Upstream      string
	Team          string // e.g. https://<team>.cloudflareaccess.com
	AUD           string
	AllowedEmail  string // one email, or a comma-separated list
	Origin        string // e.g. https://signal.example.com
	PasswordPHC   string
	SessionKey    []byte
	UpstreamBasic string // base64("user:pass")
	StateDir      string
	SessionTTL    time.Duration
	SameSite      http.SameSite
	ArgonParallel int // concurrent argon2 verifications allowed
	LockShort     int
	LockShortWin  time.Duration
	LockShortFor  time.Duration
	LockHard      int
	LockHardWin   time.Duration
	FailDelay     time.Duration
	CertsURL      string // default Team + /cdn-cgi/access/certs
	CertsTTL      time.Duration
	CertsMinRetry time.Duration
}

// ---------------------------------------------------------------- argon2id

type phc struct {
	mem     uint32
	time    uint32
	threads uint8
	salt    []byte
	hash    []byte
}

func parsePHC(s string) (*phc, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, errors.New("not an argon2id v=19 PHC string")
	}
	p := &phc{}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, errors.New("bad PHC params")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, errors.New("bad PHC param value")
		}
		switch k {
		case "m":
			p.mem = uint32(n)
		case "t":
			p.time = uint32(n)
		case "p":
			if n == 0 || n > 255 {
				return nil, errors.New("bad PHC p")
			}
			p.threads = uint8(n)
		default:
			return nil, errors.New("unknown PHC param")
		}
	}
	var err error
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(p.salt) < 16 {
		return nil, errors.New("bad PHC salt")
	}
	if p.hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(p.hash) < 16 {
		return nil, errors.New("bad PHC hash")
	}
	if p.mem < minArgonMemKiB || p.time < minArgonTime || p.threads == 0 {
		return nil, errors.New("argon2id params weaker than minimum")
	}
	return p, nil
}

func hashPassword(pw []byte, mem, t uint32, threads uint8) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey(pw, salt, t, mem, threads, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", mem, t, threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h)), nil
}

func (p *phc) verify(pw []byte) bool {
	h := argon2.IDKey(pw, p.salt, p.time, p.mem, p.threads, uint32(len(p.hash)))
	return subtle.ConstantTimeCompare(h, p.hash) == 1
}

// ---------------------------------------------------------------- JWKS + JWT

type jwks struct {
	mu        sync.Mutex
	url       string
	ttl       time.Duration
	minRetry  time.Duration
	client    *http.Client
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
	now       func() time.Time
}

func (j *jwks) fetch() error {
	j.lastTry = j.now()
	resp, err := j.client.Get(j.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("certs status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) > 4 {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
		if pk.N.BitLen() < 2048 || e < 3 {
			continue
		}
		keys[k.Kid] = pk
	}
	if len(keys) == 0 {
		return errors.New("no usable RSA keys in certs")
	}
	j.keys = keys
	j.fetchedAt = j.now()
	return nil
}

func (j *jwks) key(kid string) (*rsa.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	if j.keys == nil || now.Sub(j.fetchedAt) > j.ttl {
		if j.keys == nil || now.Sub(j.lastTry) >= j.minRetry {
			if err := j.fetch(); err != nil && j.keys == nil {
				return nil, err // fail closed: no keys at all
			}
		}
	}
	if k, ok := j.keys[kid]; ok {
		return k, nil
	}
	if now.Sub(j.lastTry) >= j.minRetry {
		if err := j.fetch(); err == nil {
			if k, ok := j.keys[kid]; ok {
				return k, nil
			}
		}
	}
	return nil, errors.New("unknown kid")
}

type claims struct {
	Iss   string          `json:"iss"`
	Aud   json.RawMessage `json:"aud"`
	Exp   float64         `json:"exp"`
	Nbf   float64         `json:"nbf"`
	Iat   float64         `json:"iat"`
	Email string          `json:"email"`
}

func (c *claims) hasAud(want string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return subtle.ConstantTimeCompare([]byte(one), []byte(want)) == 1
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if subtle.ConstantTimeCompare([]byte(a), []byte(want)) == 1 {
				return true
			}
		}
	}
	return false
}

var errJWT = errors.New("jwt rejected")

// verifyJWT returns the token's email and expiry when every check passes.
func (g *Gate) verifyJWT(tok string) (string, time.Time, error) {
	if tok == "" || len(tok) > 16384 {
		return "", time.Time{}, fmt.Errorf("%w: missing", errJWT)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", time.Time{}, fmt.Errorf("%w: shape", errJWT)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: header b64", errJWT)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "RS256" {
		return "", time.Time{}, fmt.Errorf("%w: alg", errJWT)
	}
	key, err := g.keys.key(hdr.Kid)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: key", errJWT)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: sig b64", errJWT)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return "", time.Time{}, fmt.Errorf("%w: signature", errJWT)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: claims b64", errJWT)
	}
	var c claims
	if json.Unmarshal(cb, &c) != nil {
		return "", time.Time{}, fmt.Errorf("%w: claims json", errJWT)
	}
	now := g.now()
	if c.Iss != g.cfg.Team {
		return "", time.Time{}, fmt.Errorf("%w: iss", errJWT)
	}
	if !c.hasAud(g.cfg.AUD) {
		return "", time.Time{}, fmt.Errorf("%w: aud", errJWT)
	}
	exp := time.Unix(int64(c.Exp), 0)
	if c.Exp == 0 || !now.Before(exp) {
		return "", time.Time{}, fmt.Errorf("%w: expired", errJWT)
	}
	if c.Nbf != 0 && now.Add(clockSkew).Before(time.Unix(int64(c.Nbf), 0)) {
		return "", time.Time{}, fmt.Errorf("%w: nbf", errJWT)
	}
	if c.Iat != 0 && now.Add(clockSkew).Before(time.Unix(int64(c.Iat), 0)) {
		return "", time.Time{}, fmt.Errorf("%w: iat", errJWT)
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if email == "" || !g.allowed[email] {
		return "", time.Time{}, fmt.Errorf("%w: email", errJWT)
	}
	return email, exp, nil
}

// ---------------------------------------------------------------- sessions + CSRF

type session struct {
	E   string `json:"e"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

func (g *Gate) mac(parts ...string) []byte {
	m := hmac.New(sha256.New, g.cfg.SessionKey)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return m.Sum(nil)
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (g *Gate) newSession(email string) (string, session) {
	now := g.now()
	s := session{E: email, Iat: now.Unix(), Exp: now.Add(g.cfg.SessionTTL).Unix(), Jti: randToken(12)}
	pb, _ := json.Marshal(s)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sig := base64.RawURLEncoding.EncodeToString(g.mac("session", p))
	return p + "." + sig, s
}

func (g *Gate) checkSession(r *http.Request, email string) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	p, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return session{}, false
	}
	want := g.mac("session", p)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return session{}, false
	}
	pb, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return session{}, false
	}
	var s session
	if json.Unmarshal(pb, &s) != nil {
		return session{}, false
	}
	if s.E != email || g.now().Unix() >= s.Exp {
		return session{}, false
	}
	return s, true
}

func (g *Gate) setCookie(w http.ResponseWriter, name, value string, maxAge int, ss http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: ss,
	})
}

// ---------------------------------------------------------------- lockout

type lockEntry struct {
	Fails      []int64 `json:"fails"` // unix seconds, within the hard window
	LockedTill int64   `json:"locked_till"`
	Hard       bool    `json:"hard"`
}

type lockout struct {
	mu    sync.Mutex
	path  string
	state map[string]*lockEntry
}

func loadLockout(dir string) *lockout {
	l := &lockout{state: map[string]*lockEntry{}}
	if dir == "" {
		return l
	}
	l.path = filepath.Join(dir, "lockout.json")
	if b, err := os.ReadFile(l.path); err == nil {
		_ = json.Unmarshal(b, &l.state)
	}
	return l
}

func (l *lockout) save() {
	if l.path == "" {
		return
	}
	b, err := json.Marshal(l.state)
	if err != nil {
		log.Printf("result=lockout_persist_failed stage=marshal")
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		// Only the error class is logged; the state holds no secrets anyway.
		log.Printf("result=lockout_persist_failed stage=write err=%q", errClass(err))
		return
	}
	if err := os.Rename(tmp, l.path); err != nil {
		log.Printf("result=lockout_persist_failed stage=rename err=%q", errClass(err))
	}
}

func errClass(err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrNotExist):
		return "not_exist"
	default:
		var pe *os.PathError
		if errors.As(err, &pe) {
			return pe.Err.Error()
		}
		return "other"
	}
}

// locked reports whether key is locked now, and whether it is a hard lock.
func (g *Gate) locked(key string) (bool, bool) {
	l := g.lock
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.state[key]
	if e == nil {
		return false, false
	}
	if e.Hard {
		return true, true
	}
	return g.now().Unix() < e.LockedTill, false
}

func (g *Gate) recordFail(key string) (hard bool) {
	l := g.lock
	l.mu.Lock()
	defer l.mu.Unlock()
	now := g.now()
	e := l.state[key]
	if e == nil {
		e = &lockEntry{}
		l.state[key] = e
	}
	cut := now.Add(-g.cfg.LockHardWin).Unix()
	kept := e.Fails[:0]
	for _, t := range e.Fails {
		if t > cut {
			kept = append(kept, t)
		}
	}
	e.Fails = append(kept, now.Unix())
	short := 0
	sc := now.Add(-g.cfg.LockShortWin).Unix()
	for _, t := range e.Fails {
		if t > sc {
			short++
		}
	}
	if len(e.Fails) >= g.cfg.LockHard {
		e.Hard = true
	} else if short >= g.cfg.LockShort {
		e.LockedTill = now.Add(g.cfg.LockShortFor).Unix()
	}
	l.save()
	return e.Hard
}

func (g *Gate) recordSuccess(key string) {
	l := g.lock
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.state[key]; e != nil && !e.Hard {
		delete(l.state, key)
		l.save()
	}
}

// ---------------------------------------------------------------- gate

type Gate struct {
	cfg     Config
	allowed map[string]bool
	pw      *phc
	keys    *jwks
	lock    *lockout
	// loginMu serialises the whole "re-check lockout -> argon2 verify ->
	// record result" section, so the 5-try limit is exact under concurrency
	// and at most one 64 MiB argon2 computation runs at a time.
	loginMu  sync.Mutex
	verifies atomic.Int64 // number of argon2 verifications performed (test hook)
	proxy    *httputil.ReverseProxy
	now      func() time.Time
	sleep    func(time.Duration)
}

func NewGate(cfg Config) (*Gate, error) {
	if cfg.AUD == "" || cfg.Team == "" || cfg.AllowedEmail == "" || cfg.Origin == "" {
		return nil, errors.New("aud, team, allowed-email and origin are required")
	}
	if len(cfg.SessionKey) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	if cfg.UpstreamBasic == "" {
		return nil, errors.New("upstream basic credentials required")
	}
	if _, err := base64.StdEncoding.DecodeString(cfg.UpstreamBasic); err != nil {
		return nil, errors.New("upstream basic file is not base64")
	}
	pw, err := parsePHC(cfg.PasswordPHC)
	if err != nil {
		return nil, err
	}
	up, err := url.Parse(cfg.Upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return nil, errors.New("bad upstream URL")
	}
	allowed := map[string]bool{}
	for _, e := range strings.Split(cfg.AllowedEmail, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			allowed[e] = true
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("allowed-email is empty")
	}
	cfg.Team = strings.TrimRight(cfg.Team, "/")
	if cfg.CertsURL == "" {
		cfg.CertsURL = cfg.Team + "/cdn-cgi/access/certs"
	}
	if cfg.ArgonParallel == 0 {
		cfg.ArgonParallel = 1
	}
	if cfg.ArgonParallel != 1 {
		return nil, errors.New("argon2-concurrency must be 1 (verification is serialised with the lockout check)")
	}
	g := &Gate{cfg: cfg, pw: pw, allowed: allowed, now: time.Now, sleep: time.Sleep}
	g.keys = &jwks{url: cfg.CertsURL, ttl: cfg.CertsTTL, minRetry: cfg.CertsMinRetry,
		client: &http.Client{Timeout: 10 * time.Second}, now: func() time.Time { return g.now() }}
	g.lock = loadLockout(cfg.StateDir)
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			pr.Out.Host = pr.In.Host
			sanitizeOutbound(pr.Out.Header)
			pr.Out.Header.Set("Authorization", "Basic "+cfg.UpstreamBasic)
		},
		FlushInterval: -1,
		ErrorLog:      log.New(os.Stderr, "proxy: ", log.LstdFlags),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("result=upstream_error path=%q", r.URL.Path)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
		},
	}
	return g, nil
}

// sanitizeOutbound removes every Cf-* header, Authorization, X-Forwarded-*,
// and the CF_Authorization / __Host-sg_* cookies before forwarding.
func sanitizeOutbound(h http.Header) {
	for k := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "cf-") || lk == "authorization" || lk == "proxy-authorization" ||
			strings.HasPrefix(lk, "x-forwarded-") || lk == "forwarded" {
			h.Del(k)
		}
	}
	if cs := h.Values("Cookie"); len(cs) > 0 {
		var keep []string
		for _, line := range cs {
			for _, part := range strings.Split(line, ";") {
				p := strings.TrimSpace(part)
				name, _, _ := strings.Cut(p, "=")
				if p == "" || strings.EqualFold(name, "CF_Authorization") || strings.HasPrefix(name, "__Host-sg_") {
					continue
				}
				keep = append(keep, p)
			}
		}
		h.Del("Cookie")
		if len(keep) > 0 {
			h.Set("Cookie", strings.Join(keep, "; "))
		}
	}
}

func isWebsocket(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return true
			}
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" && net.ParseIP(ip) != nil {
		return ip
	}
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin, NOT no-referrer: under no-referrer browsers send
	// "Origin: null" on form POSTs (Fetch spec), which the Origin check
	// rejects with 403. same-origin still sends no Referer cross-site.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == healthPath {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
		return
	}
	ip := clientIP(r)
	email, jwtExp, err := g.verifyJWT(r.Header.Get(jwtHeader))
	if err != nil {
		log.Printf("result=bad_jwt reason=%q ip=%s path=%q", strings.TrimPrefix(err.Error(), "jwt rejected: "), ip, r.URL.Path)
		securityHeaders(w)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case loginPath:
		g.handleLogin(w, r, email, ip)
		return
	case logoutPath:
		// POST with Origin + CSRF only, so another site can't log the user out.
		// Logout clears the browser cookie only: sessions are stateless, so a
		// copied cookie stays valid until its 12h expiry (still needs a valid
		// Cloudflare Access token for this app and email). Rotating
		// the session key and restarting the gate revokes every session.
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !g.checkPostCSRF(w, r, ip) {
			return
		}
		securityHeaders(w)
		g.setCookie(w, sessionCookie, "", -1, g.cfg.SameSite)
		g.setCookie(w, csrfCookie, "", -1, http.SameSiteStrictMode)
		log.Printf("result=logout ip=%s", ip)
		http.Redirect(w, r, loginPath, http.StatusSeeOther)
		return
	}
	s, ok := g.checkSession(r, email)
	if ok && r.URL.Path == accountPath {
		nonce := randToken(16)
		g.setCookie(w, csrfCookie, nonce, 600, http.SameSiteStrictMode)
		securityHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = accountTmpl.Execute(w, struct{ CSRF string }{base64.RawURLEncoding.EncodeToString(g.mac("csrf", nonce))})
		return
	}
	if !ok {
		if isWebsocket(r) {
			log.Printf("result=ws_no_session ip=%s path=%q", ip, r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		securityHeaders(w)
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
	}
	if isWebsocket(r) {
		// Refuse cross-site websocket hijacking: browsers always send Origin.
		if r.Header.Get("Origin") != g.cfg.Origin {
			log.Printf("result=ws_bad_origin ip=%s path=%q", ip, r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// Close the proxied websocket when the session or the Access JWT
		// expires, whichever comes first. ReverseProxy closes both sides of an
		// upgraded connection when the request context ends.
		deadline := time.Unix(s.Exp, 0)
		if jwtExp.Before(deadline) {
			deadline = jwtExp
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		r = r.WithContext(ctx)
		log.Printf("result=ws_open ip=%s path=%q until=%s", ip, r.URL.Path, deadline.UTC().Format(time.RFC3339))
	}
	g.proxy.ServeHTTP(w, r)
}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signal</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#1b1c1f;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#e9e9e9}
form{background:#2c2c2e;padding:2rem 2.2rem;border-radius:14px;width:min(320px,86vw);box-shadow:0 8px 30px rgba(0,0,0,.4)}
h1{font-size:1.2rem;margin:0 0 1.2rem;font-weight:600}
input[type=password]{width:100%;box-sizing:border-box;padding:.75rem .9rem;border-radius:9px;border:1px solid #48484a;background:#1c1c1e;color:#fff;font-size:1rem}
button{margin-top:1rem;width:100%;padding:.75rem;border:0;border-radius:9px;background:#3a76f0;color:#fff;font-size:1rem;font-weight:600;cursor:pointer}
.msg{color:#ff7b72;font-size:.9rem;margin:0 0 .8rem}
</style></head><body>
<form method="post" action="/__gate/login" autocomplete="on">
<h1>Signal</h1>
{{if .Msg}}<p class="msg">{{.Msg}}</p>{{end}}
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="password" name="password" aria-label="Password" placeholder="Password" autofocus required autocomplete="current-password">
<button type="submit">Continue</button>
</form></body></html>`))

var accountTmpl = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signal</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#1b1c1f;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#e9e9e9}
div{background:#2c2c2e;padding:2rem 2.2rem;border-radius:14px;width:min(320px,86vw);text-align:center}
a,button{display:block;box-sizing:border-box;width:100%;margin-top:1rem;padding:.75rem;border:0;border-radius:9px;background:#3a76f0;color:#fff;text-decoration:none;font-weight:600;font-size:1rem;cursor:pointer}
button.out{background:#48484a}
</style></head><body><div><h1>Signal</h1>
<a href="/">Open Signal</a>
<form method="post" action="/__gate/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="out" type="submit">Log out</button></form>
</div></body></html>`))

func (g *Gate) renderLogin(w http.ResponseWriter, status int, msg string) {
	nonce := randToken(16)
	g.setCookie(w, csrfCookie, nonce, 600, http.SameSiteStrictMode)
	securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginTmpl.Execute(w, struct{ Msg, CSRF string }{msg, base64.RawURLEncoding.EncodeToString(g.mac("csrf", nonce))})
}

// checkPostCSRF enforces Origin == configured origin and the double-submit
// CSRF token on a POST. It writes the error response itself.
func (g *Gate) checkPostCSRF(w http.ResponseWriter, r *http.Request, ip string) bool {
	if r.Header.Get("Origin") != g.cfg.Origin {
		log.Printf("result=bad_origin ip=%s path=%q", ip, r.URL.Path)
		securityHeaders(w)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return false
	}
	nc, err := r.Cookie(csrfCookie)
	tok, terr := base64.RawURLEncoding.DecodeString(r.PostForm.Get("csrf"))
	if err != nil || terr != nil || nc.Value == "" || !hmac.Equal(tok, g.mac("csrf", nc.Value)) {
		log.Printf("result=bad_csrf ip=%s path=%q", ip, r.URL.Path)
		securityHeaders(w)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (g *Gate) refuseLocked(w http.ResponseWriter, ip string, hard bool) {
	if hard {
		log.Printf("result=locked GATE_HARD_LOCK ip=%s", ip)
	} else {
		log.Printf("result=locked ip=%s", ip)
	}
	g.renderLogin(w, http.StatusTooManyRequests, "Too many attempts. Try again later.")
}

func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request, email, ip string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if _, ok := g.checkSession(r, email); ok {
			securityHeaders(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		g.renderLogin(w, http.StatusOK, "")
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !g.checkPostCSRF(w, r, ip) {
		return
	}
	key := email
	// Cheap early refusal (no lock held); the authoritative check is below.
	if lk, hard := g.locked(key); lk {
		g.refuseLocked(w, ip, hard)
		return
	}
	pw := []byte(r.PostForm.Get("password"))
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
	}()
	// One-at-a-time section: re-check the lockout, verify, and record the
	// result before the next attempt may start.
	g.loginMu.Lock()
	if lk, hard := g.locked(key); lk {
		g.loginMu.Unlock()
		g.refuseLocked(w, ip, hard)
		return
	}
	ok := false
	if len(pw) > 0 && len(pw) <= 1024 {
		g.verifies.Add(1)
		ok = g.pw.verify(pw)
	}
	hard := false
	if ok {
		g.recordSuccess(key)
	} else {
		hard = g.recordFail(key)
	}
	g.loginMu.Unlock()
	if !ok {
		if hard {
			log.Printf("result=wrong_password GATE_HARD_LOCK ip=%s", ip)
		} else {
			log.Printf("result=wrong_password ip=%s", ip)
		}
		g.sleep(g.cfg.FailDelay)
		g.renderLogin(w, http.StatusUnauthorized, "Wrong password.")
		return
	}
	val, _ := g.newSession(email)
	g.setCookie(w, sessionCookie, val, int(g.cfg.SessionTTL/time.Second), g.cfg.SameSite)
	g.setCookie(w, csrfCookie, "", -1, http.SameSiteStrictMode)
	log.Printf("result=ok ip=%s", ip)
	securityHeaders(w)
	http.Redirect(w, r, "/", http.StatusSeeOther) // fixed target: no open redirect
}

// ---------------------------------------------------------------- CLI

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func readStdinPassword(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, 1025))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty password on stdin")
	}
	if len(b) > 1024 {
		return nil, errors.New("password too long")
	}
	if bytes.HasSuffix(b, []byte("\n")) || bytes.HasSuffix(b, []byte("\r")) {
		return nil, errors.New("password on stdin ends with a newline; pipe it with printf '%s'")
	}
	return b, nil
}

// envName maps a flag name to its environment variable: allowed-email ->
// GATE_ALLOWED_EMAIL.
func envName(flagName string) string {
	return "GATE_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// applyEnv sets each flag from its GATE_* environment variable when present.
// It runs before Parse, so command-line flags still win.
func applyEnv(fs *flag.FlagSet, lookup func(string) (string, bool)) error {
	var err error
	fs.VisitAll(func(f *flag.Flag) {
		if err != nil {
			return
		}
		if v, ok := lookup(envName(f.Name)); ok {
			if e := fs.Set(f.Name, v); e != nil {
				err = fmt.Errorf("%s: %w", envName(f.Name), e)
			}
		}
	})
	return err
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("signal-gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		listen      = fs.String("listen", ":8080", "listen address")
		upstream    = fs.String("upstream", "http://signal-web:3000", "upstream URL")
		team        = fs.String("team", "", "Access team URL, e.g. https://x.cloudflareaccess.com")
		audVal      = fs.String("aud", "", "Access application AUD tag (or use -aud-file)")
		audFile     = fs.String("aud-file", "", "file holding the Access application AUD")
		email       = fs.String("allowed-email", "", "allowed email, or a comma-separated list")
		origin      = fs.String("origin", "", "public origin, e.g. https://signal.example.com")
		pwFile      = fs.String("password-file", "", "argon2id PHC file")
		keyFile     = fs.String("session-key-file", "", "session HMAC key file (>=32 bytes)")
		basicFile   = fs.String("upstream-basic-file", "", "file with base64(user:pass) for upstream")
		stateDir    = fs.String("state-dir", "", "writable dir for lockout state")
		ttl         = fs.Duration("session-ttl", 12*time.Hour, "session lifetime (absolute)")
		sameSite    = fs.String("cookie-samesite", "lax", "lax or strict")
		argonPar    = fs.Int("argon2-concurrency", 1, "concurrent password checks")
		hashStdin   = fs.Bool("hash-stdin", false, "read a password on stdin, print an argon2id PHC string")
		verifyStdin = fs.String("verify-stdin", "", "PHC file: read a password on stdin, print OK or FAIL")
		mem         = fs.Uint("m", 65536, "argon2 memory KiB (for -hash-stdin)")
		tcost       = fs.Uint("t", 3, "argon2 iterations (for -hash-stdin)")
		par         = fs.Uint("p", 1, "argon2 parallelism (for -hash-stdin)")
		healthcheck = fs.Bool("healthcheck", false, "probe the local healthz endpoint and exit")
		unreadable  = fs.Bool("check-unreadable", false, "exit 0 only if every path argument is NOT readable by this uid (isolation test)")
	)
	if err := applyEnv(fs, os.LookupEnv); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case *hashStdin:
		if *mem < minArgonMemKiB || *tcost < minArgonTime || *par < 1 || *par > 255 {
			fmt.Fprintln(stderr, "argon2 params below minimum")
			return 2
		}
		pw, err := readStdinPassword(stdin)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		s, err := hashPassword(pw, uint32(*mem), uint32(*tcost), uint8(*par))
		for i := range pw {
			pw[i] = 0
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, s)
		return 0
	case *verifyStdin != "":
		s, err := readSecretFile(*verifyStdin)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		p, err := parsePHC(s)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		pw, err := readStdinPassword(stdin)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		ok := p.verify(pw)
		for i := range pw {
			pw[i] = 0
		}
		if ok {
			fmt.Fprintln(stdout, "OK")
			return 0
		}
		fmt.Fprintln(stdout, "FAIL")
		return 1
	case *unreadable:
		if fs.NArg() == 0 {
			fmt.Fprintln(stderr, "no paths")
			return 2
		}
		rc := 0
		for _, p := range fs.Args() {
			f, err := os.Open(p)
			if err == nil {
				buf := make([]byte, 1)
				_, rerr := f.Read(buf)
				f.Close()
				if rerr == nil || rerr == io.EOF {
					fmt.Fprintf(stdout, "READABLE %s\n", p)
					rc = 1
					continue
				}
			}
			fmt.Fprintf(stdout, "unreadable %s\n", p)
		}
		return rc
	case *healthcheck:
		_, port, err := net.SplitHostPort(*listen)
		if err != nil {
			return 1
		}
		c := &http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://127.0.0.1:" + port + healthPath)
		if err != nil || resp.StatusCode != 200 {
			return 1
		}
		resp.Body.Close()
		return 0
	}

	cfg := Config{Listen: *listen, Upstream: *upstream, Team: *team, AllowedEmail: *email, Origin: *origin,
		StateDir: *stateDir, SessionTTL: *ttl, ArgonParallel: *argonPar,
		LockShort: 5, LockShortWin: 15 * time.Minute, LockShortFor: 15 * time.Minute,
		LockHard: 20, LockHardWin: 24 * time.Hour, FailDelay: time.Second,
		CertsTTL: time.Hour, CertsMinRetry: time.Minute}
	switch strings.ToLower(*sameSite) {
	case "lax":
		cfg.SameSite = http.SameSiteLaxMode
	case "strict":
		cfg.SameSite = http.SameSiteStrictMode
	default:
		fmt.Fprintln(stderr, "cookie-samesite must be lax or strict")
		return 2
	}
	var err error
	switch {
	case *audVal != "" && *audFile != "":
		fmt.Fprintln(stderr, "set only one of -aud and -aud-file")
		return 2
	case *audVal != "":
		cfg.AUD = strings.TrimSpace(*audVal)
	default:
		if cfg.AUD, err = readSecretFile(*audFile); err != nil {
			log.Print(err)
			return 2
		}
	}
	if cfg.PasswordPHC, err = readSecretFile(*pwFile); err != nil {
		log.Print(err)
		return 2
	}
	if cfg.SessionKey, err = os.ReadFile(*keyFile); err != nil {
		log.Printf("read session key: %v", err)
		return 2
	}
	if cfg.UpstreamBasic, err = readSecretFile(*basicFile); err != nil {
		log.Print(err)
		return 2
	}
	g, err := NewGate(cfg)
	if err != nil {
		log.Printf("config: %v", err)
		return 2
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: g, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	log.Printf("signal-gate listening on %s, upstream %s", cfg.Listen, cfg.Upstream)
	if err := srv.ListenAndServe(); err != nil {
		log.Print(err)
		return 1
	}
	return 0
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
