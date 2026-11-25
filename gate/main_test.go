package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testTeam   = "https://team.example.cloudflareaccess.com"
	testAUD    = "aud-signal-0123456789abcdef"
	testEmail  = "user@example.com"
	testOrigin = "https://signal.example.com"
	testPW     = "correct-horse-14"
	testBasic  = "user:internal-machine-only"
)

var (
	keyOnce  sync.Once
	testKey  *rsa.PrivateKey
	otherKey *rsa.PrivateKey
	testPHC  string
)

func keys(t *testing.T) {
	keyOnce.Do(func() {
		var err error
		if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if otherKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if testPHC, err = hashPassword([]byte(testPW), minArgonMemKiB, minArgonTime, 1); err != nil {
			panic(err)
		}
	})
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func makeJWT(t *testing.T, k *rsa.PrivateKey, alg, kid string, cl map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(cl)
	in := b64u(h) + "." + b64u(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64u(sig)
}

func goodClaims() map[string]any {
	now := time.Now()
	return map[string]any{"iss": testTeam, "aud": []string{testAUD}, "email": testEmail,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "type": "app"}
}

type upstreamSeen struct {
	mu      sync.Mutex
	headers http.Header
}

func newUpstream(t *testing.T, seen *upstreamSeen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.headers = r.Header.Clone()
		seen.mu.Unlock()
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(testBasic)) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Login"`)
			http.Error(w, "upstream 401", http.StatusUnauthorized)
			return
		}
		if isWebsocket(r) {
			hj, _ := w.(http.Hijacker)
			conn, brw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			brw.Flush()
			buf := make([]byte, 64)
			for {
				n, err := brw.Read(buf)
				if err != nil {
					return
				}
				conn.Write(buf[:n])
			}
		}
		w.Write([]byte("signal-ui"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newCerts(t *testing.T, k *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	e := big.NewInt(int64(k.PublicKey.E)).Bytes()
	doc := map[string]any{"keys": []map[string]string{{"kid": kid, "kty": "RSA", "alg": "RS256",
		"n": b64u(k.PublicKey.N.Bytes()), "e": b64u(e)}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type fixture struct {
	g    *Gate
	up   *upstreamSeen
	clk  *fakeClock
	dir  string
	cert *httptest.Server
	upst *httptest.Server
}

type fakeClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *fakeClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return time.Now().Add(c.off) }
func (c *fakeClock) add(d time.Duration) { c.mu.Lock(); c.off += d; c.mu.Unlock() }

func baseCfg(certsURL, upstream, dir string) Config {
	return Config{Upstream: upstream, Team: testTeam, AUD: testAUD, AllowedEmail: testEmail,
		Origin: testOrigin, PasswordPHC: testPHC, SessionKey: bytes.Repeat([]byte{7}, 32),
		UpstreamBasic: base64.StdEncoding.EncodeToString([]byte(testBasic)), StateDir: dir,
		SessionTTL: 12 * time.Hour, SameSite: http.SameSiteLaxMode, ArgonParallel: 1,
		LockShort: 5, LockShortWin: 15 * time.Minute, LockShortFor: 15 * time.Minute,
		LockHard: 20, LockHardWin: 24 * time.Hour, FailDelay: 0,
		CertsURL: certsURL, CertsTTL: time.Hour, CertsMinRetry: time.Minute}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	keys(t)
	f := &fixture{up: &upstreamSeen{}, clk: &fakeClock{}, dir: t.TempDir()}
	f.cert = newCerts(t, testKey, "kid1")
	f.upst = newUpstream(t, f.up)
	f.g = f.build(t)
	return f
}

func (f *fixture) build(t *testing.T) *Gate {
	g, err := NewGate(baseCfg(f.cert.URL, f.upst.URL, f.dir))
	if err != nil {
		t.Fatal(err)
	}
	g.now = f.clk.now
	g.sleep = func(time.Duration) {}
	return g
}

func (f *fixture) jwt(t *testing.T) string {
	now := f.clk.now()
	cl := goodClaims()
	cl["exp"], cl["iat"], cl["nbf"] = now.Add(time.Hour).Unix(), now.Unix(), now.Unix()
	return makeJWT(t, testKey, "RS256", "kid1", cl)
}

func (f *fixture) do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	if req.RemoteAddr == "" || req.RemoteAddr == "192.0.2.1:1234" {
		req.RemoteAddr = "203.0.113.9:5555"
	}
	rr := httptest.NewRecorder()
	f.g.ServeHTTP(rr, req)
	return rr
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// login runs the GET+POST flow and returns the session cookie.
func (f *fixture) login(t *testing.T, pw string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	jwt := f.jwt(t)
	req := httptest.NewRequest("GET", loginPath, nil)
	req.Header.Set(jwtHeader, jwt)
	rr := f.do(t, req)
	if rr.Code != 200 {
		t.Fatalf("login GET = %d", rr.Code)
	}
	var csrfC *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	m := csrfRe.FindStringSubmatch(rr.Body.String())
	if csrfC == nil || m == nil {
		t.Fatal("no csrf cookie/token")
	}
	form := url.Values{"csrf": {m[1]}, "password": {pw}}
	post := httptest.NewRequest("POST", loginPath, strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", testOrigin)
	post.Header.Set(jwtHeader, jwt)
	post.AddCookie(csrfC)
	prr := f.do(t, post)
	for _, c := range prr.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge > 0 {
			return prr, c
		}
	}
	return prr, nil
}

// ---------------------------------------------------------------- JWT

func TestJWTChecks(t *testing.T) {
	f := newFixture(t)
	exp := goodClaims()
	exp["exp"] = time.Now().Add(-time.Minute).Unix()
	wrongAud := goodClaims()
	wrongAud["aud"] = []string{"aud-of-another-access-app"}
	wrongEmail := goodClaims()
	wrongEmail["email"] = "someone.else@example.com"
	wrongIss := goodClaims()
	wrongIss["iss"] = "https://evil.cloudflareaccess.com"
	future := goodClaims()
	future["nbf"] = time.Now().Add(10 * time.Minute).Unix()
	noneTok := b64u([]byte(`{"alg":"none","kid":"kid1"}`)) + "." + b64u(mustJSON(goodClaims())) + "."
	hsTok := b64u([]byte(`{"alg":"HS256","kid":"kid1"}`)) + "." + b64u(mustJSON(goodClaims())) + ".AAAA"
	cases := []struct {
		name string
		tok  string
		want int
	}{
		{"good", makeJWT(t, testKey, "RS256", "kid1", goodClaims()), http.StatusFound},
		{"missing", "", http.StatusUnauthorized},
		{"bad signature", makeJWT(t, otherKey, "RS256", "kid1", goodClaims()), http.StatusUnauthorized},
		{"unknown kid", makeJWT(t, testKey, "RS256", "kid-unknown", goodClaims()), http.StatusUnauthorized},
		{"wrong aud (other Access app)", makeJWT(t, testKey, "RS256", "kid1", wrongAud), http.StatusUnauthorized},
		{"expired", makeJWT(t, testKey, "RS256", "kid1", exp), http.StatusUnauthorized},
		{"wrong email", makeJWT(t, testKey, "RS256", "kid1", wrongEmail), http.StatusUnauthorized},
		{"wrong iss", makeJWT(t, testKey, "RS256", "kid1", wrongIss), http.StatusUnauthorized},
		{"not yet valid", makeJWT(t, testKey, "RS256", "kid1", future), http.StatusUnauthorized},
		{"alg none", noneTok, http.StatusUnauthorized},
		{"alg HS256", hsTok, http.StatusUnauthorized},
		{"garbage", "a.b.c", http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if c.tok != "" {
				req.Header.Set(jwtHeader, c.tok)
			}
			if got := f.do(t, req).Code; got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
		})
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestForgedEmailHeaderWithoutTokenIs401(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Access-Authenticated-User-Email", testEmail)
	if got := f.do(t, req).Code; got != http.StatusUnauthorized {
		t.Fatalf("got %d", got)
	}
	req = httptest.NewRequest("GET", loginPath, nil)
	req.Header.Set("Cf-Access-Authenticated-User-Email", testEmail)
	if got := f.do(t, req).Code; got != http.StatusUnauthorized {
		t.Fatalf("login page without token: got %d", got)
	}
}

func TestCertsUnreachableFailsClosed(t *testing.T) {
	keys(t)
	up := newUpstream(t, &upstreamSeen{})
	g, err := NewGate(baseCfg("http://127.0.0.1:1/certs", up.URL, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(jwtHeader, makeJWT(t, testKey, "RS256", "kid1", goodClaims()))
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rr.Code)
	}
}

// ---------------------------------------------------------------- login, cookie, proxy

func TestLoginCookieFlagsAndProxyHeaders(t *testing.T) {
	f := newFixture(t)
	prr, sess := f.login(t, testPW)
	if prr.Code != http.StatusSeeOther || prr.Header().Get("Location") != "/" {
		t.Fatalf("POST = %d loc=%q", prr.Code, prr.Header().Get("Location"))
	}
	if sess == nil {
		t.Fatal("no session cookie")
	}
	raw := ""
	for _, v := range prr.Header().Values("Set-Cookie") {
		if strings.HasPrefix(v, sessionCookie+"=") {
			raw = v
		}
	}
	for _, want := range []string{"Path=/", "Max-Age=43200", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(raw, want) {
			t.Errorf("session Set-Cookie missing %q: %s", want, raw)
		}
	}
	if strings.Contains(strings.ToLower(raw), "domain=") {
		t.Errorf("__Host- cookie must not have Domain: %s", raw)
	}
	// Proxied request: all Cf-* and Authorization stripped, basic injected.
	req := httptest.NewRequest("GET", "/some/page", nil)
	req.Header.Set(jwtHeader, f.jwt(t))
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.5")
	req.Header.Set("Cf-Access-Authenticated-User-Email", testEmail)
	req.Header.Set("CF-Ray", "abc")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("evil:guess")))
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Add("Cookie", "CF_Authorization=jwtjwt; keepme=1")
	req.AddCookie(sess)
	rr := f.do(t, req)
	if rr.Code != 200 || rr.Body.String() != "signal-ui" {
		t.Fatalf("proxied = %d %q", rr.Code, rr.Body.String())
	}
	h := f.up.headers
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "cf-") {
			t.Errorf("upstream saw %s", k)
		}
	}
	if got := h.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte(testBasic)) {
		t.Errorf("upstream Authorization not the injected one")
	}
	ck := h.Get("Cookie")
	if strings.Contains(ck, "CF_Authorization") || strings.Contains(ck, "__Host-sg_") || !strings.Contains(ck, "keepme=1") {
		t.Errorf("upstream cookie header wrong: %q", ck)
	}
	if h.Get("X-Forwarded-For") != "" && strings.Contains(h.Get("X-Forwarded-For"), "1.2.3.4") {
		t.Errorf("client X-Forwarded-For passed through")
	}
}

func TestNoSessionRedirectsToLogin(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(jwtHeader, f.jwt(t))
	rr := f.do(t, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != loginPath {
		t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestTamperedAndExpiredSession(t *testing.T) {
	f := newFixture(t)
	_, sess := f.login(t, testPW)
	bad := *sess
	bad.Value = sess.Value[:len(sess.Value)-2] + "AA"
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(jwtHeader, f.jwt(t))
	req.AddCookie(&bad)
	if got := f.do(t, req).Code; got != http.StatusFound {
		t.Fatalf("tampered: %d", got)
	}
	f.clk.add(12*time.Hour + time.Second)
	req = httptest.NewRequest("GET", "/", nil)
	cl := goodClaims()
	cl["exp"] = time.Now().Add(13 * time.Hour).Unix()
	req.Header.Set(jwtHeader, makeJWT(t, testKey, "RS256", "kid1", cl))
	req.AddCookie(sess)
	if got := f.do(t, req).Code; got != http.StatusFound {
		t.Fatalf("expired session: %d", got)
	}
}

func TestSessionBoundToEmail(t *testing.T) {
	f := newFixture(t)
	val, _ := f.g.newSession("someone.else@example.com")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(jwtHeader, f.jwt(t))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: val})
	if got := f.do(t, req).Code; got != http.StatusFound {
		t.Fatalf("got %d", got)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	f := newFixture(t)
	_, sess := f.login(t, testPW)
	acc := httptest.NewRequest("GET", accountPath, nil)
	acc.Header.Set(jwtHeader, f.jwt(t))
	acc.AddCookie(sess)
	arr := f.do(t, acc)
	if arr.Code != 200 || !strings.Contains(arr.Body.String(), `action="/__gate/logout"`) {
		t.Fatalf("account page with logout form: %d", arr.Code)
	}
	var csrfC *http.Cookie
	for _, c := range arr.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	tok := csrfRe.FindStringSubmatch(arr.Body.String())[1]
	// GET logout is refused (no cross-site logout by link/image).
	g := httptest.NewRequest("GET", logoutPath, nil)
	g.Header.Set(jwtHeader, f.jwt(t))
	g.AddCookie(sess)
	if c := f.do(t, g).Code; c != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout: %d", c)
	}
	// POST without CSRF token or with a foreign Origin is refused.
	for _, origin := range []string{testOrigin, "https://evil.example"} {
		form := url.Values{}
		if origin != testOrigin {
			form.Set("csrf", tok)
		}
		bad := httptest.NewRequest("POST", logoutPath, strings.NewReader(form.Encode()))
		bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		bad.Header.Set("Origin", origin)
		bad.Header.Set(jwtHeader, f.jwt(t))
		bad.AddCookie(sess)
		bad.AddCookie(csrfC)
		if c := f.do(t, bad).Code; c != http.StatusForbidden {
			t.Fatalf("logout without valid CSRF/origin (%s): %d", origin, c)
		}
	}
	req := httptest.NewRequest("POST", logoutPath, strings.NewReader(url.Values{"csrf": {tok}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", testOrigin)
	req.Header.Set(jwtHeader, f.jwt(t))
	req.AddCookie(sess)
	req.AddCookie(csrfC)
	rr := f.do(t, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d", rr.Code)
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("session cookie not cleared")
	}
}

func TestLoginPageHasLogoutFreeFormAndHeaders(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", loginPath, nil)
	req.Header.Set(jwtHeader, f.jwt(t))
	rr := f.do(t, req)
	body := rr.Body.String()
	if !strings.Contains(body, `type="password"`) || strings.Contains(body, `name="username"`) {
		t.Fatal("login page must be password-only")
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "Cache-Control"} {
		if rr.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}

// Regression (6:42 PM MT live bug): with Referrer-Policy: no-referrer the
// browser sent "Origin: null" on the login POST and the gate returned 403.
// Every gate page that holds a POST form must use a policy that keeps Origin.
func TestFormPagesKeepOriginOnPost(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", loginPath, nil)
	req.Header.Set(jwtHeader, f.jwt(t))
	rr := f.do(t, req)
	if got := rr.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("login page Referrer-Policy = %q, want same-origin", got)
	}
	_, sess := f.login(t, testPW)
	if sess == nil {
		t.Fatal("login failed")
	}
	acc := httptest.NewRequest("GET", accountPath, nil)
	acc.Header.Set(jwtHeader, f.jwt(t))
	acc.AddCookie(sess)
	arr := f.do(t, acc)
	if got := arr.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("account page Referrer-Policy = %q, want same-origin", got)
	}
	// Origin: null must still be refused (no loosening of the check).
	r2 := httptest.NewRequest("GET", loginPath, nil)
	r2.Header.Set(jwtHeader, f.jwt(t))
	lrr := f.do(t, r2)
	var csrfC *http.Cookie
	for _, c := range lrr.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	m := csrfRe.FindStringSubmatch(lrr.Body.String())
	if csrfC == nil || m == nil {
		t.Fatal("no csrf")
	}
	post := httptest.NewRequest("POST", loginPath, strings.NewReader(url.Values{"csrf": {m[1]}, "password": {testPW}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "null")
	post.Header.Set(jwtHeader, f.jwt(t))
	post.AddCookie(csrfC)
	if prr := f.do(t, post); prr.Code != http.StatusForbidden {
		t.Fatalf("Origin: null POST = %d, want 403", prr.Code)
	}
}

// ---------------------------------------------------------------- CSRF + open redirect

func TestCSRFAndOrigin(t *testing.T) {
	f := newFixture(t)
	jwt := f.jwt(t)
	get := httptest.NewRequest("GET", loginPath, nil)
	get.Header.Set(jwtHeader, jwt)
	rr := f.do(t, get)
	var csrfC *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	tok := csrfRe.FindStringSubmatch(rr.Body.String())[1]
	try := func(name, origin, token string, withCookie bool) {
		form := url.Values{"password": {testPW}}
		if token != "" {
			form.Set("csrf", token)
		}
		post := httptest.NewRequest("POST", loginPath, strings.NewReader(form.Encode()))
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			post.Header.Set("Origin", origin)
		}
		post.Header.Set(jwtHeader, jwt)
		if withCookie {
			post.AddCookie(csrfC)
		}
		if got := f.do(t, post).Code; got != http.StatusForbidden {
			t.Errorf("%s: got %d want 403", name, got)
		}
	}
	try("no token", testOrigin, "", true)
	try("wrong token", testOrigin, b64u([]byte("nope-nope-nope-nope-nope-nope-32")), true)
	try("no csrf cookie", testOrigin, tok, false)
	try("cross-site origin", "https://evil.example", tok, true)
	try("missing origin", "", tok, true)
}

func TestOpenRedirectRefused(t *testing.T) {
	f := newFixture(t)
	// The POST ignores any next/redirect parameter and always goes to "/".
	jwt := f.jwt(t)
	get := httptest.NewRequest("GET", loginPath+"?next=//evil.example", nil)
	get.Header.Set(jwtHeader, jwt)
	rr := f.do(t, get)
	var csrfC *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	tok := csrfRe.FindStringSubmatch(rr.Body.String())[1]
	form := url.Values{"csrf": {tok}, "password": {testPW}, "next": {"https://evil.example/x"}}
	post := httptest.NewRequest("POST", loginPath+"?next=//evil.example&redirect=https://evil.example", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", testOrigin)
	post.Header.Set(jwtHeader, jwt)
	post.AddCookie(csrfC)
	prr := f.do(t, post)
	if loc := prr.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q", loc)
	}
	var sess *http.Cookie
	for _, c := range prr.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	get2 := httptest.NewRequest("GET", loginPath+"?next=https://evil.example", nil)
	get2.Header.Set(jwtHeader, jwt)
	get2.AddCookie(sess)
	if loc := f.do(t, get2).Header().Get("Location"); loc != "/" {
		t.Fatalf("logged-in login GET Location = %q", loc)
	}
}

// ---------------------------------------------------------------- lockout

func TestWrongPasswordAndLockout(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 5; i++ {
		prr, sess := f.login(t, "wrong-password")
		if prr.Code != http.StatusUnauthorized || sess != nil {
			t.Fatalf("attempt %d: %d", i, prr.Code)
		}
		if !strings.Contains(prr.Body.String(), "Wrong password") {
			t.Fatal("generic error missing")
		}
	}
	prr, sess := f.login(t, testPW)
	if prr.Code != http.StatusTooManyRequests || sess != nil {
		t.Fatalf("6th attempt with right password while locked: %d", prr.Code)
	}
	// Survives a restart (state file).
	f.g = f.build(t)
	if prr, _ := f.login(t, testPW); prr.Code != http.StatusTooManyRequests {
		t.Fatalf("after restart: %d", prr.Code)
	}
	if fi, err := os.Stat(filepath.Join(f.dir, "lockout.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode: %v %v", fi, err)
	}
	f.clk.add(16 * time.Minute)
	if prr, sess := f.login(t, testPW); prr.Code != http.StatusSeeOther || sess == nil {
		t.Fatalf("after lockout window: %d", prr.Code)
	}
}

func TestHardLock(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 20; i++ {
		if i > 0 && i%5 == 0 {
			f.clk.add(16 * time.Minute)
		}
		f.login(t, "wrong-password")
	}
	f.clk.add(2 * time.Hour)
	f.g = f.build(t)
	if prr, _ := f.login(t, testPW); prr.Code != http.StatusTooManyRequests {
		t.Fatalf("hard lock not enforced: %d", prr.Code)
	}
}

// ---------------------------------------------------------------- websockets

func wsDial(t *testing.T, addr, origin, jwt string, sess *http.Cookie) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("GET /api/websocket HTTP/1.1\r\nHost: signal.example.com\r\n")
	b.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") // gitleaks:allow (RFC 6455 sample key)
	if origin != "" {
		b.WriteString("Origin: " + origin + "\r\n")
	}
	if jwt != "" {
		b.WriteString(jwtHeader + ": " + jwt + "\r\n")
	}
	if sess != nil {
		b.WriteString("Cookie: " + sess.Name + "=" + sess.Value + "\r\n")
	}
	b.WriteString("\r\n")
	c.Write([]byte(b.String()))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, br, resp
}

func TestWebsocket(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(f.g)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	jwt := f.jwt(t)

	c, _, resp := wsDial(t, addr, testOrigin, jwt, nil)
	c.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ws without cookie: %d", resp.StatusCode)
	}
	c, _, resp = wsDial(t, addr, testOrigin, "", nil)
	c.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ws without jwt: %d", resp.StatusCode)
	}
	_, sess := f.login(t, testPW)
	c, _, resp = wsDial(t, addr, "https://evil.example", jwt, sess)
	c.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ws cross-site origin: %d", resp.StatusCode)
	}
	c, br, resp := wsDial(t, addr, testOrigin, jwt, sess)
	defer c.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("ws with session: %d", resp.StatusCode)
	}
	c.Write([]byte("ping\n"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo: %q %v", line, err)
	}
	if got := f.up.headers.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte(testBasic)) {
		t.Fatal("ws upstream did not get injected basic auth")
	}
}

func TestWebsocketClosedAtSessionExpiry(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(f.g)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	// Mint a session that expires ~2s from now (real time).
	f.clk.add(-(12*time.Hour - 2*time.Second))
	val, s := f.g.newSession(testEmail)
	f.clk.add(12*time.Hour - 2*time.Second)
	if time.Until(time.Unix(s.Exp, 0)) > 3*time.Second {
		t.Fatal("test session not short")
	}
	sess := &http.Cookie{Name: sessionCookie, Value: val}
	c, br, resp := wsDial(t, addr, testOrigin, f.jwt(t), sess)
	defer c.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("ws: %d", resp.StatusCode)
	}
	c.Write([]byte("hi\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if l, err := br.ReadString('\n'); err != nil || l != "hi\n" {
		t.Fatalf("echo before expiry: %q %v", l, err)
	}
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(6 * time.Second))
	_, err := io.ReadAll(br)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("websocket was not closed at session expiry")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("closed too late")
	}
}

func TestDirectUpstreamWithoutBasicIs401(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.upst.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("direct signal-web hit without basic auth: %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------- health

func TestHealthzLoopbackOnly(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", healthPath, nil)
	req.RemoteAddr = "127.0.0.1:4000"
	rr := httptest.NewRecorder()
	f.g.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("loopback healthz: %d", rr.Code)
	}
	req = httptest.NewRequest("GET", healthPath, nil)
	req.RemoteAddr = "203.0.113.1:4000"
	rr = httptest.NewRecorder()
	f.g.ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("non-loopback healthz: %d", rr.Code)
	}
}

// ---------------------------------------------------------------- PHC + CLI

func TestParsePHCRejectsWeak(t *testing.T) {
	keys(t)
	if _, err := parsePHC(testPHC); err != nil {
		t.Fatal(err)
	}
	weak, _ := hashPassword([]byte("x"), 4096, 1, 1)
	if _, err := parsePHC(weak); err == nil {
		t.Fatal("weak params accepted")
	}
	for _, s := range []string{"", "$argon2i$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$2b$12$abcdefghijklmnopqrstuu", "$argon2id$v=19$m=65536,t=3,p=1$short$short"} {
		if _, err := parsePHC(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := NewGate(Config{PasswordPHC: weak}); err == nil {
		t.Fatal("gate started with bad config")
	}
}

func TestHashAndVerifyStdin(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"-hash-stdin", "-m", "19456", "-t", "2", "-p", "1"}, strings.NewReader(testPW), &out, &errb); rc != 0 {
		t.Fatalf("hash rc=%d %s", rc, errb.String())
	}
	phcStr := strings.TrimSpace(out.String())
	if !strings.HasPrefix(phcStr, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("bad PHC prefix")
	}
	if strings.Contains(out.String()+errb.String(), testPW) {
		t.Fatal("password echoed")
	}
	// Default params are m=65536,t=3,p=1.
	out.Reset()
	if rc := run([]string{"-hash-stdin"}, strings.NewReader(testPW), &out, &errb); rc != 0 ||
		!strings.HasPrefix(out.String(), "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("default params: rc=%d", rc)
	}
	file := filepath.Join(t.TempDir(), "h")
	os.WriteFile(file, []byte(phcStr+"\n"), 0o400)
	out.Reset()
	if rc := run([]string{"-verify-stdin", file}, strings.NewReader(testPW), &out, &errb); rc != 0 || strings.TrimSpace(out.String()) != "OK" {
		t.Fatalf("verify good: rc=%d out=%q", rc, out.String())
	}
	out.Reset()
	if rc := run([]string{"-verify-stdin", file}, strings.NewReader("wrong-password"), &out, &errb); rc != 1 || strings.TrimSpace(out.String()) != "FAIL" {
		t.Fatalf("verify bad: rc=%d out=%q", rc, out.String())
	}
	out.Reset()
	if rc := run([]string{"-hash-stdin"}, strings.NewReader(testPW+"\n"), &out, &errb); rc == 0 {
		t.Fatal("trailing newline accepted")
	}
	if rc := run([]string{"-hash-stdin"}, strings.NewReader(""), &out, &errb); rc == 0 {
		t.Fatal("empty accepted")
	}
	if rc := run([]string{"-hash-stdin", "-m", "1024", "-t", "1"}, strings.NewReader(testPW), &out, &errb); rc == 0 {
		t.Fatal("weak params accepted")
	}
	// Two hashes of the same password use different salts.
	var a, b bytes.Buffer
	run([]string{"-hash-stdin", "-m", "19456", "-t", "2"}, strings.NewReader(testPW), &a, &errb)
	run([]string{"-hash-stdin", "-m", "19456", "-t", "2"}, strings.NewReader(testPW), &b, &errb)
	if a.String() == b.String() {
		t.Fatal("salt not random")
	}
}

// Logs must never contain the password, the session cookie or the JWT.
func TestNoSecretsInLogs(t *testing.T) {
	var buf bytes.Buffer
	logMu.Lock()
	old := captureLog(&buf)
	defer func() { restoreLog(old); logMu.Unlock() }()
	f := newFixture(t)
	f.login(t, "wrong-password-xyz")
	_, sess := f.login(t, testPW)
	jwt := f.jwt(t)
	logs := buf.String()
	for _, s := range []string{"wrong-password-xyz", testPW, sess.Value, jwt, testBasic,
		base64.StdEncoding.EncodeToString([]byte(testBasic))} {
		if strings.Contains(logs, s) {
			t.Fatalf("secret material in logs")
		}
	}
	if !strings.Contains(logs, "result=wrong_password") || !strings.Contains(logs, "result=ok") {
		t.Fatalf("expected result lines in logs: %s", logs)
	}
	_ = fmt.Sprint
}

func TestCheckUnreadable(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "r")
	os.WriteFile(readable, []byte("x"), 0o600)
	var out, errb bytes.Buffer
	if rc := run([]string{"-check-unreadable", readable}, nil, &out, &errb); rc != 1 || !strings.Contains(out.String(), "READABLE") {
		t.Fatalf("readable file not reported: rc=%d", rc)
	}
	out.Reset()
	if rc := run([]string{"-check-unreadable", filepath.Join(dir, "missing")}, nil, &out, &errb); rc != 0 {
		t.Fatalf("missing file: rc=%d", rc)
	}
	if os.Getuid() != 0 {
		noperm := filepath.Join(dir, "n")
		os.WriteFile(noperm, []byte("secret"), 0o000)
		out.Reset()
		if rc := run([]string{"-check-unreadable", noperm}, nil, &out, &errb); rc != 0 || strings.Contains(out.String(), "secret") {
			t.Fatalf("mode-000 file: rc=%d", rc)
		}
	}
}

// Red Team fix: concurrent wrong guesses must not get past the 5-try limit.
func TestConcurrentGuessesRespectLockout(t *testing.T) {
	f := newFixture(t)
	jwt := f.jwt(t)
	type attempt struct {
		c   *http.Cookie
		tok string
	}
	var atts []attempt
	for i := 0; i < 10; i++ {
		get := httptest.NewRequest("GET", loginPath, nil)
		get.Header.Set(jwtHeader, jwt)
		rr := f.do(t, get)
		var c *http.Cookie
		for _, ck := range rr.Result().Cookies() {
			if ck.Name == csrfCookie {
				c = ck
			}
		}
		atts = append(atts, attempt{c, csrfRe.FindStringSubmatch(rr.Body.String())[1]})
	}
	start := make(chan struct{})
	codes := make([]int, len(atts))
	var wg sync.WaitGroup
	for i, a := range atts {
		wg.Add(1)
		go func(i int, a attempt) {
			defer wg.Done()
			form := url.Values{"csrf": {a.tok}, "password": {"wrong-guess"}}
			post := httptest.NewRequest("POST", loginPath, strings.NewReader(form.Encode()))
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			post.Header.Set("Origin", testOrigin)
			post.Header.Set(jwtHeader, jwt)
			post.AddCookie(a.c)
			post.RemoteAddr = "203.0.113.9:5555"
			<-start
			rr := httptest.NewRecorder()
			f.g.ServeHTTP(rr, post)
			codes[i] = rr.Code
		}(i, a)
	}
	close(start)
	wg.Wait()
	if n := f.g.verifies.Load(); n > 5 {
		t.Fatalf("argon2 verifications = %d, want at most 5", n)
	} else if n != 5 {
		t.Fatalf("argon2 verifications = %d, want exactly 5 (limit must be exact)", n)
	}
	wrong, locked := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusUnauthorized:
			wrong++
		case http.StatusTooManyRequests:
			locked++
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	if wrong != 5 || locked != 5 {
		t.Fatalf("wrong=%d locked=%d, want 5/5", wrong, locked)
	}
	// And the right password is refused too while locked, without verifying.
	before := f.g.verifies.Load()
	if prr, _ := f.login(t, testPW); prr.Code != http.StatusTooManyRequests {
		t.Fatalf("right password while locked: %d", prr.Code)
	}
	if f.g.verifies.Load() != before {
		t.Fatal("argon2 ran while locked")
	}
}

func TestLockoutPersistFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logMu.Lock()
	old := captureLog(&buf)
	defer func() { restoreLog(old); logMu.Unlock() }()
	keys(t)
	up := newUpstream(t, &upstreamSeen{})
	cert := newCerts(t, testKey, "kid1")
	cfg := baseCfg(cert.URL, up.URL, filepath.Join(t.TempDir(), "does-not-exist"))
	g, err := NewGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.sleep = func(time.Duration) {}
	f := &fixture{g: g, up: &upstreamSeen{}, clk: &fakeClock{}}
	g.now = f.clk.now
	f.login(t, "wrong-password-abc")
	logs := buf.String()
	if !strings.Contains(logs, "result=lockout_persist_failed stage=write") {
		t.Fatalf("persist failure not logged: %s", logs)
	}
	if strings.Contains(logs, "wrong-password-abc") {
		t.Fatal("password in logs")
	}
}

func TestArgonConcurrencyMustBeOne(t *testing.T) {
	keys(t)
	cfg := baseCfg("http://127.0.0.1:1/", "http://127.0.0.1:2/", t.TempDir())
	cfg.ArgonParallel = 2
	if _, err := NewGate(cfg); err == nil {
		t.Fatal("argon2-concurrency 2 accepted")
	}
}

func TestMultipleAllowedEmails(t *testing.T) {
	keys(t)
	cfg := Config{Upstream: "http://127.0.0.1:1", Team: testTeam, AUD: testAUD,
		AllowedEmail: " Other@Example.com , " + testEmail, Origin: testOrigin, PasswordPHC: testPHC,
		SessionKey: bytes.Repeat([]byte{7}, 32), UpstreamBasic: base64.StdEncoding.EncodeToString([]byte(testBasic)),
		StateDir: t.TempDir(), SessionTTL: time.Hour, SameSite: http.SameSiteLaxMode}
	g, err := NewGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !g.allowed["other@example.com"] || !g.allowed[testEmail] || len(g.allowed) != 2 {
		t.Fatalf("allowed set = %v", g.allowed)
	}
	cfg.AllowedEmail = " , "
	if _, err := NewGate(cfg); err == nil {
		t.Fatal("empty allowed list accepted")
	}
}

func TestEnvFallbackAndFlagPrecedence(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	team := fs.String("team", "", "")
	email := fs.String("allowed-email", "", "")
	env := map[string]string{"GATE_TEAM": "https://env.example", "GATE_ALLOWED_EMAIL": "a@example.com"}
	if err := applyEnv(fs, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"-team=https://flag.example"}); err != nil {
		t.Fatal(err)
	}
	if *team != "https://flag.example" || *email != "a@example.com" {
		t.Fatalf("team=%q email=%q", *team, *email)
	}
	fs2 := flag.NewFlagSet("y", flag.ContinueOnError)
	fs2.Duration("session-ttl", time.Hour, "")
	if err := applyEnv(fs2, func(k string) (string, bool) { return "nope", k == "GATE_SESSION_TTL" }); err == nil {
		t.Fatal("bad env duration accepted")
	}
}
