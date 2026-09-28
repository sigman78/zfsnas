package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS and a token endpoint
// that returns whatever ID token the test prepared.
type fakeIdP struct {
	srv       *httptest.Server
	jwks      []map[string]string
	idToken   string
	lastForm  url.Values
	lastBasic [2]string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
			"jwks_uri":               f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": f.jwks})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.lastForm = r.PostForm
		u, p, _ := r.BasicAuth()
		f.lastBasic = [2]string{u, p}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.idToken, "token_type": "Bearer"})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) provider() *Provider {
	return NewProvider(Config{IssuerURL: f.srv.URL, ClientID: "znas", ClientSecret: "s3cr+t"}, f.srv.Client())
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(t *testing.T, alg, kid string, key crypto.Signer, claims map[string]interface{}) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := b64(hdr) + "." + b64(body)
	var sig []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		h := sha256.Sum256([]byte(input))
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	case *ecdsa.PrivateKey:
		h := sha256.Sum256([]byte(input))
		r, s, e := ecdsa.Sign(rand.Reader, k, h[:])
		err = e
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func rsaJWK(kid string, k *rsa.PublicKey) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
}

func (f *fakeIdP) claims(nonce string) map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iss": f.srv.URL, "sub": "user-123", "aud": "znas",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": nonce,
		"preferred_username": "alice", "email": "alice@example.com", "email_verified": true,
		"groups": []string{"znas-admins", "family"},
	}
}

func TestExchangeRS256(t *testing.T) {
	f := newFakeIdP(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.jwks = []map[string]string{rsaJWK("k1", &key.PublicKey)}
	ar, _ := NewAuthRequest()
	f.idToken = sign(t, "RS256", "k1", key, f.claims(ar.Nonce))

	p := f.provider()
	authURL, err := p.AuthCodeURL(context.Background(), ar, "https://nas/cb")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") != ar.State {
		t.Fatalf("auth URL missing PKCE/state: %s", authURL)
	}

	c, err := p.Exchange(context.Background(), ar, "the-code", "https://nas/cb")
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-123" || c.PreferredUsername != "alice" || !bool(c.EmailVerified) {
		t.Fatalf("claims = %+v", c)
	}
	if g := c.StringList("groups"); len(g) != 2 || g[0] != "znas-admins" {
		t.Fatalf("groups = %v", g)
	}
	if f.lastForm.Get("code_verifier") != ar.CodeVerifier || f.lastForm.Get("code") != "the-code" {
		t.Fatalf("token form = %v", f.lastForm)
	}
	if f.lastBasic != [2]string{"znas", url.QueryEscape("s3cr+t")} {
		t.Fatalf("basic auth = %v", f.lastBasic)
	}
}

func TestVerifyES256AndEdDSA(t *testing.T) {
	f := newFakeIdP(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	f.jwks = []map[string]string{
		{"kty": "EC", "kid": "ec", "crv": "P-256", "x": b64(ec.X.FillBytes(make([]byte, 32))), "y": b64(ec.Y.FillBytes(make([]byte, 32)))},
		{"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": b64(edPub)},
	}
	p := f.provider()
	if _, err := p.VerifyIDToken(context.Background(), sign(t, "ES256", "ec", ec, f.claims("n")), "n"); err != nil {
		t.Fatalf("ES256: %v", err)
	}
	if _, err := p.VerifyIDToken(context.Background(), sign(t, "EdDSA", "ed", edPriv, f.claims("n")), "n"); err != nil {
		t.Fatalf("EdDSA: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFakeIdP(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.jwks = []map[string]string{rsaJWK("k1", &key.PublicKey)}
	p := f.provider()

	mod := func(fn func(c map[string]interface{})) map[string]interface{} {
		c := f.claims("n")
		fn(c)
		return c
	}
	cases := map[string]string{
		"wrong key":      sign(t, "RS256", "k1", other, f.claims("n")),
		"unknown kid":    sign(t, "RS256", "nope", key, f.claims("n")),
		"wrong audience": sign(t, "RS256", "k1", key, mod(func(c map[string]interface{}) { c["aud"] = "someone-else" })),
		"wrong issuer":   sign(t, "RS256", "k1", key, mod(func(c map[string]interface{}) { c["iss"] = "https://evil" })),
		"expired":        sign(t, "RS256", "k1", key, mod(func(c map[string]interface{}) { c["exp"] = time.Now().Add(-time.Hour).Unix() })),
		"nonce":          sign(t, "RS256", "k1", key, f.claims("other-nonce")),
		"no subject":     sign(t, "RS256", "k1", key, mod(func(c map[string]interface{}) { delete(c, "sub") })),
		"alg none":       strings.Join(append(strings.Split(sign(t, "RS256", "k1", key, f.claims("n")), ".")[:2], ""), "."),
	}
	// alg confusion: header claims HS256 with the RSA modulus as the "secret".
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": "k1"})
	body, _ := json.Marshal(f.claims("n"))
	cases["alg HS256"] = b64(hdr) + "." + b64(body) + "." + b64([]byte("x"))

	for name, tok := range cases {
		if _, err := p.VerifyIDToken(context.Background(), tok, "n"); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	f := newFakeIdP(t)
	p := NewProvider(Config{IssuerURL: f.srv.URL + "/other", ClientID: "znas"}, f.srv.Client())
	if err := p.Discover(context.Background()); err == nil {
		t.Fatal("discovery accepted a document for another issuer")
	}
}
