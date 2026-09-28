// Package oidc is a small OpenID Connect relying-party client for the
// authorization-code flow with PKCE, written against the standard library only.
//
// It covers exactly what the portal needs to sign users in through an external
// identity provider: discovery, building the authorization
// URL, exchanging the code at the token endpoint, and verifying the returned
// ID token (signature against the provider's JWKS, issuer, audience, expiry and
// nonce). It deliberately does not implement refresh tokens, userinfo or
// logout: the portal keeps its own session once the user is identified.
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
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// clockSkew is the tolerance applied to exp / iat / nbf checks.
const clockSkew = 2 * time.Minute

// discoveryTTL bounds how long a discovery document is trusted before it is
// fetched again. The JWKS is refreshed sooner whenever an unknown key id shows
// up, so key rotation on the provider does not wait for this.
const discoveryTTL = time.Hour

// minJWKSRefresh rate-limits JWKS refetches triggered by unknown key ids, so a
// flood of forged tokens can't turn the portal into a request amplifier.
const minJWKSRefresh = 30 * time.Second

// Config is what a Provider needs to talk to one issuer.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // empty for a public client (PKCE only)
	Scopes       []string
}

// Claims holds the ID-token claims the portal uses.
type Claims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          audience `json:"aud"`
	AuthorizedParty   string   `json:"azp"`
	Expiry            int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	NotBefore         int64    `json:"nbf"`
	Nonce             string   `json:"nonce"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	EmailVerified     flexBool `json:"email_verified"`
	// Raw keeps every claim so callers can read a configurable claim name
	// (for example the groups claim).
	Raw map[string]json.RawMessage `json:"-"`
}

// StringList returns claim name as a list of strings. A single string is
// returned as a one-element list; anything else yields nil.
func (c *Claims) StringList(name string) []string {
	raw, ok := c.Raw[name]
	if !ok {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}

// audience accepts both the string and the array form of "aud".
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// flexBool accepts true/false and the "true"/"false" strings some providers send.
type flexBool bool

func (f *flexBool) UnmarshalJSON(b []byte) error {
	switch strings.Trim(string(b), `"`) {
	case "true":
		*f = true
	default:
		*f = false
	}
	return nil
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Provider is a configured relying party for one issuer. It is safe for
// concurrent use.
type Provider struct {
	cfg    Config
	client *http.Client
	now    func() time.Time

	mu          sync.Mutex
	disc        *discovery
	discFetched time.Time
	keys        map[string]crypto.PublicKey
	anonKeys    []crypto.PublicKey // keys published without a kid
	keysFetched time.Time
}

// NewProvider returns a Provider. client may be nil for a default client with
// a 15 s timeout.
func NewProvider(cfg Config, client *http.Client) *Provider {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	cfg.IssuerURL = strings.TrimRight(cfg.IssuerURL, "/")
	return &Provider{cfg: cfg, client: client, now: time.Now}
}

// AuthRequest is the per-login state the caller must keep between the
// redirect to the provider and the callback.
type AuthRequest struct {
	State        string
	Nonce        string
	CodeVerifier string
}

// NewAuthRequest generates fresh random state, nonce and PKCE verifier.
func NewAuthRequest() (AuthRequest, error) {
	var ar AuthRequest
	var err error
	if ar.State, err = randomString(32); err != nil {
		return ar, err
	}
	if ar.Nonce, err = randomString(32); err != nil {
		return ar, err
	}
	if ar.CodeVerifier, err = randomString(48); err != nil {
		return ar, err
	}
	return ar, nil
}

// AuthCodeURL returns the provider URL to send the browser to.
func (p *Provider) AuthCodeURL(ctx context.Context, ar AuthRequest, redirectURI string) (string, error) {
	d, err := p.discovery(ctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(ar.CodeVerifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(p.scopes(), " ")},
		"state":                 {ar.State},
		"nonce":                 {ar.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return d.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Exchange trades the authorization code for tokens and returns the verified
// ID-token claims. The nonce in the token must equal ar.Nonce.
func (p *Provider) Exchange(ctx context.Context, ar AuthRequest, code, redirectURI string) (*Claims, error) {
	d, err := p.discovery(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {ar.CodeVerifier},
	}
	if p.cfg.ClientSecret == "" {
		// Public client: identify ourselves in the body; PKCE is the proof.
		form.Set("client_id", p.cfg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.ClientSecret != "" {
		// client_secret_basic: RFC 6749 §2.3.1 wants both parts form-encoded.
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	var tok struct {
		IDToken   string `json:"id_token"`
		Error     string `json:"error"`
		ErrorDesc string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("token response (HTTP %d) is not JSON", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || tok.Error != "" {
		msg := tok.Error
		if tok.ErrorDesc != "" {
			msg += ": " + tok.ErrorDesc
		}
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("token endpoint rejected the code: %s", msg)
	}
	if tok.IDToken == "" {
		return nil, errors.New("token response has no id_token (is the 'openid' scope allowed?)")
	}
	return p.VerifyIDToken(ctx, tok.IDToken, ar.Nonce)
}

// VerifyIDToken checks the JWT signature and the standard claims.
func (p *Provider) VerifyIDToken(ctx context.Context, raw, nonce string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token is not a compact JWS")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("id_token header is not base64url")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, errors.New("id_token header is not JSON")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("id_token signature is not base64url")
	}
	signed := []byte(parts[0] + "." + parts[1])

	keys, err := p.keysFor(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	verified := false
	for _, k := range keys {
		if verifySignature(hdr.Alg, k, signed, sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("id_token signature is invalid (alg %q, kid %q)", hdr.Alg, hdr.Kid)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("id_token payload is not base64url")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("id_token payload: %w", err)
	}
	if err := json.Unmarshal(payload, &c.Raw); err != nil {
		return nil, fmt.Errorf("id_token payload: %w", err)
	}
	if err := p.checkClaims(&c, nonce); err != nil {
		return nil, err
	}
	return &c, nil
}

func (p *Provider) checkClaims(c *Claims, nonce string) error {
	if strings.TrimRight(c.Issuer, "/") != p.cfg.IssuerURL {
		return fmt.Errorf("id_token issuer %q does not match %q", c.Issuer, p.cfg.IssuerURL)
	}
	if c.Subject == "" {
		return errors.New("id_token has no subject")
	}
	audOK := false
	for _, a := range c.Audience {
		if a == p.cfg.ClientID {
			audOK = true
		}
	}
	if !audOK {
		return errors.New("id_token was not issued for this client")
	}
	if len(c.Audience) > 1 && c.AuthorizedParty != "" && c.AuthorizedParty != p.cfg.ClientID {
		return errors.New("id_token authorized party is another client")
	}
	now := p.now()
	if c.Expiry == 0 || now.After(time.Unix(c.Expiry, 0).Add(clockSkew)) {
		return errors.New("id_token has expired")
	}
	if c.NotBefore != 0 && now.Add(clockSkew).Before(time.Unix(c.NotBefore, 0)) {
		return errors.New("id_token is not valid yet")
	}
	if c.IssuedAt != 0 && now.Add(clockSkew).Before(time.Unix(c.IssuedAt, 0)) {
		return errors.New("id_token was issued in the future (check the clocks)")
	}
	if nonce == "" || c.Nonce != nonce {
		return errors.New("id_token nonce does not match this login")
	}
	return nil
}

func (p *Provider) scopes() []string {
	if len(p.cfg.Scopes) == 0 {
		return []string{"openid"}
	}
	return p.cfg.Scopes
}

// Discover fetches (or returns the cached) discovery document. It is exported
// so the settings page can test a configuration before saving it.
func (p *Provider) Discover(ctx context.Context) error {
	_, err := p.discovery(ctx)
	return err
}

func (p *Provider) discovery(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	if p.disc != nil && p.now().Sub(p.discFetched) < discoveryTTL {
		d := p.disc
		p.mu.Unlock()
		return d, nil
	}
	p.mu.Unlock()

	var d discovery
	if err := p.getJSON(ctx, p.cfg.IssuerURL+"/.well-known/openid-configuration", &d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if strings.TrimRight(d.Issuer, "/") != p.cfg.IssuerURL {
		return nil, fmt.Errorf("discovery: provider says its issuer is %q, not %q", d.Issuer, p.cfg.IssuerURL)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, errors.New("discovery: document is missing an endpoint")
	}
	p.mu.Lock()
	p.disc = &d
	p.discFetched = p.now()
	p.mu.Unlock()
	return &d, nil
}

// keysFor returns the candidate verification keys for kid, refetching the
// JWKS once if the kid is unknown (key rotation).
func (p *Provider) keysFor(ctx context.Context, kid string) ([]crypto.PublicKey, error) {
	lookup := func() []crypto.PublicKey {
		p.mu.Lock()
		defer p.mu.Unlock()
		if kid != "" {
			if k, ok := p.keys[kid]; ok {
				return []crypto.PublicKey{k}
			}
			return nil
		}
		out := append([]crypto.PublicKey(nil), p.anonKeys...)
		for _, k := range p.keys {
			out = append(out, k)
		}
		return out
	}
	if ks := lookup(); len(ks) > 0 {
		return ks, nil
	}
	p.mu.Lock()
	tooSoon := !p.keysFetched.IsZero() && p.now().Sub(p.keysFetched) < minJWKSRefresh
	p.mu.Unlock()
	if !tooSoon {
		if err := p.refreshKeys(ctx); err != nil {
			return nil, err
		}
		if ks := lookup(); len(ks) > 0 {
			return ks, nil
		}
	}
	return nil, fmt.Errorf("no signing key %q in the provider's JWKS", kid)
}

func (p *Provider) refreshKeys(ctx context.Context) error {
	d, err := p.discovery(ctx)
	if err != nil {
		return err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, d.JWKSURI, &set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	var anon []crypto.PublicKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue // skip key types we don't support
		}
		if k.Kid == "" {
			anon = append(anon, pub)
		} else {
			keys[k.Kid] = pub
		}
	}
	p.mu.Lock()
	p.keys = keys
	p.anonKeys = anon
	p.keysFetched = p.now()
	p.mu.Unlock()
	return nil
}

func (p *Provider) getJSON(ctx context.Context, u string, v interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	dec := base64.RawURLEncoding.DecodeString
	switch k.Kty {
	case "RSA":
		n, err := dec(k.N)
		if err != nil {
			return nil, err
		}
		e, err := dec(k.E)
		if err != nil {
			return nil, err
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() < 3 || eInt.Int64() > 1<<31-1 {
			return nil, errors.New("bad RSA exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("RSA key shorter than 2048 bits")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := dec(k.X)
		if err != nil {
			return nil, err
		}
		y, err := dec(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("EC point is not on the curve")
		}
		return pub, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := dec(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// verifySignature checks sig over signed with key, for the JWS algorithm alg.
// The algorithm must agree with the key type, so a token can't pick an
// algorithm the key was never meant for.
func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	hashFor := func(h crypto.Hash) []byte {
		switch h {
		case crypto.SHA384:
			s := sha512.Sum384(signed)
			return s[:]
		case crypto.SHA512:
			s := sha512.Sum512(signed)
			return s[:]
		default:
			s := sha256.Sum256(signed)
			return s[:]
		}
	}
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key is not RSA")
		}
		h := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}[alg[2:]]
		if alg[0] == 'P' {
			return rsa.VerifyPSS(pub, h, hashFor(h), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(pub, h, hashFor(h), sig)
	case "ES256", "ES384", "ES512":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key is not ECDSA")
		}
		want := map[string]struct {
			h    crypto.Hash
			size int
		}{"ES256": {crypto.SHA256, 32}, "ES384": {crypto.SHA384, 48}, "ES512": {crypto.SHA512, 66}}[alg]
		if (pub.Curve.Params().BitSize+7)/8 != want.size || len(sig) != 2*want.size {
			return errors.New("ECDSA signature/curve mismatch")
		}
		r := new(big.Int).SetBytes(sig[:want.size])
		s := new(big.Int).SetBytes(sig[want.size:])
		if !ecdsa.Verify(pub, hashFor(want.h), r, s) {
			return errors.New("bad ECDSA signature")
		}
		return nil
	case "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return errors.New("key is not Ed25519")
		}
		if !ed25519.Verify(pub, signed, sig) {
			return errors.New("bad EdDSA signature")
		}
		return nil
	}
	return fmt.Errorf("unsupported alg %q", alg)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
