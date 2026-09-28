package handlers

import (
	"encoding/json"
	"testing"
	"zfsnas/internal/config"
	"zfsnas/internal/oidc"
)

func oidcTestClaims(t *testing.T, sub, username, email string, groups ...string) *oidc.Claims {
	t.Helper()
	g, _ := json.Marshal(groups)
	return &oidc.Claims{
		Issuer:            "https://id.example",
		Subject:           sub,
		PreferredUsername: username,
		Email:             email,
		EmailVerified:     true,
		Raw:               map[string]json.RawMessage{"groups": g},
	}
}

func oidcTestSetup(t *testing.T, users ...config.User) {
	t.Helper()
	if err := config.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveUsers(users); err != nil {
		t.Fatal(err)
	}
}

func oidcTestCfg(autoCreate bool) config.OIDCConfig {
	c := config.OIDCConfig{Enabled: true, IssuerURL: "https://id.example", ClientID: "znas", AutoCreate: autoCreate,
		AdminGroup: "znas-admins", StandardGroup: "znas-users"}
	config.NormaliseOIDC(&c)
	return c
}

func TestOIDCLinksExistingUserByUsername(t *testing.T) {
	oidcTestSetup(t, config.User{ID: "u1", Username: "alice", Role: config.RoleReadOnly})
	u, created, err := oidcResolveUser(oidcTestCfg(false), oidcTestClaims(t, "sub-a", "alice", "a@x"))
	if err != nil || created || u.ID != "u1" {
		t.Fatalf("got %+v created=%v err=%v", u, created, err)
	}
	users, _ := config.LoadUsers()
	if users[0].OIDCSubject != "sub-a" || users[0].Role != config.RoleReadOnly {
		t.Fatalf("link not saved or role changed: %+v", users[0])
	}
	// Same identity again resolves by subject even after a rename at the IdP.
	if u, _, err := oidcResolveUser(oidcTestCfg(false), oidcTestClaims(t, "sub-a", "alice-renamed", "")); err != nil || u.ID != "u1" {
		t.Fatalf("relogin by subject: %+v %v", u, err)
	}
	// A different identity claiming the same username is refused.
	if _, _, err := oidcResolveUser(oidcTestCfg(false), oidcTestClaims(t, "sub-evil", "alice", "")); err == nil {
		t.Fatal("second identity took over a linked account")
	}
}

func TestOIDCEmailMatchNeedsVerifiedEmail(t *testing.T) {
	oidcTestSetup(t, config.User{ID: "u1", Username: "bob", Email: "Bob@Example.com", Role: config.RoleAdmin})
	c := oidcTestCfg(false)
	c.MatchClaim = config.OIDCMatchEmail
	claims := oidcTestClaims(t, "sub-b", "robert", "bob@example.com")
	claims.EmailVerified = false
	if _, _, err := oidcResolveUser(c, claims); err == nil {
		t.Fatal("unverified email linked an account")
	}
	claims.EmailVerified = true
	if u, _, err := oidcResolveUser(c, claims); err != nil || u.ID != "u1" {
		t.Fatalf("verified email: %+v %v", u, err)
	}
}

func TestOIDCNoUserWithoutAutoCreate(t *testing.T) {
	oidcTestSetup(t)
	if _, _, err := oidcResolveUser(oidcTestCfg(false), oidcTestClaims(t, "s", "carol", "", "znas-admins")); err == nil {
		t.Fatal("unknown user let in with auto-create off")
	}
}

func TestOIDCSMBOnlyRefused(t *testing.T) {
	oidcTestSetup(t, config.User{ID: "u1", Username: "dave", Role: config.RoleSMBOnly})
	if _, _, err := oidcResolveUser(oidcTestCfg(false), oidcTestClaims(t, "s", "dave", "")); err == nil {
		t.Fatal("smb-only account signed in")
	}
}

func TestOIDCAutoCreateAndRoleSync(t *testing.T) {
	oidcTestSetup(t)
	c := oidcTestCfg(true)

	// Not in any mapped group and no default role: refused, nothing created.
	if _, _, err := oidcResolveUser(c, oidcTestClaims(t, "s-e", "Erin", "", "family")); err == nil {
		t.Fatal("user without a mapped group was created")
	}

	u, created, err := oidcResolveUser(c, oidcTestClaims(t, "s-e", "Erin", "erin@x", "znas-users"))
	if err != nil || !created {
		t.Fatalf("create: %+v %v", u, err)
	}
	if u.Username != "erin" || u.Role != config.RoleStandard || u.StandardPerms == nil || u.AuthSource != config.AuthSourceOIDC || u.PasswordHash != "" {
		t.Fatalf("created user = %+v", u)
	}

	// Promoted at the IdP -> admin on next login.
	u, created, err = oidcResolveUser(c, oidcTestClaims(t, "s-e", "erin", "", "znas-users", "znas-admins"))
	if err != nil || created || u.Role != config.RoleAdmin || u.StandardPerms != nil {
		t.Fatalf("promote: %+v created=%v %v", u, created, err)
	}
	// Removed from every mapped group -> refused.
	if _, _, err := oidcResolveUser(c, oidcTestClaims(t, "s-e", "erin", "")); err == nil {
		t.Fatal("user removed from all groups still signed in")
	}
}

func TestOIDCAutoCreateRejectsBadOrTakenUsername(t *testing.T) {
	oidcTestSetup(t, config.User{ID: "u1", Username: "frank", Email: "f@x", Role: config.RoleAdmin, OIDCSubject: "other", OIDCIssuer: "https://id.example"})
	c := oidcTestCfg(true)
	c.DefaultRole = config.RoleReadOnly
	for _, name := range []string{"../root", "has space", ""} {
		if _, _, err := oidcResolveUser(c, oidcTestClaims(t, "s-"+name, name, "")); err == nil {
			t.Errorf("username %q accepted", name)
		}
	}
	// Match claim is email, so "frank" falls through to auto-create and must
	// not reuse the existing account's name.
	c.MatchClaim = config.OIDCMatchEmail
	if _, _, err := oidcResolveUser(c, oidcTestClaims(t, "s-new", "frank", "new@x")); err == nil {
		t.Fatal("auto-create reused an existing username")
	}
}

func TestOIDCSettingsValidation(t *testing.T) {
	ok := oidcTestCfg(true)
	if err := validateOIDCSettings(ok); err != nil {
		t.Fatal(err)
	}
	bad := []func(c *config.OIDCConfig){
		func(c *config.OIDCConfig) { c.IssuerURL = "http://id.example" },
		func(c *config.OIDCConfig) { c.ClientID = "" },
		func(c *config.OIDCConfig) { c.RedirectURL = "https://nas/elsewhere" },
		func(c *config.OIDCConfig) { c.AdminGroup, c.StandardGroup = "", "" },
	}
	for i, fn := range bad {
		c := ok
		fn(&c)
		if err := validateOIDCSettings(c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
