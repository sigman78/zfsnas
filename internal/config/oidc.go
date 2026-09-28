package config

import "strings"

// OIDCConfig configures sign-in through an OpenID Connect provider.
// The portal is a confidential client using the
// authorization-code flow with PKCE.
//
// An OIDC sign-in always resolves to a portal user:
//   - a user already linked to the provider's subject, or
//   - an unlinked user whose username (or verified email, see MatchClaim)
//     equals the provider's claim — linked on first sign-in, or
//   - when AutoCreate is on, a new portal-only user whose role comes from the
//     provider's groups (AdminGroup / StandardGroup / ReadOnlyGroup, else
//     DefaultRole; no match and no default means the login is refused).
type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	ProviderName string `json:"provider_name,omitempty"` // login button label; default "OIDC"
	IssuerURL    string `json:"issuer_url,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"` // encrypted at rest; never returned by the API
	// RedirectURL overrides the callback URL registered at the provider.
	// Empty = derived from the request host (https://<host>/api/auth/oidc/callback).
	RedirectURL string `json:"redirect_url,omitempty"`
	// MatchClaim picks how an unlinked provider identity finds its portal
	// user: "preferred_username" (default) or "email" (verified emails only).
	MatchClaim string `json:"match_claim,omitempty"`
	// HidePasswordLogin hides the username/password form on the login page.
	// It is a UI switch only: /login?local=1 still shows the form, so the
	// portal stays reachable when the provider is down.
	HidePasswordLogin bool `json:"hide_password_login,omitempty"`

	AutoCreate    bool   `json:"auto_create,omitempty"`
	GroupsClaim   string `json:"groups_claim,omitempty"` // default "groups"
	AdminGroup    string `json:"admin_group,omitempty"`
	StandardGroup string `json:"standard_group,omitempty"`
	ReadOnlyGroup string `json:"read_only_group,omitempty"`
	DefaultRole   string `json:"default_role,omitempty"` // "" (refuse), "standard" or "read-only"
}

// OIDC match-claim values.
const (
	OIDCMatchUsername = "preferred_username"
	OIDCMatchEmail    = "email"
)

// NormaliseOIDC fills in defaults and drops invalid values.
func NormaliseOIDC(c *OIDCConfig) {
	c.IssuerURL = strings.TrimRight(strings.TrimSpace(c.IssuerURL), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	c.ProviderName = strings.TrimSpace(c.ProviderName)
	if c.ProviderName == "" {
		c.ProviderName = "OIDC"
	}
	if c.MatchClaim != OIDCMatchEmail {
		c.MatchClaim = OIDCMatchUsername
	}
	c.GroupsClaim = strings.TrimSpace(c.GroupsClaim)
	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}
	c.AdminGroup = strings.TrimSpace(c.AdminGroup)
	c.StandardGroup = strings.TrimSpace(c.StandardGroup)
	c.ReadOnlyGroup = strings.TrimSpace(c.ReadOnlyGroup)
	if c.DefaultRole != RoleStandard && c.DefaultRole != RoleReadOnly {
		c.DefaultRole = ""
	}
}

// Ready reports whether sign-in through the provider can be offered.
func (c *OIDCConfig) Ready() bool {
	return c.Enabled && c.IssuerURL != "" && c.ClientID != ""
}

// RoleForGroups maps the provider's groups to a portal role. The most
// privileged match wins; with no match the DefaultRole applies, and "" means
// the user must not be let in.
func (c *OIDCConfig) RoleForGroups(groups []string) string {
	has := func(name string) bool {
		if name == "" {
			return false
		}
		for _, g := range groups {
			if g == name {
				return true
			}
		}
		return false
	}
	switch {
	case has(c.AdminGroup):
		return RoleAdmin
	case has(c.StandardGroup):
		return RoleStandard
	case has(c.ReadOnlyGroup):
		return RoleReadOnly
	}
	return c.DefaultRole
}
