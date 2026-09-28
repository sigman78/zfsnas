package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/oidc"
	"zfsnas/internal/session"

	"github.com/gorilla/mux"
)

// Sign-in through an OpenID Connect provider.
//
//	GET /api/auth/oidc/info      public: is OIDC sign-in offered, and the button label
//	GET /api/auth/oidc/login     redirect the browser to the provider
//	GET /api/auth/oidc/callback  provider redirects back here with ?code&state
//
// A successful callback resolves to a portal user (see config.OIDCConfig for
// the linking and auto-create rules) and then creates exactly the same session
// as a password login, so every permission check downstream is unchanged.
// The portal's own TOTP step is not applied: the provider is the second factor.

const (
	oidcCallbackPath = "/api/auth/oidc/callback"
	oidcStateCookie  = "zfsnas_oidc_state"
	oidcPendingTTL   = 10 * time.Minute
	oidcMaxPending   = 1000
)

// oidcPending holds the in-flight logins between the redirect to the provider
// and the callback, keyed by the state value.
var oidcPending = struct {
	sync.Mutex
	m map[string]oidcPendingLogin
}{m: map[string]oidcPendingLogin{}}

type oidcPendingLogin struct {
	req         oidc.AuthRequest
	redirectURI string
	created     time.Time
}

// oidcProviderCache rebuilds the provider only when its settings change, so
// the discovery document and signing keys stay cached between logins.
var oidcProviderCache struct {
	sync.Mutex
	key string
	p   *oidc.Provider
}

func oidcProviderFor(c config.OIDCConfig) *oidc.Provider {
	key := c.IssuerURL + "\x00" + c.ClientID + "\x00" + c.ClientSecret
	oidcProviderCache.Lock()
	defer oidcProviderCache.Unlock()
	if oidcProviderCache.p == nil || oidcProviderCache.key != key {
		oidcProviderCache.p = oidc.NewProvider(oidc.Config{
			IssuerURL:    c.IssuerURL,
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       []string{"openid", "profile", "email", "groups"},
		}, nil)
		oidcProviderCache.key = key
	}
	return oidcProviderCache.p
}

// oidcRedirectURI is the callback URL registered at the provider.
func oidcRedirectURI(r *http.Request, c config.OIDCConfig) string {
	if c.RedirectURL != "" {
		return c.RedirectURL
	}
	// The portal only serves HTTPS, and a reverse proxy in front of it
	// (Traefik) terminates HTTPS too, so the scheme is always https.
	return "https://" + r.Host + oidcCallbackPath
}

// HandleOIDCInfo tells the login page whether to offer OIDC sign-in.
func HandleOIDCInfo(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := appCfg.OIDC
		if !c.Ready() {
			jsonOK(w, map[string]interface{}{"enabled": false})
			return
		}
		jsonOK(w, map[string]interface{}{
			"enabled":             true,
			"provider_name":       c.ProviderName,
			"hide_password_login": c.HidePasswordLogin,
		})
	}
}

// HandleOIDCLogin starts a login: remember state/nonce/PKCE, bind them to this
// browser with a cookie, and redirect to the provider.
func HandleOIDCLogin(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := appCfg.OIDC
		if !c.Ready() {
			oidcFail(w, r, "OIDC sign-in is not enabled.")
			return
		}
		ar, err := oidc.NewAuthRequest()
		if err != nil {
			oidcFail(w, r, "Could not start OIDC sign-in.")
			return
		}
		redirectURI := oidcRedirectURI(r, c)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		authURL, err := oidcProviderFor(c).AuthCodeURL(ctx, ar, redirectURI)
		if err != nil {
			audit.Log(audit.Entry{
				Action:  audit.ActionLoginFailed,
				Result:  audit.ResultError,
				Details: "OIDC: provider unreachable: " + err.Error() + " (from " + clientIP(r) + ")",
			})
			oidcFail(w, r, "The OIDC provider is unreachable. Use the password form instead.")
			return
		}

		now := time.Now()
		oidcPending.Lock()
		for k, v := range oidcPending.m {
			if now.Sub(v.created) > oidcPendingTTL {
				delete(oidcPending.m, k)
			}
		}
		if len(oidcPending.m) >= oidcMaxPending {
			oidcPending.Unlock()
			oidcFail(w, r, "Too many sign-ins in progress. Try again in a few minutes.")
			return
		}
		oidcPending.m[ar.State] = oidcPendingLogin{req: ar, redirectURI: redirectURI, created: now}
		oidcPending.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     oidcStateCookie,
			Value:    ar.State,
			Path:     "/api/auth/oidc/",
			HttpOnly: true,
			Secure:   true,
			// Lax: the provider's redirect back is a top-level GET, which
			// still carries the cookie.
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(oidcPendingTTL.Seconds()),
		})
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// HandleOIDCCallback finishes a login.
func HandleOIDCCallback(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		c := appCfg.OIDC
		// Whatever happens next, this state cookie is spent.
		http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/auth/oidc/", HttpOnly: true, Secure: true, MaxAge: -1})

		if !c.Ready() {
			oidcFail(w, r, "OIDC sign-in is not enabled.")
			return
		}
		if locked, _ := loginLimiter.check(ip); locked {
			oidcFail(w, r, "Too many failed attempts. Try again later.")
			return
		}
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			msg := e
			if d := q.Get("error_description"); d != "" {
				msg = d
			}
			oidcFail(w, r, "The OIDC provider did not sign you in: "+msg)
			return
		}

		// The state must match both a pending login and this browser's
		// cookie; otherwise someone else's login could be completed here.
		state := q.Get("state")
		cookie, err := r.Cookie(oidcStateCookie)
		if state == "" || err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
			oidcFail(w, r, "This sign-in link has expired or was opened in another browser. Please try again.")
			return
		}
		oidcPending.Lock()
		pending, ok := oidcPending.m[state]
		delete(oidcPending.m, state)
		oidcPending.Unlock()
		if !ok || time.Since(pending.created) > oidcPendingTTL {
			oidcFail(w, r, "This sign-in has expired. Please try again.")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		claims, err := oidcProviderFor(c).Exchange(ctx, pending.req, q.Get("code"), pending.redirectURI)
		if err != nil {
			oidcDeny(w, r, "", "", "token verification failed: "+err.Error(), "OIDC sign-in failed.")
			return
		}

		user, created, err := oidcResolveUser(c, claims)
		if err != nil {
			var denied *oidcDenied
			if errors.As(err, &denied) {
				oidcDeny(w, r, denied.who, claims.Subject, denied.reason, denied.userMsg)
				return
			}
			oidcDeny(w, r, "", claims.Subject, err.Error(), "Sign-in failed on the server.")
			return
		}

		hardCap, idle := sessionDurationsFor(appCfg.WebSession)
		sess, err := session.Default.Create(user.ID, user.Username, user.Role, hardCap, idle)
		if err != nil {
			oidcFail(w, r, "Could not create a session.")
			return
		}
		loginLimiter.recordSuccess(ip)
		alerts.ResetFailedLogins()
		details := "via OIDC from " + ip
		if created {
			details += " (account created by OIDC)"
		}
		audit.Log(audit.Entry{
			User:    user.Username,
			Role:    user.Role,
			Action:  audit.ActionLogin,
			Result:  audit.ResultOK,
			Details: details,
		})
		if created {
			audit.Log(audit.Entry{
				User:    user.Username,
				Role:    user.Role,
				Action:  audit.ActionCreateUser,
				Target:  user.Username,
				Result:  audit.ResultOK,
				Details: "role: " + user.Role + ", created on first OIDC sign-in",
			})
			go alerts.Send(
				alerts.EventUserCreated,
				"User created: "+user.Username,
				"User Account Created",
				"User '"+user.Username+"' (role: "+user.Role+") was created on first OIDC sign-in.",
			)
		}
		SetSessionCookie(w, sess.Token, hardCap)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// oidcDenied is a refusal with a message fit to show the user.
type oidcDenied struct {
	who, reason, userMsg string
}

func (e *oidcDenied) Error() string { return e.reason }

// oidcUsernameRe matches usernames an auto-created account may take. It is
// the portable Linux user-name set, so the account can later be given SMB or
// shell access without renaming.
var oidcUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// oidcResolveUser maps verified claims to a portal user, linking or creating
// one as configured. created reports whether a new user was made.
func oidcResolveUser(c config.OIDCConfig, claims *oidc.Claims) (*config.User, bool, error) {
	config.LockUsers()
	defer config.UnlockUsers()
	users, err := config.LoadUsers()
	if err != nil {
		return nil, false, errors.New("failed to load users")
	}
	groups := claims.StringList(c.GroupsClaim)
	name := claims.PreferredUsername
	if name == "" {
		name = claims.Email
	}

	// 1. Already linked to this provider identity.
	for i := range users {
		u := &users[i]
		if u.OIDCSubject == claims.Subject && u.OIDCIssuer == claims.Issuer {
			if u.Role == config.RoleSMBOnly {
				return nil, false, &oidcDenied{u.Username, "SMB-only account", "This account cannot sign in to the portal."}
			}
			if u.AuthSource == config.AuthSourceOIDC && c.AutoCreate {
				// Provider-managed account: the role follows the groups, and
				// losing every mapped group revokes access.
				role := c.RoleForGroups(groups)
				if role == "" {
					return nil, false, &oidcDenied{u.Username, "no mapped OIDC group", "Your OIDC account is not in a group allowed to use this portal."}
				}
				if role != u.Role {
					oidcApplyRole(u, role)
					if err := config.SaveUsers(users); err != nil {
						return nil, false, errors.New("failed to save user")
					}
				}
			}
			return u, false, nil
		}
	}

	// 2. An existing, not-yet-linked user with the same username / email.
	var match *config.User
	switch c.MatchClaim {
	case config.OIDCMatchEmail:
		if claims.Email != "" && bool(claims.EmailVerified) {
			for i := range users {
				if strings.EqualFold(users[i].Email, claims.Email) {
					match = &users[i]
					break
				}
			}
		}
	default:
		if claims.PreferredUsername != "" {
			match = config.FindUserByUsername(users, claims.PreferredUsername)
		}
	}
	if match != nil {
		if match.OIDCSubject != "" {
			// Linked to a different provider identity: never hand it over
			// just because the name matches.
			return nil, false, &oidcDenied{match.Username, "account is linked to another OIDC identity", "This portal account is linked to a different OIDC account."}
		}
		if match.Role == config.RoleSMBOnly {
			return nil, false, &oidcDenied{match.Username, "SMB-only account", "This account cannot sign in to the portal."}
		}
		match.OIDCIssuer = claims.Issuer
		match.OIDCSubject = claims.Subject
		if err := config.SaveUsers(users); err != nil {
			return nil, false, errors.New("failed to save user")
		}
		audit.Log(audit.Entry{
			User:    match.Username,
			Role:    match.Role,
			Action:  audit.ActionUpdateUser,
			Target:  match.Username,
			Result:  audit.ResultOK,
			Details: "linked to OIDC account " + name,
		})
		return match, false, nil
	}

	// 3. Create a new portal-only user.
	if !c.AutoCreate {
		return nil, false, &oidcDenied{name, "no matching portal user", "There is no portal account for " + name + ". Ask an administrator to create one."}
	}
	role := c.RoleForGroups(groups)
	if role == "" {
		return nil, false, &oidcDenied{name, "no mapped OIDC group", "Your OIDC account is not in a group allowed to use this portal."}
	}
	username := strings.ToLower(claims.PreferredUsername)
	if !oidcUsernameRe.MatchString(username) {
		return nil, false, &oidcDenied{name, "username " + claims.PreferredUsername + " is not a valid portal username", "Your OIDC username can't be used as a portal username (lowercase letters, digits, . _ - only)."}
	}
	if config.FindUserByUsername(users, username) != nil {
		return nil, false, &oidcDenied{username, "username already taken by an unlinked account", "A portal account named " + username + " already exists. Ask an administrator to link it."}
	}
	u := config.User{
		ID:          newID(),
		Username:    username,
		Email:       claims.Email,
		CreatedAt:   time.Now(),
		OIDCIssuer:  claims.Issuer,
		OIDCSubject: claims.Subject,
		AuthSource:  config.AuthSourceOIDC,
		// No PasswordHash: the account can't sign in with a password until an
		// administrator sets one.
	}
	oidcApplyRole(&u, role)
	users = append(users, u)
	if err := config.SaveUsers(users); err != nil {
		return nil, false, errors.New("failed to save user")
	}
	return &users[len(users)-1], true, nil
}

// oidcApplyRole sets role, giving a new standard user an empty permission set
// (an administrator grants capabilities afterwards) and clearing it otherwise.
func oidcApplyRole(u *config.User, role string) {
	u.Role = role
	if role == config.RoleStandard {
		if u.StandardPerms == nil {
			u.StandardPerms = &config.StandardPermissions{}
		}
	} else {
		u.StandardPerms = nil
	}
}

// oidcDeny records a refused login and sends the user back to the login page.
func oidcDeny(w http.ResponseWriter, r *http.Request, who, subject, reason, userMsg string) {
	ip := clientIP(r)
	loginLimiter.recordFailure(ip)
	alerts.RecordFailedLogin()
	details := "OIDC: " + reason
	if subject != "" {
		details += " (subject " + subject + ")"
	}
	audit.Log(audit.Entry{
		User:    who,
		Action:  audit.ActionLoginFailed,
		Result:  audit.ResultError,
		Details: details + " (from " + ip + ")",
	})
	oidcFail(w, r, userMsg)
}

// oidcFail redirects to the login page with a message it shows as plain text.
func oidcFail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/login?oidc_error="+url.QueryEscape(msg), http.StatusSeeOther)
}

// ── Settings (admin) ─────────────────────────────────────────────────────────

type oidcSettingsView struct {
	config.OIDCConfig
	ClientSecret      string `json:"client_secret"` // always "" — shadows the real secret
	HasClientSecret   bool   `json:"has_client_secret"`
	SuggestedCallback string `json:"suggested_callback"`
}

// HandleGetOIDCSettings returns the OIDC settings without the client secret.
func HandleGetOIDCSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, oidcSettingsView{
			OIDCConfig:        appCfg.OIDC,
			HasClientSecret:   appCfg.OIDC.ClientSecret != "",
			SuggestedCallback: "https://" + r.Host + oidcCallbackPath,
		})
	}
}

// HandleUpdateOIDCSettings saves the OIDC settings. An empty client_secret
// keeps the stored one; clear_client_secret removes it.
func HandleUpdateOIDCSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			config.OIDCConfig
			ClearClientSecret bool `json:"clear_client_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		next := req.OIDCConfig
		if next.ClientSecret == "" && !req.ClearClientSecret {
			next.ClientSecret = appCfg.OIDC.ClientSecret
		}
		config.NormaliseOIDC(&next)
		if err := validateOIDCSettings(next); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		prev := appCfg.OIDC
		appCfg.OIDC = next
		if err := config.SaveAppConfig(appCfg); err != nil {
			appCfg.OIDC = prev
			jsonErr(w, http.StatusInternalServerError, "failed to save settings")
			return
		}
		sess := MustSession(r)
		state := "disabled"
		if next.Enabled {
			state = "enabled"
		}
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSettings,
			Result:  audit.ResultOK,
			Details: "OIDC settings updated (" + state + ", issuer " + next.IssuerURL + ", auto-create " + map[bool]string{true: "on", false: "off"}[next.AutoCreate] + ")",
		})
		jsonOK(w, map[string]string{"message": "OIDC settings saved"})
	}
}

// HandleTestOIDCSettings checks that the issuer answers OIDC discovery.
func HandleTestOIDCSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IssuerURL string `json:"issuer_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	issuer := strings.TrimRight(strings.TrimSpace(req.IssuerURL), "/")
	if err := validateIssuerURL(issuer); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := oidc.NewProvider(oidc.Config{IssuerURL: issuer}, nil).Discover(ctx); err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "provider found"})
}

func validateOIDCSettings(c config.OIDCConfig) error {
	if !c.Enabled {
		return nil
	}
	if err := validateIssuerURL(c.IssuerURL); err != nil {
		return err
	}
	if c.ClientID == "" {
		return errors.New("client ID is required")
	}
	if c.RedirectURL != "" {
		u, err := url.Parse(c.RedirectURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != oidcCallbackPath {
			return errors.New("callback URL must be https://<host>" + oidcCallbackPath)
		}
	}
	if c.AutoCreate && c.AdminGroup == "" && c.StandardGroup == "" && c.ReadOnlyGroup == "" && c.DefaultRole == "" {
		return errors.New("auto-create needs at least one group mapping or a default role")
	}
	return nil
}

func validateIssuerURL(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return errors.New("issuer URL is not a valid URL")
	}
	if u.Scheme != "https" {
		return errors.New("issuer URL must use https")
	}
	return nil
}

// HandleUnlinkOIDC removes a user's link to their provider identity, so the
// next OIDC sign-in links (or is refused) afresh.
func HandleUnlinkOIDC(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	config.LockUsers()
	defer config.UnlockUsers()
	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	u := config.FindUserByID(users, id)
	if u == nil {
		jsonErr(w, http.StatusNotFound, "user not found")
		return
	}
	if u.AuthSource == config.AuthSourceOIDC && u.PasswordHash == "" {
		jsonErr(w, http.StatusConflict, "this account was created by OIDC and has no password; set a password before unlinking it")
		return
	}
	u.OIDCIssuer, u.OIDCSubject, u.AuthSource = "", "", ""
	if err := config.SaveUsers(users); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save user")
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateUser,
		Target:  u.Username,
		Result:  audit.ResultOK,
		Details: "OIDC link removed",
	})
	jsonOK(w, map[string]string{"message": "OIDC link removed"})
}
