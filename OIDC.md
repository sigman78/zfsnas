# OIDC sign-in

ZNAS can let people sign in through an OpenID Connect (OIDC) provider. The
portal uses the authorization-code flow with PKCE and checks the provider's
signed ID token itself. It does not trust headers from a reverse proxy, so it
works the same with or without a proxy or forward-auth service in front.

Password login keeps working. Use it as a way back in if the provider is down.

## 1. Register ZNAS at the provider

Create an OIDC client (sometimes called an application) at your provider:

1. **Redirect / callback URL**: `https://<your-nas-address>/api/auth/oidc/callback`.
   The ZNAS settings card shows the exact value for the address you're using.
2. **Client type**: confidential, with a client secret. ZNAS stores the secret
   encrypted on disk. A public client without a secret also works; PKCE then
   proves the login.
3. **Scopes**: ZNAS requests `openid profile email groups`.
4. Copy the **client ID** and **client secret**.
5. If you plan to create users automatically, set up groups at the provider
   (for example `znas-admins` and `znas-users`) and make sure the provider
   puts them in the ID token's groups claim.

## 2. Configure ZNAS

Go to **Settings → Security → OIDC Sign-In**:

| Field | Value |
|---|---|
| Login button label | Text on the login button. Default `OIDC`. |
| Issuer URL | The provider's issuer, for example `https://id.example.com`. Click **Test** to check it. |
| Client ID / secret | From step 1. |
| Callback URL | Leave blank unless the portal is reached through a fixed hostname behind a reverse proxy. |
| Link existing users by | **Username** (the `preferred_username` claim) or **Verified email**. |

Save the settings, then try signing in from a private window **before** you sign
out of your current session.

## How a sign-in finds its ZNAS user

1. **Already linked.** A ZNAS user linked to this provider account signs in.
   The link is stored on the ZNAS user as the provider's subject ID, so
   renaming the account at the provider doesn't break it. No one else can take
   it over by picking the same username.
2. **Existing user, first sign-in.** An unlinked ZNAS user whose username (or
   verified email) matches is linked and signed in. Their role and permissions
   don't change.
3. **No matching user.** The sign-in is refused, unless automatic accounts are
   turned on (see below).

SMB-only accounts can never sign in to the portal, through OIDC or otherwise.
An administrator can remove a link from **Users → ⋮ → Unlink OIDC**.

## Automatic accounts from provider groups (optional)

Turn on **Create portal users automatically from provider groups**, then map
groups to roles:

| Setting | Effect |
|---|---|
| Groups claim | Name of the ID-token claim that lists the groups. Default `groups`. |
| Admin group | Members become `admin`. |
| Standard user group | Members become `standard`, with **no** permissions at first. Grant them in Users. |
| Read-only group | Members become `read-only`. |
| Anyone else | Refuse sign-in (default), or create as read-only or standard. |

The most privileged matching group wins. Accounts created this way:

- are **portal-only**: ZNAS doesn't create an SMB or shell account for them, and they have no password;
- are marked **OIDC-managed** in the Users list;
- **get their role from the provider's groups again at every sign-in**. Moving
  someone to another group changes their role, and removing them from all
  mapped groups blocks their sign-in. Changing their role in ZNAS only lasts
  until their next sign-in.

The username must be a valid Linux username (lowercase letters, digits,
`.`, `_` and `-`), so the account can get SMB or shell access later
without being renamed. If a ZNAS user with that name already exists but isn't
linked, the sign-in is refused. An administrator must link it instead, by
matching the username.

## Hiding the password form

**Hide the password form on the login page** leaves only the OIDC button on
`/login`. This only changes what the page shows. Password login isn't
turned off: `/login?local=1` always shows the form, so you can still get in
if the provider is down. This matters if the provider runs on this same NAS.

## Notes

- **Two-factor:** an OIDC sign-in skips the portal's own TOTP step. Enforce
  multi-factor authentication at the provider.
- **Sessions:** an OIDC sign-in creates a normal ZNAS session. It follows the
  **Web Login Timeout** setting and appears under active sessions.
- **Audit log:** every sign-in, refusal, account link and automatic account is
  recorded. Refusals count toward the failed-login alert and the per-IP lockout.
- **Signing out** of ZNAS ends the ZNAS session only, not your session at the provider.
- **Supported signatures:** RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA.
