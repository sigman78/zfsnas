# Single sign-on with PocketID (or any OIDC provider)

ZNAS can let people sign in through an OpenID Connect provider such as
[PocketID](https://pocket-id.org). The portal uses the authorization-code flow
with PKCE and checks the provider's signed ID token itself. It does not trust
headers from a reverse proxy, so it works the same with or without Traefik,
tinyauth or any other proxy in front.

Password login keeps working. Use it as a way back in if the provider is down.

## 1. Create the client in PocketID

1. In PocketID, go to **OIDC Clients → Add OIDC Client**.
2. **Callback URL**: `https://<your-nas-address>/api/auth/oidc/callback`.
   The ZNAS settings card shows the exact value for the address you're using.
3. Leave **Public client** off. ZNAS is a confidential client and keeps the
   secret encrypted on disk.
4. Save, then copy the **Client ID** and **Client secret**.
5. If you plan to create users automatically, set up user groups in PocketID
   (for example `znas-admins` and `znas-users`) and allow them on this client.

## 2. Configure ZNAS

Go to **Settings → Security → Single Sign-On (OIDC)**:

| Field | Value |
|---|---|
| Issuer URL | Your PocketID address, for example `https://id.example.com`. Click **Test** to check it. |
| Client ID / secret | From step 1. |
| Callback URL | Leave blank unless the portal is reached through a fixed hostname behind a reverse proxy. |
| Link existing users by | **Username** (PocketID's `preferred_username`) or **Verified email**. |

Save the settings, then try signing in from a private window **before** you sign
out of your current session.

## How a sign-in finds its ZNAS user

1. **Already linked.** A ZNAS user linked to this PocketID account signs
   in. The link is stored on the ZNAS user as the provider's subject ID, so
   renaming the account in PocketID doesn't break it. No one else can take
   it over by picking the same username.
2. **Existing user, first sign-in.** An unlinked ZNAS user whose username (or
   verified email) matches is linked and signed in. Their role and permissions
   don't change.
3. **No matching user.** The sign-in is refused, unless automatic accounts are
   turned on (see below).

SMB-only accounts can never sign in to the portal, through SSO or otherwise.
An administrator can remove a link from **Users → ⋮ → Unlink single sign-on**.

## Automatic accounts from PocketID groups (optional)

Turn on **Create portal users automatically from provider groups**, then map
groups to roles:

| Setting | Effect |
|---|---|
| Admin group | Members become `admin`. |
| Standard user group | Members become `standard`, with **no** permissions at first. Grant them in Users. |
| Read-only group | Members become `read-only`. |
| Anyone else | Refuse sign-in (default), or create as read-only or standard. |

The most privileged matching group wins. Accounts created this way:

- are **portal-only**: ZNAS doesn't create an SMB or shell account for them, and they have no password;
- are marked **SSO-managed** in the Users list;
- **get their role from the PocketID groups again at every sign-in**. Moving someone to
  another group changes their role, and removing them from all mapped groups
  blocks their sign-in. Changing their role in ZNAS only lasts until their next sign-in.

The username must be a valid Linux username (lowercase letters, digits,
`.`, `_` and `-`), so the account can get SMB or shell access later
without being renamed. If a ZNAS user with that name already exists but isn't
linked, the sign-in is refused. An administrator must link it instead, by
matching the username.

## Hiding the password form

**Hide the password form on the login page** leaves only the SSO button on
`/login`. This only changes what the page shows. Password login isn't
turned off: `/login?local=1` always shows the form, so you can still get in
if PocketID is down. This matters if PocketID runs on this same NAS.

## Notes

- **Two-factor:** a single sign-on skips the portal's own TOTP step. The
  provider handles it (PocketID uses passkeys).
- **Sessions:** a single sign-on creates a normal ZNAS session. It follows the
  **Web Login Timeout** setting and appears under active sessions.
- **Audit log:** every sign-in, refusal, account link and automatic account is
  recorded. Refusals count toward the failed-login alert and the per-IP lockout.
- **Signing out** of ZNAS ends the ZNAS session only, not your PocketID session.
- **Supported signatures:** RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA.
