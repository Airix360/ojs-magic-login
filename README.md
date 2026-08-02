# OJS Magic Login

<table>
<tr>
<td><strong>Version</strong></td><td>1.3.0</td>
<td><strong>OJS</strong></td><td>3.5.0+</td>
<td><strong>PHP</strong></td><td>8.1+</td>
<td><strong>License</strong></td><td>GPL-3.0-or-later</td>
</tr>
</table>

[![CI](https://github.com/thathman/ojs-magic-login/actions/workflows/ci.yml/badge.svg)](https://github.com/thathman/ojs-magic-login/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-db61a2?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/thathman)

Passwordless sign-in for Open Journal Systems 3.5. Users receive a one-time link by email and sign in with a single click — no password required. Works alongside the standard login; neither flow replaces the other.

As of 1.3.0, users can *also* enable sign-in via a 6-digit authenticator-app code (TOTP, RFC 6238) as a second alternative sign-in method — entirely optional, per-account, and independent of the magic-link flow (not a combined two-factor requirement). See [TOTP alternative sign-in](#totp-alternative-sign-in) below.

---

## Screenshots

<br>

**The "Email me a sign-in link" button is injected below the password form, alongside any other sign-in options already active on the journal.**

![Login page — magic-link button below password form, alongside ORCID and Google](screenshot/01-login-button.png)

<br>

**Clicking the button opens a focused request page where the user enters their account email.**

![Request page — email field and submit button](screenshot/02-request-form.png)

<br>

**The response is always identical regardless of whether the email matched an account, preventing user enumeration.**

![Sent confirmation — neutral "check your inbox" message](screenshot/03-sent-confirmation.png)

<br>

**The email is delivered immediately with a personalised greeting, the one-time link, and an expiry notice.**

![Email received — personalised body with the magic link and 15-minute expiry](screenshot/04-email-received.png)

<br>

**Clicking the link in the email brings the user to a one-click confirm page. The token is verified read-only on GET; it is consumed only when the user clicks Sign in now.**

![Confirm page — "Sign in now" button with "Request a new link" fallback](screenshot/05-confirm-page.png)

<br>

**The email template appears in Settings › Emails and is fully editable by journal managers — no code changes required.**

![Manage Emails — "Magic sign-in link" listed with an Edit button](screenshot/06-email-template-list.png)

<br>

**Managers can customise the subject and body. Template variables are inserted via the Insert Content picker.**

![Edit Template — subject field, rich-text body editor, and template variable placeholders](screenshot/07-email-template-edit.png)

---

## Features

- One-time email links with configurable expiry (default 15 minutes)
- Per-account minimum interval between requests (default 60 seconds)
- Per-IP sliding-window rate limiting on both the send and verify endpoints
- Selector / verifier token scheme — only `sha256(verifier)` is stored; the database never holds a usable secret
- Token consumed atomically before session creation (single-use guarantee)
- Neutral send response — identical whether the email matched an account or not
- Email template editable from **Settings › Emails** (key `MAGIC_LOGIN_LINK`)
- Settings panel in **Settings › Website › Plugins** — enable/disable per journal, configure TTL and throttle
- Recent-activity panel in the same Settings screen — last 20 sends/sign-ins/rate-limit hits per journal, for admin visibility (not a security control)
- Theme-override support — supply `request.tpl` / `confirm.tpl` inside your theme to apply a custom design
- Zero modifications to OJS core files — hooks only

---

## Requirements

| | Minimum version |
|---|---|
| OJS | 3.5.0 |
| PHP | 8.1 |

---

## Installation

### ~~Via Plugin Gallery~~

~~Search for **Passwordless Sign-in (Magic Link)** in **Settings › Website › Plugins › Plugin Gallery** and click Install.~~

*Pending Plugin Gallery approval — use manual installation for now.*

### Manual

1. Download `magicLogin.tar.gz` from the [Releases](../../releases) page.
2. Unpack into `plugins/generic/` so the result is `plugins/generic/magicLogin/`.
3. In OJS go to **Settings › Website › Plugins › Generic Plugins**, find **Passwordless Sign-in (Magic Link)** and click **Enable**.
4. Click **Settings** and tick **Enable magic-link sign-in for this journal**.

> **Note — versions table**
>
> If you drop the files in manually without using the OJS plugin installer, OJS will not detect the plugin until a row exists in the `versions` table. Run this once after copying the files:
>
> ```sql
> INSERT INTO versions
>   (major, minor, revision, build, date_installed, current,
>    product_type, product, product_class_name, lazy_load, sitewide)
> VALUES (1,2,1,0,NOW(),1,
>   'plugins.generic','magicLogin','MagicLoginPlugin',1,0);
> ```
>
> The Plugin Gallery installer handles this automatically.

---

## Configuration

| Setting | Range | Default | Description |
|---------|-------|---------|-------------|
| Enable magic-link sign-in | on / off | off | Activates the feature for this journal |
| Link validity | 1 – 120 min | 15 min | How long an emailed link remains usable |
| Minimum seconds between requests | 30 – 3600 s | 60 s | Per-account throttle |

---

## How it works

```
User enters email        POST /magicLogin/send
                           IP rate-limit check
                           look up account  (response is identical either way)
                           issue selector + verifier
                           store selector and sha256(verifier)
                           email  /magicLogin/confirm?token=<selector>.<verifier>
                           show neutral "check your inbox" page

User clicks email link   GET /magicLogin/confirm?token=...
                           validate token format (regex)
                           look up selector in DB, check hash + expiry  (read-only)
                           show "Sign in now" button

User clicks Sign in      POST /magicLogin/login
                           IP rate-limit check
                           re-verify token
                           consume token  (delete from DB before session creation)
                           establish OJS session
                           redirect to dashboard
```

---

## Security

| Property | Implementation |
|----------|----------------|
| Secret storage | Only `sha256(verifier)` stored; raw verifier never touches the database |
| Timing attack prevention | `hash_equals()` for constant-time hash comparison, plus response-time padding on `/send` so a matched vs. unmatched email cannot be distinguished by request latency |
| Single-use | Token verified and consumed atomically in one DB transaction (row-locked) before session creation; concurrent requests replaying the same token cannot both succeed |
| Short expiry | 15 minutes by default; administrator-configurable |
| Rate limiting | Per-IP sliding window: 5 sends / 10 min, 10 verify attempts / 5 min |
| Account enumeration | Send endpoint returns identical response for matched and unmatched emails |
| CSRF | OJS built-in CSRF token enforced unconditionally on every mutating endpoint, including requests from an already-logged-in session (prevents login-CSRF) |
| Core changes | None — the plugin is entirely hook-based |

---

## TOTP alternative sign-in

Starting in 1.3.0, a signed-in user can enable authenticator-app (TOTP, RFC 6238) sign-in on their own account at `magicLogin/totpSetup` (also linked from their profile page). Once enabled, the sign-in page's "Email me a sign-in link" flow gains a sibling option, "Sign in with an authenticator code instead" (`magicLogin/totp`), where the user enters their username/email plus the current 6-digit code. **This is an alternative, not a combined second factor** — a user can sign in with either method; TOTP is never required in addition to the magic link. Combining them into mandatory 2FA was considered and rejected: this plugin's whole premise is reducing login friction, and silently turning every TOTP-enrolled account into "must always also enter a code" would be a bigger behavioural change than "add an alternative method," which is what was asked for.

Implementation notes and judgement calls:

- **No TOTP library existed anywhere in this installation's vendor tree** (checked `lib/pkp/lib/vendor` and both `composer.lock` files) — RFC 6238 was implemented directly on top of PHP's built-in `hash_hmac('sha1', ...)`, in `classes/TotpService.php`. Verified against the published RFC 4226 Appendix D test vectors (see `tests/totp-format.php`).
- **A real QR code is rendered client-side**, via a vendored copy of `davidshimjs/qrcodejs` (`js/qrcode.js`, MIT-licensed, no dependencies) — hand-rolling QR encoding ourselves (module matrix layout + Reed-Solomon error correction) was ruled out as significant, error-prone complexity, so this uses a small, well-established existing library instead. The setup page still also shows a tappable `otpauth://` URI (opens directly in an authenticator app when visited on the same device) and the raw base32 secret for manual entry, as a fallback for JS-disabled browsers or apps that prefer manual entry.
- **Secrets are encrypted at rest** using `classes/SecretCipher.php`, ported from the sibling PaystackOJS plugin's at-rest encryption pattern (libsodium secretbox, falling back to AES-256-GCM — both built into PHP). The key is derived from `config.inc.php`'s existing `[security] api_key_secret` / `salt`, never stored alongside the ciphertext.
- **Setup requires confirmation**: a newly generated secret is "pending" until the user proves possession by entering one valid code; it expires after 10 minutes if never confirmed.
- **Login-code replay is blocked**: the time-step a code matched is persisted per-account, and a code resolving to an already-consumed (or earlier) step is rejected — without this, a code would stay valid for reuse across its whole ±30s tolerance window.
- **Disabling TOTP requires re-entering the account password** — an active session alone is not sufficient authority to turn off a security feature.
- **Rate limiting**: verify attempts on `magicLogin/totpLogin` are throttled both per-IP (10/5 min) and per-account (8/15 min, independent of IP) — a 6-digit code has far less entropy than the magic-link token and needs brute-force resistance from both angles, reusing this plugin's existing sliding-window rate-limit pattern.

---

## Email template

Editable under **Settings › Emails › Magic sign-in link** (key `MAGIC_LOGIN_LINK`).

| Variable | Value |
|----------|-------|
| `{$recipientName}` | User's full name |
| `{$contextName}` | Journal name |
| `{$magicUrl}` | The one-time sign-in URL |
| `{$expiryMinutes}` | Link validity in minutes |

---

## Theming

The plugin ships generic templates that work with any OJS theme. To apply your own design, place overrides in your theme directory:

```
plugins/themes/<yourtheme>/
  templates/
    plugins/
      generic/
        magicLogin/
          templates/
            request.tpl   # email entry form
            confirm.tpl   # one-click sign-in confirmation
```

Available Smarty variables: `$sendUrl`, `$loginUrl`, `$token`, `$neutralMessage`, `$error`.

---

## Roadmap

| Version | Status | Description |
|---------|--------|-------------|
| 1.1.0 | Released | One-time email links with rate limiting and CSRF protection |
| 1.2.1 | Released | Automatic, theme-agnostic injection of the sign-in-link button into the login form (no theme edits required); plugin pages ship as a plain single-column default |
| 1.3.0 | Released | TOTP authenticator-app sign-in as a second alternative method |
| 2.0.0 | Released | Passkey / WebAuthn sign-in as a third passwordless method |

### Passkeys (WebAuthn) — implementation notes

Full W3C WebAuthn Level 2 registration ("attestation") and authentication
("assertion") ceremonies, hand-implemented on top of PHP's built-in
`openssl_*` functions — same "no library exists in this install's vendor
tree" situation as `classes/TotpService.php`'s RFC 6238 implementation, but
this sits directly in front of a signature check, so the scope and testing
posture are documented explicitly here rather than just in code comments:

- **What's implemented**: a minimal CBOR decoder (`classes/webauthn/Cbor.php`,
  only the subset WebAuthn structures use), COSE key → PEM conversion for
  **ES256** (EC P-256 — every platform authenticator: Touch ID, Windows
  Hello, Android biometric — and most security keys) and **RS256** (the
  remaining security keys that only offer RSA), and the full
  registration/authentication ceremony verification (challenge, origin, RP
  ID hash, user-present flag, signature) in `classes/webauthn/WebAuthnCeremony.php`.
  A user can register multiple passkeys (own table,
  `magic_login_webauthn_credentials`, unlike TOTP's single `user_settings`
  secret). Anti-clone signing-counter check (spec §6.1.1), with the
  documented allowance that authenticators reporting a counter of 0 forever
  (most platform authenticators) don't trigger it.
- **What's deliberately NOT implemented**: attestation statement signature
  verification / trust-chain checking (would require bundling X.509 parsing
  and a FIDO Metadata Service client — no bearing on the actual login
  security guarantee, which rests entirely on the *assertion* signature at
  sign-in time, not on verifying the authenticator's manufacturer identity
  at registration time). Extensions (none are requested).
- **Testing posture**: `tests/webauthn-format.php` (18 checks) proves the
  CBOR/COSE/PEM conversion against **real openssl-generated EC and RSA
  keypairs and real signatures** — not a copied "known-vector" fixture.
  `tests/webauthn-ceremony.php` (10 checks) builds real
  `authenticatorData`/`attestationObject`/`clientDataJSON` byte structures
  exactly as a browser+authenticator would and runs them through the actual
  registration/assertion verification code, checking both the success path
  and that tampering with the challenge, origin, RP ID, signature, or
  signed bytes is rejected. What this test suite **cannot** cover — and
  what genuinely needs a human with a real device — is an actual browser
  `navigator.credentials.create()`/`.get()` ceremony completing against a
  real Touch ID / Windows Hello / security key; that was verified only up
  to the point where the browser hands off to the platform's native
  authenticator prompt (confirmed: options endpoints return correct,
  session-backed, real challenges; CSRF/rate-limiting/session-storage wiring
  confirmed live; templates render correctly logged-in and logged-out).

The session-establishment layer (`classes/SessionService.php`) was already
factored to accept a second caller before this release, so wiring passkey
login into it required no structural changes.

---

## Contributing

Pull requests are welcome. Please open an issue first for anything beyond a small bug fix.

---

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE) for the full text.
