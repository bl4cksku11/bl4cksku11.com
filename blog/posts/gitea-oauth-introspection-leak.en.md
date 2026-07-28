# CVE-2026-58425: OAuth token introspection in Gitea leaks metadata across clients

**Published:** 2026-07-27 **Severity:** 4.3 Medium **Status:** Fixed in Gitea 1.27.0 (PR #38042) **CWE:** CWE-863 (Incorrect Authorization)

---

Gitea's OAuth 2.0 token introspection endpoint (`/login/oauth/introspect`) authenticated the calling client but never checked that the calling client actually owns the token being introspected. Any registered user who could create an OAuth application could hand the endpoint a token issued to a completely different client and get back that token's status, scope, subject, and the username it belongs to. That is a violation of RFC 7662 section 4. It turns introspection into a cross-tenant metadata oracle. Assigned CVE-2026-58425, rated Medium, fixed in Gitea 1.27.0.

---

## Background

RFC 7662 defines OAuth 2.0 token introspection. A resource server holds an opaque token and asks the authorization server "is this token still good, and what does it cover". The spec is explicit that the answer is sensitive. Section 4 says the authorization server SHOULD limit the information it discloses about each token to the resources authorized to receive it, and that an introspection response for a token that does not belong to the caller should not leak that token's details.

Gitea implements this endpoint. A client authenticates with HTTP Basic using its own client id and secret, puts a token in the request body, and gets a JSON document back describing the token. The bug is that the authentication step and the authorization step were not connected.

## The bug

Here is the handler as it shipped in 1.26.1, in `routers/web/auth/oauth2_provider.go`:

```go
func IntrospectOAuth(ctx *context.Context) {
	clientIDValid := false
	authHeader := ctx.Req.Header.Get("Authorization")
	if parsed, ok := httpauth.ParseAuthorizationHeader(authHeader); ok && parsed.BasicAuth != nil {
		clientID, clientSecret := parsed.BasicAuth.Username, parsed.BasicAuth.Password
		app, err := auth.GetOAuth2ApplicationByClientID(ctx, clientID)
		...
		clientIDValid = err == nil && app.ValidateClientSecret([]byte(clientSecret))
	}
	if !clientIDValid {
		ctx.Resp.Header().Set("WWW-Authenticate", `Basic realm="Gitea OAuth2"`)
		ctx.PlainText(http.StatusUnauthorized, "no valid authorization")
		return
	}

	var response struct {
		Active   bool   `json:"active"`
		Scope    string `json:"scope,omitempty"`
		Username string `json:"username,omitempty"`
		jwt.RegisteredClaims
	}

	form := web.GetForm(ctx).(*forms.IntrospectTokenForm)
	token, err := oauth2_provider.ParseToken(form.Token, oauth2_provider.DefaultSigningKey)
	if err == nil {
		grant, err := auth.GetOAuth2GrantByID(ctx, token.GrantID)
		if err == nil && grant != nil {
			app, err := auth.GetOAuth2ApplicationByID(ctx, grant.ApplicationID)
			if err == nil && app != nil {
				response.Active = true
				response.Scope = grant.Scope
				response.RegisteredClaims = oauth2_provider.NewJwtRegisteredClaimsFromUser(app.ClientID, grant.UserID, nil)
			}
			if user, err := user_model.GetUserByID(ctx, grant.UserID); err == nil {
				response.Username = user.Name
			}
		}
	}

	ctx.JSON(http.StatusOK, response)
}
```

Read it top to bottom. The first block validates the caller's client secret and, on success, binds a local variable `app` to the calling client. Good so far. Then the handler parses the token from the body, loads the grant behind that token, and reassigns `app` to `auth.GetOAuth2ApplicationByID(ctx, grant.ApplicationID)`. That inner `app` is the token's issuing client, not the caller. From that point on the response is built entirely from the token's own grant and the token's own application. The identity of the caller, which was verified a few lines up, is never compared to `grant.ApplicationID`.

The consequence: the only real requirement to read a token's metadata is that the token's signature parses under Gitea's signing key. Whether the caller is the audience is irrelevant. The variable shadowing is what makes this easy to miss in review: the same name `app` means two different things in the same function.

## Reproduction

Ran this against `gitea/gitea:1.26.1` with two users and two OAuth applications owned by different users.

```
Client A: id=5dda747d-7fdd-4694-85ff-ce4f893ce51e   owner=admin
Client B: id=588f778f-4a41-4914-ae01-85d776c369db   owner=victim
```

`admin` runs a normal authorization code flow against Client A and ends up with an access token. Now `victim`, using Client B's own credentials, introspects Client A's token:

```
$ curl -s -u "$B_ID:$B_SEC" -X POST http://localhost:3001/login/oauth/introspect \
       --data-urlencode "token=$CLIENT_A_ACCESS_TOKEN"
{
    "active": true,
    "username": "admin",
    "iss": "http://localhost:3001",
    "sub": "1",
    "aud": [
        "5dda747d-7fdd-4694-85ff-ce4f893ce51e"
    ]
}
```

The response is the punchline. The `aud` claim is Client A's id, so the server is literally telling Client B "this token belongs to Client A", and then hands over the metadata anyway. Client B's own id is different. There is no error, no empty result, no `active:false`. Just the data.

## Why it matters

Gitea lets any user create an OAuth application from the settings UI, so the attacker does not need special privileges. They register their own client, authenticate as themselves, and then introspect tokens that belong to other tenants. What they learn per token:

- Whether the token is currently active. A validity oracle that works across client boundaries and does not consume or advance the grant, so probing does not look like token use in any audit trail.
- The token's scope.
- The username the token was issued to.
- The standard registered claims including `iss`, `sub`, and `aud`.

The practical scenarios are validation of a stolen token before using it for something noisier, cross-tenant enumeration of which user and scope each token maps to, and reconnaissance ahead of chaining another bug. It is not remote code execution, and the token bytes themselves are not disclosed, which is why this lands at Medium rather than High. An authorization endpoint that ignores the caller's identity is exactly the kind of primitive that shows up as a link in a longer chain.

CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` = 4.3 Medium. The endpoint applied the wrong predicate, "is the caller authenticated", instead of the correct one, "is the caller the token's audience".

## The interesting part: the fix already existed next door

The same file had been hardened weeks earlier. PR #37704 bound token exchanges to the original requesting client and added exactly the check that introspection was missing, in two sibling handlers:

```go
// handleRefreshToken
if grant.ApplicationID != app.ID {
	handleAccessTokenError(ctx, oauth2_provider.AccessTokenError{
		ErrorCode:        oauth2_provider.AccessTokenErrorCodeInvalidGrant,
		ErrorDescription: "refresh token belongs to a different client",
	})
	return
}
```

`handleAuthorizationCode` got the equivalent guard. Introspection consumes a token bound to a grant whose application may differ from the caller, the exact same problem space, but it was not part of that pass. This is the pattern worth internalizing: when a maintainer fixes "resource belongs to a different client" in one handler, the other handlers in the same file that touch the same grant-to-application relationship are the first place to look for the variant. That is how I found it.

## The fix

The remediation is a single guard that reintroduces the caller check before trusting the token's grant:

```go
grant, err := auth.GetOAuth2GrantByID(ctx, token.GrantID)
if err == nil && grant != nil {
	if grant.ApplicationID != app.ID {
		// do not reveal token metadata for tokens not issued to this client
		ctx.JSON(http.StatusOK, response) // response is zero valued, active=false
		return
	}
	...
}
```

Now a token that belongs to a different client returns `active:false` with no metadata, which is the RFC 7662 behavior. Landed in Gitea 1.27.0 via PR #38042.

## Takeaways

Two things carry over from this one.

First, variable shadowing around an authorization decision is a smell. When the same name refers to the caller in one line and to the resource owner three lines down, the comparison between the two tends to go missing.

Second, a security fix that lands in one handler is a map, not a fence. The sibling handlers that share the same data relationship are where the next bug lives, and reading a fix PR as a variant-hunting lead is one of the highest-yield things you can do against a mature codebase.

## Disclosure

Reported privately to the Gitea security team. Confirmed and accepted by the maintainers, fix tracked as PR #38042. CVE-2026-58425 assigned. Fixed in the Gitea 1.27.0 release. Public disclosure after that release shipped.

Fast and clean triage from the Gitea team.

## Links

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-58425
- Fix PR: https://github.com/go-gitea/gitea/pull/38042
- Related hardening: https://github.com/go-gitea/gitea/pull/37704
- Gitea 1.27.0 release: https://github.com/go-gitea/gitea/releases/tag/v1.27.0
- RFC 7662 section 4: https://datatracker.ietf.org/doc/html/rfc7662#section-4
- CWE-863: https://cwe.mitre.org/data/definitions/863.html
