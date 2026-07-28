# CVE-2026-54320: Cross-tenant org takeover in Daytona via invitation acceptance with an unverified email

**Published:** 2026-07-28 **Reported:** 2026-05-30 **Severity:** 8.9 High (CVSS 3.1) / 9.4 Critical (standard onboarding case, AC:L) **Status:** Fixed in Daytona 0.184.0 **CWEs:** CWE-287 (Improper Authentication) + CWE-863 (Incorrect Authorization)

---

Daytona's `acceptInvitation` decided whether a caller may join an organization by string-comparing the invitation's target email against the email taken from the caller's OIDC token, and never checked whether that email was verified. Register the email address of a pending organization invitation, leave it unverified, accept the invitation, and Daytona binds the new account to the target organization with the invited role, up to OWNER. Confirmed live on the hosted `app.daytona.io` platform. Assigned CVE-2026-54320, fixed in Daytona 0.184.0.

---

## The bug

`apps/api/src/organization/controllers/organization.controller.ts:129-132`:

```typescript
const invitation = await this.organizationInvitationService.findOneOrFail(invitationId)
if (!EmailUtils.areEqual(invitation.email, authContext.email)) {
  throw new ForbiddenException('User email does not match invitation email')
}
```

That is the entire gate. `authContext.email` is the raw `email` claim from the JWT (set in `apps/api/src/auth/jwt.strategy.ts:64`, `let email = payload.email`). The token's `email_verified` claim is recorded onto the user (`jwt.strategy.ts:79-83`) but never consulted on the accept path. `EmailUtils.normalize` is `toLowerCase().trim()`, so the check is a plain case-insensitive string match against a claim the caller controls.

The `User.email` column has no unique constraint (`apps/api/src/user/user.entity.ts:27-30`) and the user primary key is the OIDC `sub`, so two distinct accounts can carry the same `email` value. If an unverified account gets a valid JWT with an attacker-controlled `email` claim, the accept path treats it as the invited identity.

Accepting then grants membership with the invitation's role unconditionally. `organization-invitation.service.ts:208-225` emits `INVITATION_ACCEPTED`, handled at `organization-user.service.ts:194-207`, which calls `createWithEntityManager(..., role, assignedRoles)` with `role` straight from the invitation. An invitation can carry `role: owner`.

## The sibling endpoint proves the pattern

The same controller enforces the exact check that is missing here. `createOrganization` (a few lines below) refuses an unverified email:

`organization.controller.ts:203-206`:

```typescript
const user = await this.userService.findOne(authContext.userId)
if (!user.emailVerified && !this.configService.get('skipUserEmailVerification')) {
  throw new ForbiddenException('Please verify your email address')
}
```

Creating your own empty organization requires `emailVerified`. Joining someone else's existing organization (a cross-tenant access grant, up to OWNER) does not. The check at lines 203-206 is exactly the guard missing at lines 129-132.

## Reproduction on the hosted platform

Two email addresses I own (`bl4cksku111@pm.me`, `jrivas@zerotrustoffsec.com`) and one organization I created. No other tenant's data was touched.

As `bl4cksku111@pm.me` (verified) I created "Test Org" and invited `jrivas@zerotrustoffsec.com` as Owner. The invitation sits Pending.

In a separate browser I opened Auth0 Universal Login and signed up `jrivas@zerotrustoffsec.com` with a password. I never opened the verification email. Auth0 logged me straight into `app.daytona.io/dashboard/onboarding` as `jrivas@zerotrustoffsec.com`, no verification.

At `app.daytona.io/dashboard/user/invitations` the page shows the banner "Verification Required, Please verify your email address to access all features" and, on the same screen, the Test Org invitation with an accept control. Accepted it. Daytona knows the email is unverified (it says so) and still lets this account join another organization.

The org switcher now lists "Test Org" next to "Personal". The unverified `jrivas@zerotrustoffsec.com` account is an Owner of an organization it was never legitimately part of.

Both hosted preconditions hold: self-signup is open on the `daytonaio.us.auth0.com` tenant, and Auth0 issues a usable app session before the email is verified. Register the email address on a pending invitation (the normal state for an invitee who has not signed up yet) and you join the target organization with the invited role.

## Local reproduction against the released image

Deterministic transcript against `daytonaio/daytona-api@sha256:500a1c8...` (v0.183.0, the version serving app.daytona.io), with `SKIP_USER_EMAIL_VERIFICATION=false` (production-like), using a local OIDC issuer that mints an unverified-email token directly:

```
## attacker JWT payload
{ "iss":"http://issuer:5556", "aud":"daytona", "sub":"attacker-evil",
  "email":"victim2@corp.test", "email_verified": false, "name":"Attacker" }

## STEP 1  owner@poc.test (email_verified=true) creates a non-personal org
ORG_ID=bab5858e-eb97-4955-b26b-6d05aefd5a5b

## STEP 2  owner invites victim2@corp.test with role=owner (pending invitation)
INVITATION_ID=f00ff34e-b284-434c-a10a-a163de146e58  target_email=victim2@corp.test

## CONTROL  same attacker token tries to create its OWN org
POST /api/organizations                                          -> HTTP 403
body: {"statusCode":403,"error":"Forbidden","message":"Please verify your email address"}

## ATTACK  same attacker token accepts the victim's pending OWNER invitation
POST /api/organizations/invitations/f00ff34e-.../accept          -> HTTP 201
body: {... "organizationId":"bab5858e-...","status":"accepted","role":"owner" ...}

## PROOF  attacker enumerates the victim org's members (cross-tenant)
GET /api/organizations/bab5858e-.../users                        -> HTTP 200
  member: owner@poc.test       role= owner
  member: victim2@corp.test    role= owner   <-- this is the attacker (sub=attacker-evil)
```

The same token that the platform refuses for org creation (403, email not verified) is accepted for joining another tenant's organization as OWNER (201). Same token. Same email. Two adjacent endpoints. One checked, one did not.

## Impact

An actor registers the email address of a pending organization invitation, leaves it unverified, and accepts the invitation, becoming a member of the target organization with the invited role. The boundary crossed is the organization (tenant) boundary, which is the platform's primary isolation guarantee.

With an OWNER invitation the actor owns the victim organization:

- Reads the org's sandbox environment variables (returned in `SandboxDto.env`).
- Enumerates and manages members.
- Creates or destroys sandboxes in the org.

The only precondition is a pending invitation to an email the actor can register, which is the normal state for any invitee who has not yet signed up. No prior access to the target organization is required, on the hosted platform or on self-hosted Daytona.

**CVSS 3.1:** 8.9 High, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L`. AC:H reflects needing a pending invitation to an email the attacker can register. Under the standard onboarding case, where the invitee has not yet created an account, that precondition is the norm rather than the exception, giving AC:L and CVSS 9.4 Critical.

## The fix

Gate the accept (and decline) on a verified email, mirroring `createOrganization`. In `apps/api/src/organization/controllers/organization.controller.ts` `acceptInvitation`, after loading the invitation:

```typescript
const user = await this.userService.findOne(authContext.userId)
if (!user.emailVerified && !this.configService.get('skipUserEmailVerification')) {
  throw new ForbiddenException('Please verify your email address')
}
if (!EmailUtils.areEqual(invitation.email, authContext.email)) {
  throw new ForbiddenException('User email does not match invitation email')
}
```

The same guard belongs on `declineInvitation` (lines 161-175), which otherwise lets an unverified email-holder destroy another tenant's pending invitations.

A better structural fix is to enforce `emailVerified` centrally for any email-to-identity binding, so the next email-matched flow does not reintroduce the gap.

Fixed in Daytona 0.184.0.

## Disclosure

Reported to `security@daytona.io`. Fast triage, fix in 0.184.0, GHSA-m6hx-cffh-3f3h published 2026-06-05 with CVE-2026-54320 assigned.

Thanks to the Daytona security team (Ante) for the fast turnaround.

## Links

- Advisory: https://github.com/daytonaio/daytona/security/advisories/GHSA-m6hx-cffh-3f3h
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-54320
- Daytona 0.184.0 release: https://github.com/daytonaio/daytona/releases/tag/v0.184.0
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- CWE-863: https://cwe.mitre.org/data/definitions/863.html
