# CVE-2026-54320: Takeover cross-tenant de organizaciones en Daytona vía aceptación de invitación con email sin verificar

**Publicado:** 2026-07-28 **Reportado:** 2026-05-30 **Severidad:** 8.9 Alta (CVSS 3.1) / 9.4 Crítica (caso de onboarding estándar, AC:L) **Estado:** Corregido en Daytona 0.184.0 **CWEs:** CWE-287 (Improper Authentication) + CWE-863 (Incorrect Authorization)

---

El `acceptInvitation` de Daytona decidía si un caller podía unirse a una organización comparando por string el email target de la invitación contra el email tomado del OIDC token del caller, y nunca chequeaba si ese email estaba verificado. Registrás la dirección de email de una invitación pendiente, la dejás sin verificar, aceptás la invitación, y Daytona bindea la nueva cuenta a la organización target con el rol invitado, hasta OWNER. Confirmado en vivo contra la plataforma hosted `app.daytona.io`. Asignado CVE-2026-54320, corregido en Daytona 0.184.0.

---

## El bug

`apps/api/src/organization/controllers/organization.controller.ts:129-132`:

```typescript
const invitation = await this.organizationInvitationService.findOneOrFail(invitationId)
if (!EmailUtils.areEqual(invitation.email, authContext.email)) {
  throw new ForbiddenException('User email does not match invitation email')
}
```

Eso es toda la gate. `authContext.email` es el claim `email` crudo del JWT (seteado en `apps/api/src/auth/jwt.strategy.ts:64`, `let email = payload.email`). El claim `email_verified` del token se registra en el user (`jwt.strategy.ts:79-83`) pero nunca se consulta en el path de accept. `EmailUtils.normalize` es `toLowerCase().trim()`, así que el check es un plain case-insensitive string match contra un claim que el caller controla.

La columna `User.email` no tiene unique constraint (`apps/api/src/user/user.entity.ts:27-30`) y la primary key del user es el `sub` de OIDC, así que dos cuentas distintas pueden tener el mismo valor de `email`. Si una cuenta sin verificar recibe un JWT válido con un claim `email` controlado por el atacante, el path de accept la trata como la identidad invitada.

Aceptar entonces otorga membership con el rol de la invitación sin condiciones. `organization-invitation.service.ts:208-225` emite `INVITATION_ACCEPTED`, manejado en `organization-user.service.ts:194-207`, que llama `createWithEntityManager(..., role, assignedRoles)` con el `role` directo de la invitación. Una invitación puede llevar `role: owner`.

## El endpoint hermano prueba el patrón

El mismo controller enforza el check exacto que falta acá. `createOrganization` (unas líneas más abajo) rechaza un email sin verificar:

`organization.controller.ts:203-206`:

```typescript
const user = await this.userService.findOne(authContext.userId)
if (!user.emailVerified && !this.configService.get('skipUserEmailVerification')) {
  throw new ForbiddenException('Please verify your email address')
}
```

Crear tu propia organización vacía requiere `emailVerified`. Unirse a la organización existente de otro (un acceso cross-tenant, hasta OWNER) no. El check en líneas 203-206 es exactamente el guard que falta en líneas 129-132.

## Reproducción contra la plataforma hosted

Dos direcciones de email que poseo (`bl4cksku111@pm.me`, `jrivas@zerotrustoffsec.com`) y una organización que creé. Ningún dato de otro tenant fue tocado.

Como `bl4cksku111@pm.me` (verificado) creé "Test Org" e invité a `jrivas@zerotrustoffsec.com` como Owner. La invitación quedó Pending.

En un browser separado abrí Auth0 Universal Login e hice signup de `jrivas@zerotrustoffsec.com` con password. Nunca abrí el email de verificación. Auth0 me logueó directo al dashboard en `app.daytona.io/dashboard/onboarding` como `jrivas@zerotrustoffsec.com`, sin verificación.

En `app.daytona.io/dashboard/user/invitations` la página muestra el banner "Verification Required, Please verify your email address to access all features" y, en la misma pantalla, la invitación de Test Org con un control de accept. La acepté. Daytona sabe que el email está sin verificar (lo dice literalmente) y aún así deja que esta cuenta se una a otra organización.

El org switcher ahora lista "Test Org" al lado de "Personal". La cuenta sin verificar `jrivas@zerotrustoffsec.com` es Owner de una organización de la que nunca legítimamente formó parte.

Ambas preconditions hosted se cumplen: el self-signup está abierto en el tenant `daytonaio.us.auth0.com`, y Auth0 emite una sesión de app usable antes de que el email esté verificado. Registrás el email de una invitación pendiente (el estado normal para un invitee que todavía no hizo signup) y te unís a la organización target con el rol invitado.

## Reproducción local contra la imagen released

Transcript determinístico contra `daytonaio/daytona-api@sha256:500a1c8...` (v0.183.0, la versión sirviendo app.daytona.io), con `SKIP_USER_EMAIL_VERIFICATION=false` (production-like), usando un issuer OIDC local que emite un token con email sin verificar directamente:

```
## payload del JWT del atacante
{ "iss":"http://issuer:5556", "aud":"daytona", "sub":"attacker-evil",
  "email":"victim2@corp.test", "email_verified": false, "name":"Attacker" }

## STEP 1  owner@poc.test (email_verified=true) crea una org no-personal
ORG_ID=bab5858e-eb97-4955-b26b-6d05aefd5a5b

## STEP 2  owner invita a victim2@corp.test con role=owner (pending invitation)
INVITATION_ID=f00ff34e-b284-434c-a10a-a163de146e58  target_email=victim2@corp.test

## CONTROL  el mismo token del atacante intenta crear SU propia org
POST /api/organizations                                          -> HTTP 403
body: {"statusCode":403,"error":"Forbidden","message":"Please verify your email address"}

## ATTACK  el mismo token del atacante acepta la invitación OWNER pendiente
POST /api/organizations/invitations/f00ff34e-.../accept          -> HTTP 201
body: {... "organizationId":"bab5858e-...","status":"accepted","role":"owner" ...}

## PROOF  el atacante enumera los members de la org víctima (cross-tenant)
GET /api/organizations/bab5858e-.../users                        -> HTTP 200
  member: owner@poc.test       role= owner
  member: victim2@corp.test    role= owner   <-- este es el atacante (sub=attacker-evil)
```

El mismo token que la plataforma rechaza para crear org (403, email no verificado) es aceptado para unirse a la organización de otro tenant como OWNER (201). Mismo token. Mismo email. Dos endpoints adyacentes. Uno chequea, el otro no.

## Impacto

Un actor registra la dirección de email de una invitación pendiente a una organización, la deja sin verificar, y acepta la invitación, volviéndose member de la organización target con el rol invitado. El boundary cruzado es el boundary de organización (tenant), que es la garantía primaria de aislamiento de la plataforma.

Con una invitación OWNER el actor es dueño de la organización víctima:

- Lee las environment variables del sandbox de la org (retornadas en `SandboxDto.env`).
- Enumera y maneja members.
- Crea o destruye sandboxes en la org.

La única precondition es una invitación pendiente a un email que el actor pueda registrar, que es el estado normal para cualquier invitee que todavía no hizo signup. No hace falta acceso previo a la organización target, ni en la plataforma hosted ni en Daytona self-hosted.

**CVSS 3.1:** 8.9 Alta, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L`. El AC:H refleja necesitar una invitación pendiente a un email que el atacante pueda registrar. Bajo el caso de onboarding estándar, donde el invitee todavía no creó cuenta, esa precondition es la norma en vez de la excepción, dando AC:L y CVSS 9.4 Crítica.

## El fix

Gate el accept (y el decline) sobre email verificado, mirroring `createOrganization`. En `apps/api/src/organization/controllers/organization.controller.ts` `acceptInvitation`, después de cargar la invitación:

```typescript
const user = await this.userService.findOne(authContext.userId)
if (!user.emailVerified && !this.configService.get('skipUserEmailVerification')) {
  throw new ForbiddenException('Please verify your email address')
}
if (!EmailUtils.areEqual(invitation.email, authContext.email)) {
  throw new ForbiddenException('User email does not match invitation email')
}
```

El mismo guard va en `declineInvitation` (líneas 161-175), que si no deja que un email-holder sin verificar destruya las invitaciones pending de otro tenant.

Un fix estructural mejor es enforzar `emailVerified` centralmente para cualquier binding email-a-identidad, así el próximo flujo email-matched no reintroduce el gap.

Corregido en Daytona 0.184.0.

## Divulgación

Reportado a `security@daytona.io`. Triage rápido, fix en 0.184.0, GHSA-m6hx-cffh-3f3h publicado el 2026-06-05 con CVE-2026-54320 asignado.

Gracias al equipo de seguridad de Daytona (Ante) por el turnaround rápido.

## Links

- Advisory: https://github.com/daytonaio/daytona/security/advisories/GHSA-m6hx-cffh-3f3h
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-54320
- Release de Daytona 0.184.0: https://github.com/daytonaio/daytona/releases/tag/v0.184.0
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- CWE-863: https://cwe.mitre.org/data/definitions/863.html
