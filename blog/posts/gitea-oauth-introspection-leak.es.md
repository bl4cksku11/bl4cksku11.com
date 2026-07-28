# CVE-2026-58425: La introspección de tokens OAuth en Gitea filtra metadata entre clientes

**Publicado:** 2026-07-27 **Severidad:** 4.3 Media **Estado:** Corregido en Gitea 1.27.0 (PR #38042) **CWE:** CWE-863 (Incorrect Authorization)

---

El endpoint de token introspection de OAuth 2.0 de Gitea (`/login/oauth/introspect`) autenticaba al client que llamaba pero nunca chequeaba que ese client realmente fuera el dueño del token que se estaba introspectando. Cualquier usuario registrado que pudiera crear una aplicación OAuth podía pasarle al endpoint un token emitido para un client completamente distinto y recibir de vuelta el status, el scope, el subject y el username al que pertenece ese token. Es una violación de RFC 7662 sección 4. Convierte la introspection en un oráculo de metadata cross-tenant. Asignado como CVE-2026-58425, rated Medium, corregido en Gitea 1.27.0.

---

## Contexto

RFC 7662 define el token introspection de OAuth 2.0. Un resource server tiene un token opaco y le pregunta al authorization server "¿este token sigue siendo válido y qué cubre?". El spec es explícito en que la respuesta es sensible. La sección 4 dice que el authorization server SHOULD limitar la información que expone sobre cada token a los recursos autorizados a recibirla, y que una respuesta de introspection para un token que no pertenece al caller no debería filtrar los detalles de ese token.

Gitea implementa este endpoint. Un client se autentica con HTTP Basic usando su propio client id y secret, mete un token en el body del request, y recibe de vuelta un documento JSON describiendo el token. El bug es que el paso de autenticación y el paso de autorización no estaban conectados.

## El bug

Este es el handler tal como shipeó en 1.26.1, en `routers/web/auth/oauth2_provider.go`:

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

Leelo de arriba a abajo. El primer bloque valida el client secret del caller y, cuando pasa, bindea una variable local `app` al calling client. Bien hasta ahí. Después el handler parsea el token del body, carga el grant detrás de ese token, y reasigna `app` a `auth.GetOAuth2ApplicationByID(ctx, grant.ApplicationID)`. Ese `app` interno es el client emisor del token, no el caller. Desde ese punto en adelante la respuesta se construye enteramente a partir del grant propio del token y de la aplicación propia del token. La identidad del caller, que fue verificada unas líneas más arriba, nunca se compara con `grant.ApplicationID`.

La consecuencia: el único requisito real para leer la metadata de un token es que la firma del token parsee bajo la signing key de Gitea. Si el caller es el audience o no, es irrelevante. El shadowing de variables es lo que hace que esto sea fácil de perder en review: el mismo nombre `app` significa dos cosas distintas en la misma función.

## Reproducción

Lo corrí contra `gitea/gitea:1.26.1` con dos usuarios y dos aplicaciones OAuth cuyos owners son usuarios distintos.

```
Client A: id=5dda747d-7fdd-4694-85ff-ce4f893ce51e   owner=admin
Client B: id=588f778f-4a41-4914-ae01-85d776c369db   owner=victim
```

`admin` corre un flujo normal de authorization code contra Client A y termina con un access token. Ahora `victim`, usando las credenciales del propio Client B, introspecta el token de Client A:

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

La respuesta es el punchline. El claim `aud` es el id del Client A, así que el servidor literalmente le está diciendo al Client B "este token pertenece al Client A", y después le entrega la metadata igual. El id propio del Client B es distinto. No hay error, no hay resultado vacío, no hay `active:false`. Solo los datos.

## Por qué importa

Gitea deja a cualquier usuario crear una aplicación OAuth desde la UI de settings, así que el atacante no necesita privilegios especiales. Registra su propio client, se autentica como él mismo, y después introspecta tokens que pertenecen a otros tenants. Qué aprende por token:

- Si el token está activo. Un oráculo de validez que funciona cruzando los límites del client y que no consume ni avanza el grant, así que probar no se ve como uso del token en ningún audit trail.
- El scope del token.
- El username al que se emitió el token.
- Los registered claims estándar incluyendo `iss`, `sub` y `aud`.

Los escenarios prácticos son la validación de un token robado antes de usarlo para algo más ruidoso, la enumeración cross-tenant de qué usuario y qué scope mapea cada token, y el reconnaissance previo a chainear otro bug. No es RCE, y los bytes del token no se exponen, por eso queda en Medium en vez de High. Pero un endpoint de autorización que ignora la identidad del caller es exactamente el tipo de primitiva que aparece como eslabón en una cadena más larga.

CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` = 4.3 Media. El endpoint aplicó el predicado equivocado, "¿está autenticado el caller?", en vez del correcto, "¿es el caller el audience del token?".

## Lo interesante: el fix ya existía al lado

El mismo archivo había sido endurecido unas semanas antes. El PR #37704 bindeó los token exchanges al client requesting original y agregó exactamente el check que le faltaba a la introspection, en dos handlers hermanos:

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

`handleAuthorizationCode` recibió el guard equivalente. La introspection consume un token bindeado a un grant cuya application puede diferir del caller, exactamente el mismo espacio de problema, pero no fue parte de esa pasada. Este es el patrón que vale la pena internalizar: cuando un maintainer arregla "el recurso pertenece a otro client" en un handler, los otros handlers del mismo archivo que tocan la misma relación grant-a-application son el primer lugar donde buscar la variante. Así fue como lo encontré.

## El parche

La remediación es un solo guard que reintroduce el check del caller antes de confiar en el grant del token:

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

Ahora un token que pertenece a otro client devuelve `active:false` sin metadata, que es el comportamiento RFC 7662. Aterrizó en Gitea 1.27.0 vía PR #38042.

## Takeaways

Dos cosas me llevo de esta.

Primera, el shadowing de variables alrededor de una decisión de autorización es un smell. Cuando el mismo nombre se refiere al caller en una línea y al owner del recurso tres líneas más abajo, la comparación entre los dos tiende a desaparecer.

Segunda, un fix de seguridad que aterriza en un handler es un mapa, no una cerca. Los handlers hermanos que comparten la misma relación de datos son donde vive el próximo bug, y leer un PR de fix como una lead para variant hunting es una de las cosas de mayor yield que se puede hacer contra un codebase maduro.

## Divulgación

Reportado privadamente al equipo de seguridad de Gitea. Confirmado y aceptado por los maintainers, fix trackeado como PR #38042. CVE-2026-58425 asignado. Corregido en el release de Gitea 1.27.0. Divulgación pública después de que ese release shipeó.

Triage rápido y limpio del equipo de Gitea.

## Links

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-58425
- Fix PR: https://github.com/go-gitea/gitea/pull/38042
- Hardening relacionado: https://github.com/go-gitea/gitea/pull/37704
- Release de Gitea 1.27.0: https://github.com/go-gitea/gitea/releases/tag/v1.27.0
- RFC 7662 sección 4: https://datatracker.ietf.org/doc/html/rfc7662#section-4
- CWE-863: https://cwe.mitre.org/data/definitions/863.html
