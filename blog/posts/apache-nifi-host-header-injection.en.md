# CVE-2026-54665: Pre-auth host header injection in Apache NiFi

**Published:** 2026-06-20 **Reported:** 2026-05-15 **Severity:** 5.4 Medium (baseline) / 8.1 High (with OIDC) **Status:** Fixed in NiFi 2.10.0 **CWEs:** CWE-444 (Inconsistent Interpretation of HTTP Requests) + CWE-601 (Open Redirect)

---

A pre-authentication host header injection in Apache NiFi. Any unauthenticated client could send `X-Forwarded-Host` or `X-ProxyHost` and have that value reflected into the URIs that NiFi builds for OAuth2 redirect, SAML SP entity, CSRF cookie domain, and the public `/nifi-api/authentication/configuration` endpoint. Affected: 0.0.1 through 2.9.0. Fixed in 2.10.0.

The interesting part is not the bug itself, it is how it got there. A 2025 refactor (NIFI-14209) deleted the `HostHeaderHandler` that had been enforcing the documented `nifi.web.proxy.host` allowlist for a decade, and replaced it with a customizer that only validates **ports**. The allowlist kept appearing in docs and configs after the refactor, but at runtime nothing read the host portion anymore.

---

## The bug

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

The pattern is `^([^:]+):?([1-9][0-9]{2,4})?$`. It accepts any string with no colon in the host portion. `attacker.example.com`, `nifi-prod.example.com.evil-attacker.net`, `127.0.0.1`. All match. There is no allowlist check.

Compare the same file's `getPath()` a few lines down: it validates `X-ProxyContextPath`, `X-Forwarded-Context`, and `X-Forwarded-Prefix` against `nifi.web.proxy.context.path` and throws `IllegalArgumentException` when the value is not on the allowlist. The host inspection just forgot to do the same thing.

## The allowlist that doesn't validate hosts

`NiFiProperties.java:1603-1614` parses the `nifi.web.proxy.host` property into a list:

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

The only caller is `FrameworkServerConnectorFactory.getValidPorts()`, which extracts only the **port** from each entry to build the Jetty listener's accepted port set:

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

So an operator who reads the admin guide section on `nifi.web.proxy.host`, sets it to `nifi.example.com,nifi-internal.example.com`, and assumes NiFi will reject requests with other host values, is wrong. NiFi only used those entries to learn what **ports** were valid.

## PoC

Server: `apache-nifi-2.9.0-bin.zip` started with default `conf/nifi.properties` (only `nifi.web.https.port=18443` changed to free the default port). Single-user mode, HTTPS on `127.0.0.1:18443`.

Baseline:

```bash
$ curl -sk --resolve localhost:18443:127.0.0.1 -H 'Accept: application/json' \
    https://localhost:18443/nifi-api/authentication/configuration
{"authenticationConfiguration":{"externalLoginRequired":false,"loginSupported":true,
 "loginUri":"https://localhost:18443/nf/#/login",
 "logoutUri":"https://localhost:18443/nifi-api/access/logout/complete"}}
```

With `X-Forwarded-Host`:

```bash
$ curl -sk --resolve localhost:18443:127.0.0.1 -H 'Accept: application/json' \
    -H 'X-Forwarded-Host: attacker.example.com' \
    https://localhost:18443/nifi-api/authentication/configuration
{"authenticationConfiguration":{"externalLoginRequired":false,"loginSupported":true,
 "loginUri":"https://attacker.example.com:18443/nf/#/login",
 "logoutUri":"https://attacker.example.com:18443/nifi-api/access/logout/complete"}}
```

With `X-ProxyHost`:

```bash
$ curl -sk --resolve localhost:18443:127.0.0.1 -H 'Accept: application/json' \
    -H 'X-ProxyHost: evil.example.com' \
    https://localhost:18443/nifi-api/authentication/configuration
{"authenticationConfiguration":{"externalLoginRequired":false,"loginSupported":true,
 "loginUri":"https://evil.example.com:18443/nf/#/login",
 "logoutUri":"https://evil.example.com:18443/nifi-api/access/logout/complete"}}
```

Worth noting: the TLS layer Host header is correctly gated. A request with `Host: attacker.example.com` but matching SNI returns `Error 400 Invalid SNI` because Jetty's `SecureRequestCustomizer` enforces SNI-against-Host. That defense covers the TLS-layer Host header. It does not cover the two HTTP application-layer headers above, which are exactly the headers a reverse proxy in front of NiFi would forward from untrusted clients.

## Downstream consumers

`RequestUriBuilder.fromHttpServletRequest()` is called in 26 sites across the NiFi framework. The reflected host travels into all of them. The security-critical ones:

| Call site | What it builds |
|---|---|
| `StandardOAuth2AuthorizationRequestResolver.java:97` | OAuth2 `redirect_uri` sent to the OIDC IdP |
| `StandardRelyingPartyRegistrationResolver.java:114` | SAML SP entity and ACS URI in the AuthnRequest |
| `OidcAuthenticationSuccessHandler.java:102, 105` | Post-OIDC redirect target |
| `Saml2AuthenticationSuccessHandler.java:103, 106` | Post-SAML redirect target |
| `OidcLogoutSuccessHandler.java:213` | Post-OIDC-logout redirect target |
| `StandardCookieCsrfTokenRepository.java:71` | CSRF cookie URI, used to derive cookie domain |
| `AuthenticationResource.java:99` | Anonymous `/nifi-api/authentication/configuration` response |
| `FlowResource.java:398, 2621` | Content-viewer URIs |
| `ApplicationResource.java:173, 187, 329` | Request URIs used for cluster replication |

The verified impact is the anonymous `/authentication/configuration` reflection. The interesting one is the OAuth2 `redirect_uri`. For deployments with OIDC enabled, the `redirect_uri` sent to the IdP comes from the attacker-controllable host. Against an IdP that accepts unregistered redirect URIs, or one that does loose wildcard matching on registered URIs (which is more common than you would hope), the attacker controls where the authorization code is delivered. That is the difference between a 5.4 medium-impact reflection bug and an 8.1 high-impact account takeover primitive.

## How it got here: NIFI-14209

Commit `ae5a77b84f5c7e5e51e85e99f1d40079dbdee5f1`, landed 2025-02-05, titled "Restructured Host Header Validation". The commit message reads:

> Replaced HostHeaderHandler with HostPortValidatorCustomizer.
> Jetty SecureRequestCustomizer enforces host validation for SNI with Server Certificate DNS Subject Alternative Names.
> Added tests for TLS SNI with invalid host and port values.
> Refactored and streamlined RequestUriBuilder.fromHttpServletRequest().

The diff deleted `HostHeaderHandler.java`, 318 lines, the Jetty `Handler` that had been consuming the `nifi.web.proxy.host` list and rejecting requests with host values outside it. The replacement, `HostPortValidatorCustomizer.java`, is 85 lines and only validates ports.

The premise was that `SecureRequestCustomizer` covers host validation through TLS SNI. That premise is correct for the TLS-layer Host header. It does not generalize to the two application-layer headers (`X-Forwarded-Host`, `X-ProxyHost`) that `StandardRequestUriProvider.getHost()` reads next in line. The refactor moved the trust boundary without updating the readers on the other side.

## Affected versions

- Apache NiFi 0.0.1 through 2.9.0 (vulnerable, per the official advisory)
- Apache NiFi 2.10.0 (fixed)

The NIFI-14209 commit that introduced the regression landed in February 2025. Pre-2.2.0 versions retained the original `HostHeaderHandler` defense; the regression is from that point forward.

## The fix

NiFi 2.10.0 (Jira NIFI-15953, [PR #11268](https://github.com/apache/nifi/pull/11268)) adds back the allowlist validation, this time covering `X-ProxyHost` and `X-Forwarded-Host` in addition to the Host header. The fix matches what `getPath()` was already doing for the context-path headers. From the advisory text:

> Apache NiFi 2.10.0 implements validation for the X-ProxyHost and X-Forwarded-Host HTTP request headers based on the nifi.web.proxy.host property. Enabling header validation requires configuring the application with HTTPS. Reverse proxy servers in front of Apache NiFi are responsible for filtering input request headers and providing allowed values to the application.

For operators on 2.2.0 through 2.9.0 who cannot upgrade immediately, the mitigation is to strip `X-Forwarded-Host` and `X-ProxyHost` at the reverse proxy before they reach NiFi. The default `nifi.properties` does not warn about this; if you run NiFi behind anything that forwards these headers from untrusted clients, audit it.

## Disclosure

Reported to `security@nifi.apache.org` on 2026-05-15 with the live reproduction above. Triage and patch development on the Apache side was fast. CVE assigned, PR merged, advisory published on 2026-06-20.

## Links

- Advisory: https://nifi.apache.org/documentation/security/#CVE-2026-54665
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-54665
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-54665
- Jira: https://issues.apache.org/jira/browse/NIFI-15953
- Fix PR: https://github.com/apache/nifi/pull/11268
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- CWE-601: https://cwe.mitre.org/data/definitions/601.html

---

> **AI/LLM usage disclosure:** AI assistance was used during the discovery process to accelerate reconnaissance and code review. The full reconnaissance and exploitation process was supervised by me. All exploit code was crafted by me and tested by me end-to-end against the target to verify the finding reproduces as described.
