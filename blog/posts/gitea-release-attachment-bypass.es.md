# CVE-2026-58428: Bypaseando el allowlist de extensiones de attachments de releases en Gitea vía el formulario web

**Publicado:** 2026-07-27 **Severidad:** Media **Estado:** Corregido en Gitea 1.27.0 **CWEs:** CWE-424 (Improper Protection of Alternate Path) + CWE-434 (Unrestricted Upload of File with Dangerous Type)

---

Gitea permite al operator restringir qué extensiones de archivo se pueden adjuntar a releases con `Repository.Release.AllowedTypes`. Un advisory previo, CVE-2025-68939, arregló una forma de saltarse ese allowlist renombrando un attachment vía API. El fix solo cubrió la API. El formulario web de edit de releases llegaba al mismo write en la base de datos por otro path y nunca validaba el nombre nuevo, así que un usuario con write access al repositorio podía renombrar un attachment ya subido a cualquier extensión prohibida. Es una variante de CVE-2025-68939. Asignado como CVE-2026-58428, rated Medium, corregido en 1.27.0.

Esta también tiene un subplot que vale la pena contar: originalmente le puse un score muy alto, y Medium es el número honesto por una razón que involucra el serving path exacto en `httplib/serve.go`.

---

## Contexto

Cuando subís un archivo a un release de Gitea, el server chequea la extensión del archivo contra un allowlist configurado por el operator. Si el operator setea `ALLOWED_TYPES = .zip,.tar.gz`, solo esas extensiones se aceptan en el upload. Los attachments también se pueden renombrar después.

CVE-2025-68939 era sobre el rename path: subís un `.zip`, después lo renombrás a `.exe`, y si el rename no re-chequea el allowlist, defeasteste la restricción. Eso fue arreglado en el PR #32151, que agregó el chequeo del allowlist a los endpoints de edit de la API. El fix delegaba a una service function que llama a `upload.Verify` antes de persistir el nombre nuevo.

La pregunta que hice durante un patch diff de ese fix era simple. La acción de rename escribe al nombre del attachment en la base de datos. ¿La API es el único caller que hace ese write, o hay otra entry point que llega al mismo write sin pasar por el validador parcheado?

## El bug

Hay otra entry point. El formulario web de edit de releases.

`EditReleasePost` en `routers/web/repo/release.go` recolecta los campos del formulario con prefijo `attachment-edit-` en un mapa uuid-a-nombre-nuevo:

```go
const editPrefix = "attachment-edit-"
editAttachments := make(map[string]string)
if setting.Attachment.Enabled {
	for k, v := range ctx.Req.Form {
		if strings.HasPrefix(k, editPrefix) {
			editAttachments[k[len(editPrefix):]] = v[0]
		}
	}
}
...
release_service.UpdateRelease(ctx, ctx.Doer, ctx.Repo.GitRepo,
	rel, addAttachmentUUIDs, delAttachmentUUIDs, editAttachments)
```

Ese mapa se le pasa a `release_service.UpdateRelease`, que escribe cada nombre nuevo directo a la base de datos:

```go
for uuid, newName := range editAttachments {
	if !deletedUUIDs.Contains(uuid) {
		if err = repo_model.UpdateAttachmentByUUID(ctx, &repo_model.Attachment{
			UUID: uuid,
			Name: newName,
		}, "name"); err != nil {
			return err
		}
	}
}
```

No hay ningún `upload.Verify(nil, newName, setting.Repository.Release.AllowedTypes)` en ninguna parte de este path. Comparalo con lo que hace el endpoint de API parcheado, donde la misma acción lógica pasa por `attachment_service.UpdateAttachment`, que llama a `upload.Verify` y rechaza una extensión prohibida con un 422. La API creció un guard. El formulario web siguió escribiendo el nombre en crudo. Misma acción, dos puertas, una sola trabada.

## Reproducción

Testeado contra Gitea 1.26.1 con un allowlist del operator de `.zip,.tar.gz` y un usuario regular `bob` que es dueño de `bob/test-repo`.

Primero el sanity check de que el fix parent funciona. `bob` sube `innocent.zip` a un release, después intenta renombrarlo a `evil.exe` vía la API:

```http
PATCH /api/v1/repos/bob/test-repo/releases/1/assets/1 HTTP/1.1
Authorization: token <bob_token>
Content-Type: application/json

{"name":"evil.exe"}
```

El server devuelve HTTP 422, forbidden file extension. Bien, el fix del CVE-2025-68939 parent está en su lugar.

Ahora el mismo rename vía el formulario web:

```http
POST /bob/test-repo/releases/edit/v0.1 HTTP/1.1
Cookie: i_like_gitea=<session>
Content-Type: application/x-www-form-urlencoded

tag_name=v0.1&tag_target=main&title=rename+payload&content=&attachment-edit-<uuid>=evil.exe
```

El server devuelve HTTP 303 a la página de releases. No hay error de validación. Leer el attachment de vuelta confirma que el nombre ahora es `evil.exe`, y el link de download sirve el archivo bajo esa extensión. El allowlist que la API enforza queda silenciosamente bypaseado por el formulario.

## Por qué es Medium, y cómo llegué ahí

Originalmente lo filé como High, prestando el vector `C:H/I:H` del advisory parent razonando que un attachment renombrado a `.html` o `.svg` servido desde el origen de Gitea se convierte en stored XSS. El maintainer me empujó para atrás y dijo Medium. Tenía razón, y vale la pena mostrar exactamente por qué, porque es una buena lección sobre no asumir un impacto que no verificaste.

La capa de file-serving de Gitea está endurecida contra precisamente esto. En `modules/httplib/serve.go`, cada archivo servido recibe un Content Security Policy estricto:

```go
// Disable JS execution on the same origin, since we serve the file from the same origin as Gitea server.
serveHeaderCspDefault = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
```

El token `sandbox` sin `allow-scripts` mata la ejecución de JavaScript aún cuando el archivo se renderiza inline. Además, el HTML supplied por el usuario se fuerza a `text/plain`:

```go
//  intentionally do not render user's HTML content as a page, for safety, and avoid content spamming & abusing
opts.ContentType = "text/plain"
```

y la disposition default para los attachments es `attachment`, con `X-Content-Type-Options: nosniff` seteado. Un `.html` o `.svg` renombrado no ejecuta script en el origen de Gitea. El stored XSS que asumí simplemente no dispara. Una vez que sacás el XSS de la mesa, el impacto de confidentiality e integrity en el vector CVSS baja, y el número honesto es Medium.

Lo que el bug efectivamente te da es el defeat de la política del allowlist del operator: hostear un archivo bajo una extensión prohibida, por ejemplo distribuir un `.exe` o `.msi` que se hace pasar por un asset de release legítimo, y silenciosamente deshacer un control de hardening que el operator deliberadamente activó. Eso es real y vale la pena arreglarlo, pero no es code execution. En términos de preconditions necesita que el operator haya configurado un allowlist y que el atacante tenga write al repositorio, las mismas restricciones que el parent, así que las restricciones tampoco lo suben por encima del parent.

El takeaway para mí fue verificar la última milla del impacto antes de anclar la severidad. El serving path estaba a un archivo de distancia y cambió el rating entero.

## El parche

Espejar el fix parent en el path web. Verificar cada nombre nuevo contra el allowlist antes del write, dentro de `UpdateRelease`:

```go
for uuid, newName := range editAttachments {
	if deletedUUIDs.Contains(uuid) {
		continue
	}
	if err := upload.Verify(nil, newName, setting.Repository.Release.AllowedTypes); err != nil {
		return err
	}
	if err = repo_model.UpdateAttachmentByUUID(ctx, &repo_model.Attachment{
		UUID: uuid,
		Name: newName,
	}, "name"); err != nil {
		return err
	}
}
```

El handler debería surface una extensión prohibida como un 422 o un flash error para matchear el comportamiento de la API. Corregido en Gitea 1.27.0.

## Takeaways

Cuando aterriza un fix, el primer movimiento de variant hunting es preguntarse qué otros callers llegan al mismo write. El fix de CVE-2025-68939 guardó el rename de la API, y el formulario web llegaba al `UpdateAttachmentByUUID` idéntico sin ningún guard. Dos puertas a una acción, y el maintainer solo trabó una.

La segunda lección es sobre honestidad en el scoring. Anclé al High del parent basado en una suposición de XSS que no había testeado, y la capa de serving la defeasteste. Chequear el serve path real convirtió un High equivocado en un Medium correcto, y corregirte vos mismo frente al triager es más barato que defender un número que no podés respaldar.

## Divulgación

Reportado privadamente al equipo de seguridad de Gitea. Confirmado por los maintainers. La severidad se estabilizó en Medium después de la discusión. CVE-2026-58428 asignado. Corregido en el release de Gitea 1.27.0. Divulgación pública después de que ese release shipeó.

Gracias al equipo de Gitea por el triage y por el pushback en el scoring.

## Links

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-58428
- Advisory parent: [CVE-2025-68939 / GHSA-263q-5cv3-xq9g](https://github.com/go-gitea/gitea/security/advisories/GHSA-263q-5cv3-xq9g)
- Fix parent: https://github.com/go-gitea/gitea/pull/32151
- Release de Gitea 1.27.0: https://github.com/go-gitea/gitea/releases/tag/v1.27.0
- CWE-424: https://cwe.mitre.org/data/definitions/424.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
