# CVE-2026-102980: El único endpoint de páginas de Plane que se olvidó de chequear en qué project está la página

**Publicado:** 2026-10-05 **Reportado:** 2026-05-23 **Severidad:** 6.5 Media **Estado:** Corregido en Plane 1.4.0 (GHSA-ghcr-frqr-6pqr) **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

---

Los endpoints de páginas de Plane bindean la página al project de la URL antes de servirla. `PageVersionEndpoint` no. Filtra las versiones de página por workspace y page id, e ignora el `project_id` que tiene sentado en su propia firma. La clase de permisos deriva el rol del caller de ese mismo `project_id` sin bindear, así que un member de cualquier project manda el id de su propio project, el chequeo de rol pasa, y la query de versiones devuelve una página de un project al que nunca lo invitaron. Como el `description_html` de la última versión es el contenido actual de la página, esto lee páginas vivas, no solo historial. Asignado CVE-2026-102980, 6.5 Media, corregido en Plane 1.4.0.

---

## El bug

`apps/api/plane/app/views/page/version.py`, en v1.3.1:

```python
class PageVersionEndpoint(BaseAPIView):
    permission_classes = [ProjectPagePermission]

    def get(self, request, slug, project_id, page_id, pk=None):
        if pk:
            page_version = PageVersion.objects.get(workspace__slug=slug, page_id=page_id, pk=pk)
            ...
        page_versions = PageVersion.objects.filter(workspace__slug=slug, page_id=page_id)
```

Los dos lookups filtran por `workspace__slug` y `page_id`. `project_id` es un parámetro del método, bindeado por el router de URLs, y nunca se usa.

Los endpoints hermanos sí lo usan. `PagesDescriptionViewSet` en `page/base.py` pinea la página con `projects__id=project_id` tanto en su path de lectura como en el de escritura, y `PageViewSet.get_queryset` filtra las páginas al project de la URL. De todos los lectores de páginas, `PageVersionEndpoint` es el único que omite el binding, que es lo que hace que esto sea un descuido de un endpoint y no una decisión de diseño.

La clase de permisos no compensa. `ProjectPagePermission` en `apps/api/plane/app/permissions/page.py`:

```python
role = self._check_project_member_access(request, slug, project_id)   # rol desde el project de la URL
...
page = Page.objects.get(id=page_id, workspace__slug=slug)             # página buscada a nivel workspace
...
return self._has_public_page_action_access(request, role)             # páginas PUBLIC: GUEST+ puede GET
```

Tres líneas, dos scopes distintos. El rol viene del `project_id` de la URL. La página se busca a nivel workspace, sin ninguna restricción que la ate a ese project. La decisión después los combina como si describieran la misma cosa.

Entonces el atacante manda un `project_id` donde tiene un rol, que para un member del workspace es trivialmente su propio project. La clase de permisos lee un rol válido de GUEST o ADMIN de ahí y permite el GET. La query de versiones después va a buscar la página sin esa restricción de project y la encuentra donde realmente vive.

Las páginas vienen por default con `access = 0`, PUBLIC, así que la página típica califica para la rama de `GUEST+ puede GET`. "Público" acá significa público para el project, que es justo la suposición que se rompe cuando falta el binding al project.

## PoC

Plane CE v1.2.3, deployment community con docker-compose. Un workspace `shared2-ws` con dos projects. Alice es ADMIN de `PA` y no es member de `PB`. Bob es dueño de una página pública en `PB` cuyo contenido es un secreto reconocible.

**Baseline.** Alice pide la versión por el project real de la página, `PB`, donde no tiene membresía:

```console
GET /api/workspaces/shared2-ws/projects/f64f7bee-a6d3-4839-b948-66b3a64f793b/pages/67ef447d-d892-4dbd-98e9-506b317287bf/versions/cb6d3a36-5b11-486b-9f1c-caec0371a5a8/
Cookie: session-id=<alice>

HTTP/1.1 403 Forbidden
{"detail":"You do not have permission to perform this action."}
```

Negado, correctamente. `ProjectPagePermission` no encuentra membresía de Alice en `PB`.

**Exploit.** Misma página, misma versión, misma sesión. Alice cambia el project del path por el suyo:

```console
GET /api/workspaces/shared2-ws/projects/2bd1294d-3c4b-459a-9a28-4626f3d5185a/pages/67ef447d-d892-4dbd-98e9-506b317287bf/versions/cb6d3a36-5b11-486b-9f1c-caec0371a5a8/
Cookie: session-id=<alice>

HTTP/1.1 200 OK
{"id":"cb6d3a36-...","page":"67ef447d-...",
 "description_html":"<p>CONFIDENTIAL PAGE: master API key sk-live-9f3a2b not for project A</p>",
 "owned_by":"36e49693-... (bob)"}
```

Un segmento del path es toda la diferencia entre los dos requests. La clase de permisos derivó el rol de Alice de `PA` donde es ADMIN, la query de versiones nunca ató la página a `PA`, y volvió el contenido de Bob.

Los paths de escritura no están afectados, y vale decirlo porque acota el hallazgo. El `PATCH` sobre la metadata de la página mantiene un owner guard sobre el campo de access, y `PagesDescriptionViewSet` bindea `projects__id=project_id`, así que una escritura de contenido cross-project tira `DoesNotExist`. Esto es disclosure de solo lectura.

## Impacto

Un member del workspace que pertenece a exactamente un project lee el contenido completo de cualquier página PUBLIC de cualquier otro project del mismo workspace, incluidos projects a los que nunca lo invitaron. El GET está permitido para GUEST para arriba, así que el rol más bajo alcanza. Como las páginas son públicas por default, la expuesta es la página típica y no la excepcional.

La configuración a la que esto le pega es aquella donde los projects separados son el borde de confidencialidad: un workspace que segmenta trabajo de clientes, o planificación interna, en projects, y después agrega un colaborador externo como guest en uno de ellos. Ese guest puede leer las páginas de los otros. El borde que el admin cree haber configurado es el borde que este endpoint no hace cumplir.

Leer la última versión es leer la página tal como está ahora mismo, así que esto no se limita a revisiones históricas.

**CVSS 3.1:** 6.5 Media, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`. `C:H` por el contenido completo de la página, `I:N` y `A:N` porque los paths de escritura aguantan. `PR:L` porque el atacante necesita ser member del workspace con un project, que en este modelo de amenaza es el colaborador guest.

Afectados: Plane `<= 1.3.1`, confirmado en v1.2.3, mismo código en v1.3.1 y en `preview` HEAD `039d582`.

## Fix

El reporte sugería bindear los lookups de versiones como ya lo hacen los hermanos, y agregar el mismo binding en `ProjectPagePermission` para que el chequeo de rol no se pueda satisfacer con un project no relacionado.

Plane 1.4.0 hizo la primera parte, contra la tabla de join en vez del campo que yo sugerí:

```python
page_version = (
    PageVersion.objects.filter(
        workspace__slug=slug,
        page__project_pages__project_id=project_id,
        page__project_pages__deleted_at__isnull=True,
        page_id=page_id,
        pk=pk,
    )
    .distinct()
    .get()
)
```

Hay dos detalles ahí que vale notar. `deleted_at__isnull=True` significa que el link tiene que estar *activo*, así que una página que fue removida de un project no se puede leer después a través de él. Y el `.distinct()` protege al `get()`: joinear por `project_pages` puede producir más de una fila, y `get()` sobre un queryset de varias filas tira `MultipleObjectsReturned`, que sale como un 500. La query de listado recibe el mismo scoping como defensa en profundidad.

El comentario de los maintainers en el archivo parcheado cita dos advisories, `GHSA-g49r` junto a este, así que el mismo fix cerró un reporte relacionado.

Lo que no cambió es `ProjectPagePermission`. Sigue derivando el rol del caller del project de la URL mientras busca la página a nivel workspace. Ahora el queryset es lo que hace cumplir el borde, que acá alcanza porque el queryset es lo que devuelve los datos. Sí significa que la clase de permisos queda disponible para cablearse a un endpoint futuro que se olvide de su propio scoping.

Corregido en Plane 1.4.0, publicado el 2026-07-31.

## Disclosure

| Fecha        | Evento                                                        |
|--------------|----------------------------------------------------------------|
| 2026-05-23   | Comparados los endpoints de páginas por scoping inconsistente de project, explotado en CE v1.2.3 |
| 2026-05-23   | Reportado vía GitHub Security Advisory                         |
| 2026-07-31   | El fix sale en Plane 1.4.0                                     |
| 2026-09-28   | Publicado GHSA-ghcr-frqr-6pqr, asignado CVE-2026-102980        |

## Takeaways

Este salió por comparación, no por leer con lupa ninguna función puntual. Cinco endpoints sirven datos de páginas. Cuatro pinean la página al project de la URL. Listarlos uno al lado del otro y diffear sus querysets hace que el quinto salte de una forma que leer `version.py` solo no logra, porque aislado el código se ve bien. `PageVersion.objects.get(workspace__slug=slug, page_id=page_id, pk=pk)` tiene un filtro de workspace y dos ids específicos. Se lee como un lookup scopeado. Recién se lee mal al lado del hermano que tiene un filtro más.

La mitad estructural es la separación entre la clase de permisos y el queryset. `ProjectPagePermission` responde "cuál es el rol de este caller en el project de la URL", bien. El queryset responde "qué filas matchean", también bien, para la pregunta que le dieron. Ninguno es responsable de "¿está la página en el project de la URL?", así que nadie la hace. Ese gap es el mismo que está detrás de [CVE-2026-105637](/blog/p/plane-bulk-asset-cross-project-hijack/) en las rutas de assets: una capa de permisos scopeada a la URL, una capa de datos scopeada a ids que manda el caller, y nadie chequeando que las dos describan el mismo objeto.

## Links

- Advisory: https://github.com/makeplane/plane/security/advisories/GHSA-ghcr-frqr-6pqr
- Registro CVE: https://www.cve.org/CVERecord?id=CVE-2026-102980
- Hallazgo hermano en las rutas de assets: https://bl4cksku11.com/blog/p/plane-bulk-asset-cross-project-hijack/
- Plane: https://github.com/makeplane/plane
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
