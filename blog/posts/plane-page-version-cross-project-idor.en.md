# CVE-2026-102980: The one Plane page endpoint that forgot to check which project the page is in

**Published:** 2026-10-05 **Reported:** 2026-05-23 **Severity:** 6.5 Medium **Status:** Fixed in Plane 1.4.0 (GHSA-ghcr-frqr-6pqr) **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

---

Plane's page endpoints bind a page to the project in the URL before serving it. `PageVersionEndpoint` does not. It filters page versions by workspace and page id, and ignores the `project_id` sitting in its own function signature. The permission class derives the caller's role from that same unbound `project_id`, so a member of any one project supplies their own project's id, the role check passes, and the version query returns a page from a project they were never invited to. Since the latest version's `description_html` is the page's current content, this reads live pages, not just history. Assigned CVE-2026-102980, 6.5 Medium, fixed in Plane 1.4.0.

---

## The bug

`apps/api/plane/app/views/page/version.py`, on v1.3.1:

```python
class PageVersionEndpoint(BaseAPIView):
    permission_classes = [ProjectPagePermission]

    def get(self, request, slug, project_id, page_id, pk=None):
        if pk:
            page_version = PageVersion.objects.get(workspace__slug=slug, page_id=page_id, pk=pk)
            ...
        page_versions = PageVersion.objects.filter(workspace__slug=slug, page_id=page_id)
```

Both lookups filter on `workspace__slug` and `page_id`. `project_id` is a parameter of the method, bound by the URL router, and never used.

The sibling endpoints do use it. `PagesDescriptionViewSet` in `page/base.py` pins the page with `projects__id=project_id` in both its read and its write path, and `PageViewSet.get_queryset` filters pages to the URL project. Out of the page readers, `PageVersionEndpoint` is the only one that omits the binding, which is what makes this a one-endpoint oversight rather than a design decision.

The permission class does not compensate. `ProjectPagePermission` in `apps/api/plane/app/permissions/page.py`:

```python
role = self._check_project_member_access(request, slug, project_id)   # role from the URL project
...
page = Page.objects.get(id=page_id, workspace__slug=slug)             # page looked up workspace-wide
...
return self._has_public_page_action_access(request, role)             # PUBLIC pages: GUEST+ may GET
```

Three lines, two different scopes. The role comes from the URL's `project_id`. The page is fetched workspace-wide, with no constraint tying it to that project. The decision then combines them as though they described the same thing.

So the attacker supplies a `project_id` where they hold a role, which for a workspace member is trivially their own project. The permission class reads a valid GUEST or ADMIN role from it and allows the GET. The version query then goes looking for the page without that project constraint and finds it wherever it actually lives.

Pages default to `access = 0`, PUBLIC, so the typical page qualifies for the `GUEST+ may GET` branch. "Public" here means public to the project, which is precisely the assumption that breaks when the project binding is missing.

## PoC

Plane CE v1.2.3, docker-compose community deployment. One workspace `shared2-ws` with two projects. Alice is ADMIN of `PA` and not a member of `PB`. Bob owns a public page in `PB` whose content is a recognisable secret.

**Baseline.** Alice requests the version through the page's real project, `PB`, where she has no membership:

```console
GET /api/workspaces/shared2-ws/projects/f64f7bee-a6d3-4839-b948-66b3a64f793b/pages/67ef447d-d892-4dbd-98e9-506b317287bf/versions/cb6d3a36-5b11-486b-9f1c-caec0371a5a8/
Cookie: session-id=<alice>

HTTP/1.1 403 Forbidden
{"detail":"You do not have permission to perform this action."}
```

Correctly denied. `ProjectPagePermission` finds no membership for Alice in `PB`.

**Exploit.** Same page, same version, same session. Alice changes the project in the path to her own:

```console
GET /api/workspaces/shared2-ws/projects/2bd1294d-3c4b-459a-9a28-4626f3d5185a/pages/67ef447d-d892-4dbd-98e9-506b317287bf/versions/cb6d3a36-5b11-486b-9f1c-caec0371a5a8/
Cookie: session-id=<alice>

HTTP/1.1 200 OK
{"id":"cb6d3a36-...","page":"67ef447d-...",
 "description_html":"<p>CONFIDENTIAL PAGE: master API key sk-live-9f3a2b not for project A</p>",
 "owned_by":"36e49693-... (bob)"}
```

One path segment is the entire difference between the two requests. The permission class derived Alice's role from `PA` where she is ADMIN, the version query never bound the page to `PA`, and Bob's content came back.

The write paths are not affected, which is worth stating because it bounds the finding. `PATCH` on page metadata keeps an owner guard on the access field, and `PagesDescriptionViewSet` binds `projects__id=project_id`, so a cross-project content write raises `DoesNotExist`. This is read-only disclosure.

## Impact

A workspace member who belongs to exactly one project reads the full content of any PUBLIC page in any other project of the same workspace, including projects they were never invited to. GET is allowed for GUEST and up, so the lowest role is enough. Because pages default to public, the typical page is exposed rather than the exceptional one.

The configuration this hurts is the one where separate projects are the confidentiality boundary: a workspace that segments client work, or internal planning, into projects and then adds an external collaborator as a guest on one of them. That guest can read the others' pages. The boundary the admin believes they configured is the boundary this endpoint does not enforce.

Reading the latest version is reading the page as it stands right now, so this is not limited to historical revisions.

**CVSS 3.1:** 6.5 Medium, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`. `C:H` for full page content, `I:N` and `A:N` because the write paths hold. `PR:L` because the attacker needs to be a workspace member with a project, which in this threat model is the guest collaborator.

Affected: Plane `<= 1.3.1`, confirmed on v1.2.3, same code on v1.3.1 and `preview` HEAD `039d582`.

## Fix

The report suggested binding the version lookups the way the siblings already do, and adding the same binding to `ProjectPagePermission` so the role check cannot be satisfied by an unrelated project.

Plane 1.4.0 did the first part, against the join table rather than the field I suggested:

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

Two details in there are worth noticing. `deleted_at__isnull=True` means the link has to be *active*, so a page that was removed from a project cannot be read back through it afterwards. And `.distinct()` guards the `get()`: joining through `project_pages` can produce more than one row, and `get()` on a multi-row queryset raises `MultipleObjectsReturned`, which surfaces as a 500. The list query gets the same scoping as defence in depth.

The maintainers' comment in the patched file cites two advisories, `GHSA-g49r` alongside this one, so the same fix closed a related report.

What did not change is `ProjectPagePermission`. It still derives the caller's role from the URL project while fetching the page workspace-wide. The queryset is now the thing enforcing the boundary, which is sufficient here because the queryset is what returns the data. It does mean the permission class remains available to be wired into a future endpoint that forgets its own scoping.

Fixed in Plane 1.4.0, released 2026-07-31.

## Disclosure

| Date         | Event                                                       |
|--------------|--------------------------------------------------------------|
| 2026-05-23   | Page endpoints compared for inconsistent project scoping, exploited on CE v1.2.3 |
| 2026-05-23   | Reported via GitHub Security Advisory                        |
| 2026-07-31   | Fix ships in Plane 1.4.0                                     |
| 2026-09-28   | GHSA-ghcr-frqr-6pqr published, CVE-2026-102980 assigned      |

## Takeaways

This one was found by comparison rather than by reading any single function closely. Five endpoints serve page data. Four of them pin the page to the URL project. Listing them side by side and diffing their querysets makes the fifth obvious in a way that reading `version.py` on its own does not, because in isolation the code looks fine. `PageVersion.objects.get(workspace__slug=slug, page_id=page_id, pk=pk)` has a workspace filter and two specific ids. It reads like a scoped lookup. It only reads wrong next to the sibling that has one more filter.

The structural half is the split between the permission class and the queryset. `ProjectPagePermission` answers "what is this caller's role in the URL project", correctly. The queryset answers "which rows match", also correctly, for the question it was given. Neither is responsible for "is the page in the URL project", so nobody asks it. That gap is the same one behind [CVE-2026-105637](/blog/p/plane-bulk-asset-cross-project-hijack/) in the asset routes: a permission layer scoped to the URL, a data layer scoped to caller-supplied ids, and no one checking that the two describe the same object.

## Links

- Advisory: https://github.com/makeplane/plane/security/advisories/GHSA-ghcr-frqr-6pqr
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-102980
- Sibling finding in the asset routes: https://bl4cksku11.com/blog/p/plane-bulk-asset-cross-project-hijack/
- Plane: https://github.com/makeplane/plane
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
