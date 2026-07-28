# CVE-2026-58428: Bypassing Gitea's release attachment extension allowlist through the web edit form

**Published:** 2026-07-27 **Severity:** Medium **Status:** Fixed in Gitea 1.27.0 **CWEs:** CWE-424 (Improper Protection of Alternate Path) + CWE-434 (Unrestricted Upload of File with Dangerous Type)

---

Gitea lets an operator restrict which file extensions can be attached to releases with `Repository.Release.AllowedTypes`. A previous advisory, CVE-2025-68939, fixed one way to sneak past that allowlist by renaming an attachment through the API. The fix only covered the API. The web release edit form reached the same database write through a different path and never validated the new name, so a user with repository write access could rename an already-uploaded attachment to any forbidden extension. This is a variant of CVE-2025-68939. Assigned CVE-2026-58428, rated Medium, fixed in 1.27.0.

---

## Background

When you upload a file to a Gitea release, the server checks the file's extension against an operator-configured allowlist. If the operator set `ALLOWED_TYPES = .zip,.tar.gz`, then only those extensions are accepted on upload. Attachments can also be renamed after the fact.

CVE-2025-68939 was about the rename path: you upload a `.zip`, then rename it to `.exe`, and if the rename does not re-check the allowlist you have defeated the restriction. That was fixed in PR #32151, which added the allowlist check to the API edit endpoints. The fix delegated to a service function that calls `upload.Verify` before persisting the new name.

The question I asked during a patch diff of that fix was simple. The rename action writes to the attachment name in the database. Is the API the only caller that performs that write, or is there another entry point that reaches the same write without going through the patched validator.

## The bug

There is another entry point. The web release edit form.

`EditReleasePost` in `routers/web/repo/release.go` collects form fields prefixed `attachment-edit-` into a map of uuid-to-new-name:

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

That map is handed to `release_service.UpdateRelease`, which writes each new name straight to the database:

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

There is no `upload.Verify(nil, newName, setting.Repository.Release.AllowedTypes)` anywhere on this path. Compare that to what the patched API endpoint does, where the same logical action goes through `attachment_service.UpdateAttachment`, which calls `upload.Verify` and rejects a forbidden extension with a 422. The API grew a guard. The web form kept writing the raw name. Same action, two doors, one of them locked.

## Reproduction

Tested against Gitea 1.26.1 with an operator allowlist of `.zip,.tar.gz` and a regular user `bob` who owns `bob/test-repo`.

First the sanity check that the parent fix works. `bob` uploads `innocent.zip` to a release, then tries to rename it to `evil.exe` through the API:

```http
PATCH /api/v1/repos/bob/test-repo/releases/1/assets/1 HTTP/1.1
Authorization: token <bob_token>
Content-Type: application/json

{"name":"evil.exe"}
```

The server returns HTTP 422, forbidden file extension. Good, the parent CVE-2025-68939 fix is in place.

Now the same rename through the web form:

```http
POST /bob/test-repo/releases/edit/v0.1 HTTP/1.1
Cookie: i_like_gitea=<session>
Content-Type: application/x-www-form-urlencoded

tag_name=v0.1&tag_target=main&title=rename+payload&content=&attachment-edit-<uuid>=evil.exe
```

The server returns HTTP 303 to the releases page. No validation error. Reading the attachment back confirms the name is now `evil.exe`, and the download link serves the file under that extension. The allowlist that the API enforces is silently bypassed by the form.

## Severity: why Medium, not High

The parent advisory carries a `C:H/I:H` vector on the reasoning that a renamed `.html` or `.svg` attachment served from the Gitea origin becomes stored XSS. That reasoning does not survive the actual serving path.

In `modules/httplib/serve.go`, every served file gets a strict Content Security Policy:

```go
// Disable JS execution on the same origin, since we serve the file from the same origin as Gitea server.
serveHeaderCspDefault = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
```

The `sandbox` token with no `allow-scripts` blocks JavaScript execution even when the file is rendered inline. User-supplied HTML is forced to `text/plain`:

```go
//  intentionally do not render user's HTML content as a page, for safety, and avoid content spamming & abusing
opts.ContentType = "text/plain"
```

and the default disposition for attachments is `attachment`, with `X-Content-Type-Options: nosniff` set. A renamed `.html` or `.svg` does not execute script on the Gitea origin. Without XSS on the same origin, the confidentiality and integrity impact on the CVSS vector drops.

What the bug provides is the defeat of the operator's allowlist policy: hosting a file under a forbidden extension, for example distributing a `.exe` or `.msi` that masquerades as a legitimate release asset, and silently undoing a hardening control the operator deliberately turned on. Preconditions match the parent (operator has configured an allowlist, attacker holds repository write), so the impact does not exceed the parent either. That lands the rating at Medium.

## The fix

Mirror the parent fix onto the web path. Verify each new name against the allowlist before the write, inside `UpdateRelease`:

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

The handler should surface a forbidden extension as a 422 or a flash error to match the API behavior. Fixed in Gitea 1.27.0.

## Takeaways

When a fix lands, the first variant-hunting move is to ask which other callers reach the same write. The CVE-2025-68939 fix guarded the API rename, and the web form reached the identical `UpdateAttachmentByUUID` write with no guard at all. Two doors to one action, only one locked.

## Disclosure

Reported privately to the Gitea security team. Confirmed by the maintainers. CVE-2026-58428 assigned. Fixed in the Gitea 1.27.0 release. Public disclosure after that release shipped.

Thanks to the Gitea maintainers for the fast triage.

## Links

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-58428
- Parent advisory: [CVE-2025-68939 / GHSA-263q-5cv3-xq9g](https://github.com/go-gitea/gitea/security/advisories/GHSA-263q-5cv3-xq9g)
- Parent fix: https://github.com/go-gitea/gitea/pull/32151
- Gitea 1.27.0 release: https://github.com/go-gitea/gitea/releases/tag/v1.27.0
- CWE-424: https://cwe.mitre.org/data/definitions/424.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
