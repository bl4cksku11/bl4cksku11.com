# blog/

Static blog for bl4cksku11.com. No build step, no framework — Markdown rendered client-side with [marked](https://marked.js.org/) + [highlight.js](https://highlightjs.org/).

## Estructura / Structure

```
blog/
├── index.html              # listado + buscador + filtro por tags
├── post.html               # vista de un post (?slug=xxx&lang=es|en)
├── posts.json              # manifest (metadata de todos los posts)
├── posts/
│   ├── <slug>.es.md        # contenido en español
│   └── <slug>.en.md        # contenido en inglés (opcional)
├── assets/
│   └── blog.css            # estilos compartidos
└── README.md
```

## Cómo publicar un post nuevo (3 pasos)

### 1. Crear el(los) archivo(s) Markdown

Dentro de `posts/`, crea uno o dos archivos con la convención `<slug>.<lang>.md`:

```
posts/cobalt-strike-evasion.es.md
posts/cobalt-strike-evasion.en.md   # opcional
```

El `slug` es el id del post — sin espacios, sin acentos, en kebab-case. Será parte de la URL final:
`https://bl4cksku11.com/blog/post.html?slug=cobalt-strike-evasion`.

El contenido es Markdown estándar (GitHub-flavored). Funciona:

- Headings (`#`, `##`, `###`)
- Listas, listas numeradas, tablas
- Bloques de código con lenguaje (` ```bash `, ` ```python `, etc.)
- Citas (`>`)
- Imágenes (subilas a `posts/img/` y referenciá `![alt](img/foo.png)`)
- Enlaces

> Tip: el primer `# Título` del MD **no** se muestra como título grande del post (el título grande viene del manifest). Podés incluirlo o no, es decisión estética.

### 2. Agregar la entrada al manifest

Editá `posts.json` y sumá un objeto al array `posts`:

```json
{
  "slug": "cobalt-strike-evasion",
  "date": "2026-05-12",
  "languages": ["es", "en"],
  "tags": ["red-team", "evasion", "windows"],
  "title": {
    "es": "Evasión con Cobalt Strike — notas de campo",
    "en": "Cobalt Strike evasion — field notes"
  },
  "excerpt": {
    "es": "Lo que funcionó y lo que no, contra EDRs de gama media.",
    "en": "What worked and what did not, against mid-tier EDRs."
  }
}
```

Campos:

| Campo        | Obligatorio | Descripción |
|--------------|-------------|-------------|
| `slug`       | sí          | Id del post — debe coincidir con el nombre del archivo MD |
| `date`       | sí          | `YYYY-MM-DD`. Ordena el listado (más nuevos primero) |
| `languages`  | sí          | Idiomas disponibles. Ej: `["es"]` o `["es","en"]` |
| `tags`       | no          | Array de strings; aparecen como filtros en el listado |
| `cover`      | no          | Path de la portada (ej: `"img/foo.jpg"`). String o `{es, en}` |
| `author`     | no          | Autor único — string u objeto. Override del `defaultAuthor`. Ver sección Autores |
| `authors`    | no          | Array de autores (múltiples). Override del `defaultAuthor` |
| `title`      | sí          | String o `{es, en}` |
| `excerpt`    | sí          | String o `{es, en}`. Resumen mostrado en el listado |
| `readingTime`| no          | Si lo omites se calcula automáticamente |

Si solo escribís en un idioma, usá `"languages": ["es"]` y dejá `title`/`excerpt` como strings simples (sin objeto). El toggle ES/EN seguirá funcionando: si el lector pide EN y el post no existe en EN, se muestra ES con un aviso.

### 3. Listo

Subí los archivos. El blog los toma automáticamente — no hay nada que compilar.

```bash
git add blog/posts/cobalt-strike-evasion.* blog/posts.json
git commit -m "blog: cobalt strike evasion notes"
git push
```

## Autores

Los autores aparecen como **chip pequeño** en cada card del listado y como **bloque grande** (avatar + nombre + handle + rol) arriba del título en la página del post.

### Autor por defecto

Para no repetir tu info en cada post, definila una sola vez al tope de `posts.json`:

```jsonc
{
  "defaultAuthor": {
    "name": "Jose Rivas",
    "handle": "bl4cksku11",
    "role": {
      "es": "Red Team Operator / Penetration Tester",
      "en": "Red Team Operator / Penetration Tester"
    },
    "url": "https://bl4cksku11.com",
    "avatar": "img/authors/bl4cksku11.jpg"
  },
  "posts": [ /* ... */ ]
}
```

Si un post no especifica autor, hereda este `defaultAuthor` automáticamente.

### Override por post (autor invitado o múltiples)

Cualquier post puede sobreescribir con `author` (uno solo) o `authors` (varios):

```jsonc
{
  "slug": "guest-post-on-edrs",
  "author": {
    "name": "Pepito Pérez",
    "handle": "pepito",
    "role": "Malware Analyst",
    "url": "https://twitter.com/pepito",
    "avatar": "img/authors/pepito.jpg"
  }
}
```

Múltiples autores:

```jsonc
{
  "slug": "joint-research",
  "authors": [
    { "name": "Jose Rivas",   "handle": "bl4cksku11", "avatar": "img/authors/bl4cksku11.jpg" },
    { "name": "Pepito Pérez", "handle": "pepito",     "avatar": "img/authors/pepito.jpg"    }
  ]
}
```

Versión corta — solo nombre, sin avatar/handle:

```jsonc
"author": "Jose Rivas"
```

### Campos del objeto autor

| Campo    | Obligatorio | Descripción |
|----------|-------------|-------------|
| `name`   | sí          | Nombre mostrado. String o `{es, en}` |
| `handle` | no          | Username sin `@` (se renderiza con `@` en rojo en la página del post) |
| `role`   | no          | Rol/cargo. String o `{es, en}` |
| `url`    | no          | Si está, el bloque del autor en la página del post se vuelve clickeable |
| `avatar` | no          | Path a la imagen (relativa a `posts/`). Si falta, se muestran las iniciales |

### Avatares

Tirá los avatares en `blog/posts/img/authors/`:

```
blog/posts/img/authors/
├── bl4cksku11.jpg
└── pepito.jpg
```

Recomendación: cuadrados, **128×128 px** o **256×256 px**, JPG, < 30 KB. El layout los recorta con `object-fit: cover`. Si no hay avatar, se renderizan las **iniciales** (primeras dos palabras del nombre) en rojo sobre fondo oscuro.

## Imágenes

Todas las imágenes viven en `blog/posts/img/`. Las paths que escribas (tanto en el MD como en el campo `cover` del manifest) son **relativas a esa carpeta** — igual que en GitHub / VS Code / Obsidian.

### Estructura

```
blog/posts/
├── img/
│   ├── clickfix-analysis-dropper.jpg   ← portada del post
│   ├── clickfix-overlay.png            ← imágenes inline del post
│   └── clickfix-payload-flow.png
├── clickfix-analysis-dropper.es.md
└── clickfix-analysis-dropper.en.md
```

### Imagen de portada (cover)

Aparece como banner arriba del card en el listado y como hero arriba del título en la página del post. Es opcional — si no la pones, el card se ve como antes.

En `posts.json`:

```jsonc
{
  "slug": "clickfix-analysis-dropper",
  // ...
  "cover": "img/clickfix-analysis-dropper.jpg"
}
```

O por idioma (si la portada lleva texto y querés versionarla):

```jsonc
"cover": {
  "es": "img/clickfix-cover-es.jpg",
  "en": "img/clickfix-cover-en.jpg"
}
```

**Recomendaciones de tamaño:**

- Ratio de display: card usa **16:7**, hero usa **21:9** — ambos hacen `object-fit: cover`, así que cualquier imagen razonablemente apaisada funciona, solo cuidá que el sujeto esté en el centro
- Resolución sugerida: **1600×700 px** (queda bien en retina sin pesar mucho)
- Formato: JPG para fotos, PNG para capturas/diagramas, WebP si querés ahorrar peso
- Peso objetivo: **< 250 KB** por portada (la página la sirve sin lazy-load para que aparezca rápido)

### Imágenes dentro del post (inline)

Markdown estándar:

```markdown
![Diagrama del flujo del dropper](img/clickfix-payload-flow.png)
```

Path relativa a `posts/`, igual que el cover. Resultado: full-width, borde sutil acorde al tema, `loading="lazy"` automático.

### Caption opcional

Si pones un `title` después del path, se renderiza como caption debajo de la imagen (en `<figure><figcaption>`):

```markdown
![Overlay falso de Cloudflare Turnstile](img/clickfix-overlay.png "Captura del overlay falso servido por el sitio comprometido")
```

### Imágenes externas

URLs absolutas pasan tal cual sin reescritura:

```markdown
![](https://example.com/foto.jpg)
```

> Nota: si referenciás imágenes externas, considerá descargarlas y servirlas desde tu repo — más control, mejor privacidad para tus lectores, y no se rompe el post si el host original cambia.

## Probar localmente

`fetch()` no funciona con `file://`. Necesitás un servidor HTTP local:

```bash
# Desde la raíz del repo
python3 -m http.server 8000
# luego: http://localhost:8000/blog/
```

O cualquier alternativa: `npx serve`, `php -S localhost:8000`, `caddy file-server`, etc.

## Features incluidas

- **Buscador**: filtra por título, excerpt, slug y tags. Instantáneo, client-side.
- **Filtro por tags**: clickear un tag muestra solo posts con ese tag.
- **Portadas (cover)**: banner en el listado + hero en el post, con ratio fijo y borde acorde al tema.
- **Autores**: chip en el listado + bloque grande arriba del post. `defaultAuthor` global + override por post (uno o varios).
- **Toggle ES/EN**: la preferencia se persiste en `localStorage` y se propaga vía URL.
- **Reading time**: se calcula sobre el cuerpo del MD (≈220 wpm).
- **Code highlighting**: highlight.js con tema custom matcheando la paleta del sitio.
- **Imágenes con caption**: `![alt](img/foo.png "caption")` produce `<figure><figcaption>`.
- **Frontmatter opcional**: si por costumbre escribís frontmatter YAML al inicio del MD, se ignora silenciosamente — la metadata vive en `posts.json`.

## Aesthetic choices

- Paleta heredada de la landing: `--bg #030303`, `--red #cc1111`, `--border #2e2e2e`.
- Tipografía: Space Mono (Google Fonts).
- Scanlines + hex rain de fondo: shared con el index principal.
- Headings dentro del cuerpo del post llevan prefijo `// ` (h2) o `› ` (h3) en rojo.
