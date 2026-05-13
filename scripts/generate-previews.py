#!/usr/bin/env python3
"""
Generate static preview pages for each blog post.

Why: the blog renders Markdown client-side, but social link scrapers
(WhatsApp, Discord, LinkedIn, Slack, Twitter, etc.) do NOT execute
JavaScript — they read raw HTML. Without per-post HTML, every shared
link looks the same: "post — bl4cksku11" with no image.

This script reads blog/posts.json and, for each post, writes:

    blog/p/<slug>/index.html

Each generated file is a copy of blog/post.html with:
  - Post-specific <title> and <meta name="description">
  - Full Open Graph + Twitter Card meta block
  - <base href="/blog/"> so relative paths still resolve correctly
  - window.__POST_SLUG hardcoded so the SPA renderer skips URL parsing
  - <link rel="canonical"> pointing to the generated URL

Usage:

    python3 scripts/generate-previews.py

Run this every time you add a new post or change cover/title/excerpt
in posts.json. It is safe to re-run; it overwrites existing files.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BLOG = ROOT / "blog"
POST_TEMPLATE = BLOG / "post.html"
MANIFEST = BLOG / "posts.json"
OUT_DIR = BLOG / "p"

SITE_URL = "https://bl4cksku11.com"

# Default language for OG tags (the version that shows up in chat previews).
# The page itself remains bilingual once loaded — this is just the static
# meta the scrapers see.
OG_LANG = "en"


def html_escape(s):
    return (str(s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def pick_lang(field, lang):
    if field is None:
        return ""
    if isinstance(field, str):
        return field
    return (field.get(lang)
            or field.get("es")
            or field.get("en")
            or next(iter(field.values()), ""))


def resolve_img(src):
    """Mirror the JS resolveImg() helper: paths are relative to /blog/posts/."""
    if not src:
        return ""
    if re.match(r"^(https?:|//|/|data:)", str(src), re.I):
        return src
    return "posts/" + str(src).lstrip("./")


def build_meta_block(post):
    title    = pick_lang(post.get("title"),   OG_LANG)
    excerpt  = pick_lang(post.get("excerpt"), OG_LANG)
    cover    = pick_lang(post.get("cover"),   OG_LANG)
    cover_p  = resolve_img(cover)
    cover_url = f"{SITE_URL}/blog/{cover_p}" if cover_p else ""
    page_url = f"{SITE_URL}/blog/p/{post['slug']}/"
    full_title = f"{title} — bl4cksku11" if title else "post — bl4cksku11"

    lines = [
        f'<title>{html_escape(full_title)}</title>',
        f'<meta name="description" content="{html_escape(excerpt)}">',
        '',
        '<!-- Open Graph -->',
        '<meta property="og:type" content="article">',
        '<meta property="og:site_name" content="bl4cksku11">',
        f'<meta property="og:title" content="{html_escape(title)}">',
        f'<meta property="og:description" content="{html_escape(excerpt)}">',
        f'<meta property="og:url" content="{html_escape(page_url)}">',
        '<meta property="og:locale" content="en_US">',
        '<meta property="og:locale:alternate" content="es_ES">',
    ]
    if cover_url:
        lines += [
            f'<meta property="og:image" content="{html_escape(cover_url)}">',
            '<meta property="og:image:width" content="1200">',
            '<meta property="og:image:height" content="630">',
            f'<meta property="og:image:alt" content="{html_escape(title)}">',
        ]
    if post.get("date"):
        lines.append(f'<meta property="article:published_time" content="{html_escape(post["date"])}">')

    # Authors: prefer post.authors, then post.author, then defaults to site author
    authors_raw = post.get("authors") or ([post["author"]] if post.get("author") else [])
    for a in authors_raw:
        name = a if isinstance(a, str) else pick_lang(a.get("name"), OG_LANG)
        if name:
            lines.append(f'<meta property="article:author" content="{html_escape(name)}">')

    for tag in (post.get("tags") or []):
        lines.append(f'<meta property="article:tag" content="{html_escape(tag)}">')

    lines += [
        '',
        '<!-- Twitter Card -->',
        '<meta name="twitter:card" content="summary_large_image">',
        f'<meta name="twitter:title" content="{html_escape(title)}">',
        f'<meta name="twitter:description" content="{html_escape(excerpt)}">',
    ]
    if cover_url:
        lines.append(f'<meta name="twitter:image" content="{html_escape(cover_url)}">')

    lines += [
        '',
        f'<link rel="canonical" href="{html_escape(page_url)}">',
    ]

    return "\n  ".join(lines)


# Replace everything between <!-- @meta-start --> and <!-- @meta-end -->
# (inclusive). post.html owns this block so the SPA fallback URL still has
# decent default meta; generated pages under /blog/p/<slug>/ get richer,
# post-specific values that scrapers (no-JS) actually read.
META_BLOCK_RE = re.compile(
    r'<!--\s*@meta-start[^>]*-->.*?<!--\s*@meta-end\s*-->',
    re.DOTALL,
)


def transform(template_html, post):
    meta_block = build_meta_block(post)

    if not META_BLOCK_RE.search(template_html):
        raise RuntimeError(
            "Could not locate the <!-- @meta-start -->…<!-- @meta-end --> "
            "block in post.html. Check that the template wasn't restructured."
        )
    html = META_BLOCK_RE.sub(meta_block, template_html, count=1)

    # Add <base href="/blog/"> so relative paths in the template (assets/blog.css,
    # posts.json, etc.) keep working from /blog/p/<slug>/index.html.
    html = html.replace(
        '<meta charset="UTF-8">',
        '<meta charset="UTF-8">\n  <base href="/blog/">',
        1,
    )

    # Hardcode the slug for the renderer so URL parsing is unnecessary.
    slug_var = f'  <script>window.__POST_SLUG = {json.dumps(post["slug"])};</script>\n'
    html = re.sub(
        r'(<canvas id="bg"></canvas>)',
        slug_var.rstrip("\n") + r"\n  \1",
        html,
        count=1,
    )

    return html


def main():
    if not MANIFEST.exists():
        sys.exit(f"error: {MANIFEST} not found")
    if not POST_TEMPLATE.exists():
        sys.exit(f"error: {POST_TEMPLATE} not found")

    template = POST_TEMPLATE.read_text(encoding="utf-8")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    posts = manifest.get("posts", []) or []

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    written = []
    for post in posts:
        slug = post.get("slug")
        if not slug:
            continue
        out_dir = OUT_DIR / slug
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "index.html"
        out_file.write_text(transform(template, post), encoding="utf-8")
        written.append(out_file.relative_to(ROOT))

    print(f"Generated {len(written)} preview page(s):")
    for p in written:
        print(f"  {p}")
    print()
    print("Tip: commit the entire blog/p/ directory.")


if __name__ == "__main__":
    main()
