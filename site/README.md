# Frappuccino — presentation site

Static site for the Frappuccino landing + positioning pages. Built with
[Zola](https://www.getzola.org/) (a single Rust binary, no Node/npm).

## Privacy principles (non-negotiable for this project)

A privacy tool deserves a site that respects privacy:

- **No tracker, no analytics, no third-party request, no external fonts.**
- **No JS framework.** Any interactivity is hand-rolled vanilla JS, kept minimal.
- The **build runs off-server**; the server only serves static files, so the
  server-side attack surface is essentially a file server.

## Build & preview

```bash
# install Zola (https://www.getzola.org/documentation/getting-started/installation/)
zola serve     # live preview at http://127.0.0.1:1111
zola build     # outputs the static site to ./public/
```

`public/` is git-ignored — it is a build artifact.

## Deploy

⚠️ **Host this site SEPARATELY from the blind relay.** Do **not** put the public
domain on the relay's IP: it would link the relay IP to the Frappuccino brand
**and** put a second public name on that IP. The relay itself is already reached
by name (`relay.shake-document-protect.org`, since 2026-06-27), so the SNI is
already on the wire; what must not happen is tying the relay's address to the
public brand (see `docs/METADATA_EXPOSURE_MAP.md`). Any cheap neutral static host
serves `public/` fine; a `.onion` mirror is a natural addition. Avoid GitHub
Pages (Microsoft metadata) for a project of this nature.

Before going live (ROADMAP 8.2.6): set the real `base_url` and `repo_url` in
`config.toml`, add a favicon + the "fist cup" brand asset, and an APK download
link/button.

## Structure

```
config.toml            site config (base_url, brand, privacy posture)
content/
  _index.md            home / landing (rendered by templates/index.html)
  positioning.md       positioning page (rendered by templates/page.html)
templates/
  base.html            shared shell (head, header, footer — zero third-party)
  index.html           home
  page.html            generic page
sass/style.scss        the single stylesheet (sober dark theme)
static/                favicon, fonts, images, APK link target (when added)
```

## Content source of truth

The pages are adapted from the repository docs — **keep them in sync**:

- `content/_index.md` ← `README.md`
- `content/positioning.md` ← `docs/POSITIONNEMENT.md` (translated to EN)

Where the site and the code/docs diverge, the code and docs are authoritative.

## Languages

v1 is **English-primary** (the public landing copy is EN; English is the lingua
franca for the target audience). The content is i18n-ready: to add French,
declare `[languages.fr]` in `config.toml` and add `content/_index.fr.md` /
`content/positioning.fr.md` (the FR source already exists in
`docs/POSITIONNEMENT.md`). See the Zola multilingual docs.
