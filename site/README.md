# kseal documentation site

A static documentation site (MkDocs) that organizes the repository's existing
Markdown — `docs/**` plus the root `PROPOSAL.md` / `ARCHITECTURE.md` /
`README.md` — into one navigable site: getting started, architecture, SDK
guides (Android / iOS / desktop), server & ops, compliance, and the feature
parity matrix.

**No doc bodies are duplicated.** `build.sh` assembles a staging tree
(`.staging/`) of **symlinks** that mirrors the repo layout, so every rendered
page is the real canonical file and relative cross-links (e.g.
`../ARCHITECTURE.md`) resolve at build time. The only Markdown owned by this
directory is the landing page, `index.md`.

## Prerequisites

- Python 3.9+
- A POSIX shell with `ln -s` support (Linux/macOS). On Windows use WSL.

## Build

```bash
cd site
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt
./build.sh            # static HTML -> ./build (open build/index.html)
```

Live-reload dev server while editing docs:

```bash
./build.sh serve      # http://127.0.0.1:8000
```

To preview the built static site without the dev server:

```bash
python3 -m http.server --directory build 8000   # http://127.0.0.1:8000
```

## How it works

- `build.sh` — reassembles `.staging/` from scratch (so deletions in `docs/`
  are reflected), symlinking each source file into place, then runs
  `mkdocs build`.
- `mkdocs.yml` — `docs_dir: .staging`, `site_dir: build`, the `readthedocs`
  theme, the navigation tree, and GitHub-compatible heading slugs
  (`pymdownx.slugs`) so in-page anchor links match the source Markdown.
- `requirements.txt` — pinned MkDocs + extension versions for reproducible
  builds.
- `.gitignore` — the generated `.staging/` and `build/` trees are never
  committed.

## Adding a page

1. Add or edit the canonical Markdown under `docs/` (or a root doc).
2. Add a `nav:` entry in `mkdocs.yml` pointing at the staged path
   (`docs/<file>.md`, or the staged root-doc name).
3. Re-run `./build.sh`.

`build.sh` symlinks every `docs/*.md` automatically; only the `nav:` entry is
needed to surface a new page. This site is intentionally **not** wired into CI
here — a parent change owns any CI integration.
