# Windows Forensic Artifacts - MkDocs Material Site

This folder contains a MkDocs Material version of the 24-chapter Windows forensic artifacts handbook.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\mkdocs.exe serve
```

Open the local URL shown by MkDocs, usually:

```text
http://127.0.0.1:8000/
```

## Build Static Site

```powershell
.\.venv\Scripts\mkdocs.exe build --strict
```

The generated static site will be written to `site/`.

## Structure

- `mkdocs.yml` - MkDocs Material configuration and navigation.
- `docs/index.md` - Homepage.
- `docs/chapters/` - The 24 handbook chapters.
- `docs/glossary.md` - Glossary.
- `docs/about.md` - Editorial notes and status.
