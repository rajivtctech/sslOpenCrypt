# CLAUDE.md — sslOpenCrypt Project

This file instructs Claude Code on the mandatory workflow for the sslOpenCrypt project.
**These rules apply after every software change, without exception.**

---

## Repository Layout

```
Opencrypt/                              ← git root (github.com/rajivtctech/sslOpenCrypt)
├── sslopencrypt/                       ← Python source (modules, ui, core, cli, tests)
│   ├── packaging/
│   │   ├── sslopencrypt.spec           ← PyInstaller spec (Linux=onedir, Win/mac=onefile)
│   │   ├── build_appimage.sh           ← Linux AppImage build script
│   │   └── AppDir/                     ← AppRun, desktop entry, icon
│   └── tests/                         ← pytest suite
├── .github/workflows/
│   └── build-executables.yml          ← CI: builds all 3 platforms on tag push
├── wiki_content/
│   ├── Complete-Book.md               ← Editable source for the Complete Book
│   ├── Specification.md               ← Editable source for the Specification
│   └── Home.md
├── sslOpenCrypt_Complete_Book_v1.0.docx   ← Generated from Complete-Book.md
└── sslOpenCrypt_Specification_v0.3.docx   ← Generated from Specification.md
```

---

## Mandatory Post-Change Workflow

### 1 — Run Tests
Always run the full test suite before committing. All tests must pass.

```bash
cd sslopencrypt
python3 -m pytest tests/ -q
```

### 2 — Build All Platform Binaries (USB Pendrive Distribution)

All three platform builds must be kept current for pendrive distribution.
The binaries are **self-contained executables that run directly from a USB pendrive
without any installation step**.

| Platform | Format | Run from pendrive |
|---|---|---|
| **Linux** | AppImage | `chmod +x sslOpenCrypt-Linux.AppImage` then `./sslOpenCrypt-Linux.AppImage` |
| **macOS** | Single Mach-O binary | `chmod +x sslOpenCrypt-macOS`, right-click → Open (Gatekeeper) |
| **Windows** | Single PE executable | Double-click `sslOpenCrypt-Windows.exe` |

**Linux AppImage** (build on this machine):

```bash
cd sslopencrypt
bash packaging/build_appimage.sh
# Output: dist/sslOpenCrypt-Linux.AppImage
```

**macOS and Windows** binaries cannot be cross-compiled from Linux.
They are built automatically by GitHub Actions when a version tag is pushed:

```bash
git tag v1.X.Y
git push origin v1.X.Y
```

The CI workflow (`.github/workflows/build-executables.yml`) builds all three
platforms in parallel and publishes a GitHub Release with all binaries attached.

### 3 — Update Documentation (if user-facing features changed)

If the change adds a new feature, modifies existing behaviour, or changes
the UI, update the following Markdown sources **before committing**:

- `wiki_content/Complete-Book.md` — user guide, feature descriptions, version table
- `wiki_content/Specification.md` — technical specification, API descriptions

Rules:
- New module or sub-feature → add a subsection in the relevant Section of Complete-Book.md
- Changed UI workflow → update the corresponding UI Specification block
- New version milestone → add a row to the version history table (Section ~line 490)
- Ghost Crypt format change → update Section 8B binary layout description and recovery procedure
- India DSC new feature → update the India DSC section and the portal table

The `.docx` files (`sslOpenCrypt_Complete_Book_v1.0.docx`,
`sslOpenCrypt_Specification_v0.3.docx`) are generated from the Markdown sources
using the Python scripts at the repo root (`update_book_lo_chapter.py`, etc.).
Run the relevant script after editing the Markdown to regenerate the `.docx`.

### 4 — Commit and Push to GitHub

Stage all changed files — source, packaging scripts, documentation, and built
artifacts — and push to `origin main`.

```bash
cd /home/rajiv/Documents/Opencrypt   # repo root
git add -A
git commit -m "<concise imperative summary of the change>"
git push origin main
```

For a release (after the AppImage build passes and all tests are green):

```bash
git tag v1.X.Y
git push origin v1.X.Y
# GitHub Actions builds macOS + Windows; creates GitHub Release automatically.
```

---

## Platform Build Details

### Linux — AppImage

- Spec uses PyInstaller `--onedir` (COLLECT) for Linux. The `build_appimage.sh`
  script wraps the `dist/sslOpenCrypt-Linux/` directory into a squashfs AppImage
  using `appimagetool`.
- `appimagetool` is downloaded automatically to `/tmp/` if not installed.
- Requires `libfuse2` on the build machine: `sudo apt install libfuse2`
- Output: `sslopencrypt/dist/sslOpenCrypt-Linux.AppImage`
- End users: `chmod +x sslOpenCrypt-Linux.AppImage && ./sslOpenCrypt-Linux.AppImage`

### macOS — Single Binary

- Spec uses PyInstaller `--onefile` for macOS.
- Gatekeeper blocks unsigned binaries on first run. Document workaround in release notes.
- Built by CI on `macos-14` (Apple Silicon arm64). Intel Mac users run via Rosetta 2.

### Windows — Single EXE

- Spec uses PyInstaller `--onefile` for Windows.
- SmartScreen warns on first run (unsigned binary) — click "More info → Run anyway".
- Built by CI on `windows-latest`.
- OpenSSL must be installed separately on the end-user Windows machine:
  [Win64 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)

---

## Source of Truth for Each Area

| What | Where to look / update |
|---|---|
| Test suite | `sslopencrypt/tests/` — run `pytest tests/ -q` |
| Ghost Crypt logic | `sslopencrypt/modules/symmetric/ghost_crypt.py` |
| India DSC | `sslopencrypt/modules/india_dsc/controller.py` |
| PyInstaller spec | `sslopencrypt/packaging/sslopencrypt.spec` |
| AppImage build | `sslopencrypt/packaging/build_appimage.sh` |
| CI pipeline | `.github/workflows/build-executables.yml` |
| Complete Book (editable) | `wiki_content/Complete-Book.md` |
| Specification (editable) | `wiki_content/Specification.md` |
| GitHub remote | `https://github.com/rajivtctech/sslOpenCrypt` |
