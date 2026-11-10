# faux_finder

A macOS command-line tool that tells you whether an `.app` is a **"faux" native app**, a thin Mach-O wrapper around an embedded script, and extracts that script so you can read it instead of reverse engineering the binary.

It implements the workflow from Patrick Wardle's DEF CON 33 talk *"Binary Facades: from compiled macOS malware extracting embedded scripts"* (the same material as the "Nonbinary Binaries" section of [The Art of Mac Malware](https://taomm.org), Vol. I, Ch. 5): **identify the packager, extract the script with a packager-specific method, analyze the script.**

Pure Python 3, no required dependencies, macOS only.

## Supported wrappers

| Wrapper | Detected by | Extracts |
|---|---|---|
| **Platypus** | `Resources/script` plus `AppSettings.plist` `Creator` or `ScriptExec*` classes in the binary | the script |
| **Electron** | links `Electron Framework`, or the framework directory exists | the app's JavaScript from `app.asar` (own ASAR reader, no Node needed) |
| **osacompile** (AppleScript) | `aplt` bundle signature, `applet` stub, compiled `Scripts/main.scpt` | AppleScript source via `osadecompile`; run-only scripts keep the compiled `main.scpt` |
| **PyInstaller** | the `MEI` archive cookie in the binary | every archive entry and the expanded PYZ; entry points as `.pyc` |
| **Tauri** | two or more Tauri strings in the binary | non-system extended attributes and the Brotli-compressed frontend assets |

## Usage

```sh
pip install git+https://github.com/Yadhveer/faux_finder      # add ".[tauri]" extra for Tauri assets

faux_finder /path/to/Some.app              # identify only
faux_finder /path/to/Some.app -o out/      # identify and extract to out/<wrapper>/
```

From a clone you can also run `python3 -m faux_finder ...` or `pip install -e .`.

Example:

```
$ faux_finder tests/pls.app -o out
Application is a faux app created using Platypus
  - Contents/Resources/script exists
  - AppSettings.plist Creator: Platypus-5.5.0
  - AppSettings.plist InterpreterPath: /usr/bin/env
  - AppSettings.plist InterpreterArgs: []
  - binary contains ScriptExec* classes
Extracted 1 file(s) to out/platypus
```

Exit codes: `0` a wrapper was detected, `1` none detected, `2` bad input or extraction error.

Tauri asset extraction needs the optional `brotli` package (`pip install "faux_finder[tauri]"`). Without it, detection and extended-attribute recovery still work.

## How it works

Each wrapper is a small module in `faux_finder/modules/` with `name`, `detect(bundle)` (returns a list of evidence strings, empty if no match) and `extract(bundle, out_dir)`. To add one, write the module and add it to `WRAPPERS` in `faux_finder/__main__.py`. Parsers written from scratch:

- **Mach-O** (`macho.py`): fat and thin binaries, linked libraries, sections.
- **ASAR** (`electron.py`): the Chromium-pickle JSON header and file blob, including `.unpacked` files, with path-traversal protection.
- **PyInstaller CArchive** (`pyinstaller.py`): cookie, table of contents, and PYZ, with `.pyc` headers rebuilt for the archive's Python version (3.8-3.14).
- **Brotli stream recovery** (`tauri.py`): Brotli has no magic bytes and the decoder errors on any bytes after a stream, so the tool grows a prefix until it errors and bisects back to the exact end of the stream, scanning only data sections and skipping Brotli's built-in dictionary.

## Tests

```sh
python3 -I -m unittest discover -s tests
```

Uses `unittest` only. Fixtures are a real Platypus 5.5.0 app, a real `app.asar`, `osacompile` apps built at test time, a synthetic PyInstaller archive, and Brotli streams cut from a Tauri 2 build. The Brotli tests are skipped if `brotli` isn't installed. **The fixtures are harmless:** the Platypus script only writes a marker file to `/tmp` if run (don't run it anyway), and the Tauri payload points at an `.example` domain.

## Limitations

- Verified against small, real builds of PyInstaller 6.x and Tauri 2.x, a real Electron app (extraction matches `npx asar extract` byte for byte), and 73 installed apps with no false positives. Large production Tauri and PyInstaller apps haven't been tried.
- PyInstaller and run-only AppleScript output is still compiled. Use `uncompyle6`/`pycdc`, or [applescript-disassembler](https://github.com/Jinmo/applescript-disassembler) with [aevt_decompile](https://github.com/SentineLabs/aevt_decompile).
- Tauri assets are written as `asset_<offset>.<ext>`; original file names aren't recovered, and only text plus common web binary types are kept.
- Encrypted PYZ entries are skipped.
- Not implemented from the talk: the `pyi_main()` check for PyInstaller and the `OpenDefaultComponent('aplt','scpt')` check for osacompile (bundle-level signals are used instead). Standalone compiled scripts that aren't `.app` bundles aren't supported.
- Detection is heuristic. A wrapper can be repackaged to evade it, and a match means "built with this tool", not "malicious".

## Credit

The identification and extraction techniques come from Patrick Wardle's talk and [Objective-See](https://objective-see.org) research.

## License

MIT, see `LICENSE`.
