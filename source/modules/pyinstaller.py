import marshal
import mmap
import os
import struct
import zlib

import modules.macho as macho

name = "PyInstaller"

COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_SIZE = 24        # magic, package length, TOC offset, TOC length, python version
COOKIE_SIZE_V21 = 88    # ...followed by the python library name
STRINGS = [b"PYINSTALLER_", b"pyi-", b"pyi-runtime-tmpdir", b"Error detected starting Python VM", b"PYI-%d"]

# pyc magic numbers by python version (major * 100 + minor)
PYC_MAGIC = {308: 3413, 309: 3425, 310: 3439, 311: 3495, 312: 3531, 313: 3571, 314: 3627}


def find_cookie(data):
    """Locate the CArchive cookie; returns (slice_start, slice_end, cookie_pos) or None."""
    for start, end in macho.slice_ranges(data):
        pos = data.rfind(COOKIE_MAGIC, start, end)
        if pos != -1:
            return start, end, pos
    return None


def detect(bundle):
    if not bundle.executable or not os.path.isfile(bundle.executable):
        return []
    evidence = []
    with open(bundle.executable, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if find_cookie(data):
            evidence.append("PyInstaller archive cookie (MEI) found in the binary")
    if not evidence:
        return []
    evidence += ["binary contains " + s.decode() for s in macho.contains(bundle.executable, *STRINGS)]
    return evidence


def read_cookie(data, cookie_pos, end):
    magic, pkg_len, toc_offset, toc_len, pyvers = struct.unpack("!8sIIii", data[cookie_pos:cookie_pos + COOKIE_SIZE])
    has_libname = b"python" in data[cookie_pos + COOKIE_SIZE:cookie_pos + COOKIE_SIZE_V21].lower()
    cookie_size = COOKIE_SIZE_V21 if has_libname else COOKIE_SIZE
    # anything after the cookie (e.g. a code signature) is not counted in pkg_len's tail
    overlay_end_trim = end - (cookie_pos + cookie_size)
    overlay_start = end - (pkg_len + overlay_end_trim)
    return overlay_start, toc_offset, toc_len, pyvers


def read_toc(data, overlay_start, toc_offset, toc_len):
    entries = []
    pos = overlay_start + toc_offset
    stop = pos + toc_len
    while pos < stop:
        entry_len, entry_pos, packed, unpacked, compressed, type_code = struct.unpack("!iIIIBc", data[pos:pos + 18])
        entry_name = data[pos + 18:pos + entry_len].split(b"\x00")[0].decode("utf-8", "replace")
        entries.append((entry_name, entry_pos, packed, unpacked, compressed, type_code.decode("latin-1")))
        pos += entry_len
    return entries


def pyc_header(pyvers):
    version = pyvers if pyvers >= 100 else pyvers // 10 * 100 + pyvers % 10
    magic = struct.pack("<H", PYC_MAGIC.get(version, 0)) + b"\r\n"
    return magic + b"\x00" * 12


def safe_path(root, relative):
    target = os.path.realpath(os.path.join(root, relative.lstrip("/")))
    if not target.startswith(os.path.realpath(root) + os.sep):
        raise ValueError("archive entry escapes output directory: " + relative)
    return target


def write(root, relative, content):
    target = safe_path(root, relative)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as f:
        f.write(content)
    return target


def unpack_pyz(blob, out_dir, header):
    """PYZ: 'PYZ\\0', pyc magic, TOC offset, then zlib-compressed code objects."""
    written = []
    toc_offset = struct.unpack("!i", blob[8:12])[0]
    toc = marshal.loads(blob[toc_offset:])
    if isinstance(toc, list):
        toc = dict(toc)
    for module, (ispkg, offset, length) in toc.items():
        try:
            code = zlib.decompress(blob[offset:offset + length])
        except zlib.error:
            continue    # encrypted or corrupt entry
        relative = module.replace(".", "/")
        relative += "/__init__.pyc" if ispkg else ".pyc"
        written.append(write(out_dir, relative, header + code))
    return written


def extract(bundle, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    with open(bundle.executable, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        start, end, cookie_pos = find_cookie(data)
        overlay_start, toc_offset, toc_len, pyvers = read_cookie(data, cookie_pos, end)
        header = pyc_header(pyvers)
        for entry_name, entry_pos, packed, unpacked, compressed, type_code in read_toc(data, overlay_start, toc_offset, toc_len):
            blob = bytes(data[overlay_start + entry_pos:overlay_start + entry_pos + packed])
            if compressed:
                blob = zlib.decompress(blob)
            if type_code == "z" or type_code == "Z":
                written += unpack_pyz(blob, os.path.join(out_dir, entry_name + "_extracted"), header)
                written.append(write(out_dir, entry_name, blob))
            elif type_code == "s":
                # entry-point script: a bare marshalled code object, needs a pyc header to be loadable
                written.append(write(out_dir, entry_name + ".pyc", header + blob))
            elif type_code in ("m", "M"):
                written.append(write(out_dir, entry_name + ".pyc", header + blob))
            elif type_code in ("b", "x", "d", "l"):
                written.append(write(out_dir, entry_name, blob))
            # 'o' (runtime options) carry no data
    return written
