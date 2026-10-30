import mmap
import os
import subprocess

import modules.macho as macho

try:
    import brotli
except ImportError:
    brotli = None

name = "Tauri"

STRINGS = [b"error while running tauri application", b"tauri.conf.json", b"__TAURI__", b"tauri://", b"Tauri App"]

# sections that hold include_bytes!() data; everything else is only scanned as a fallback
DATA_SECTIONS = {"__const", "__data", "__rodata"}
MIN_OUTPUT = 16
# the brotli crate embeds its 122,784 byte static dictionary; its words decode as bogus streams
DICTIONARY_START = b"timedownlifeleftbackcodedatashowonlysite"
DICTIONARY_SIZE = 122784
MAGICS = {
    b"\x89PNG\r\n\x1a\n": ".png", b"GIF87a": ".gif", b"GIF89a": ".gif", b"\x00asm\x01\x00\x00\x00": ".wasm",
    b"wOF2": ".woff2", b"wOFF": ".woff", b"\xff\xd8\xff\xe0": ".jpg", b"\xff\xd8\xff\xe1": ".jpg",
}


def attributes(path):
    """Non-system extended attributes of a file, as {name: bytes}."""
    listing = subprocess.run(["xattr", path], capture_output=True, text=True)
    result = {}
    for attribute in listing.stdout.splitlines():
        if attribute.startswith("com.apple."):
            continue
        value = subprocess.run(["xattr", "-px", attribute, path], capture_output=True, text=True)
        if value.returncode == 0:
            result[attribute] = bytes.fromhex(value.stdout.replace("\n", "").replace(" ", ""))
    return result


def detect(bundle):
    if not bundle.executable or not os.path.isfile(bundle.executable):
        return []
    found = macho.contains(bundle.executable, *STRINGS)
    # one stray string (e.g. in an editor that mentions tauri.conf.json) isn't enough
    if len(found) < 2 and STRINGS[0] not in found:
        return []
    evidence = ["binary contains " + s.decode() for s in found]
    for attribute, value in attributes(bundle.executable).items():
        evidence.append("binary has extended attribute '" + attribute + "' (" + str(len(value)) + " bytes)")
    return evidence


def decodes(data, offset, size):
    """Prefix of data[offset:] decodes without error; also returns whether the stream ended."""
    decoder = brotli.Decompressor()
    try:
        out = decoder.process(bytes(data[offset:offset + size]))
    except brotli.error:
        return None, False
    return out, decoder.is_finished()


def stream_at(data, offset, limit):
    """Decode a complete brotli stream starting at offset: (output, length) or None.

    Brotli has no magic, and the decoder errors on bytes after the end of a stream, so the
    end is found by growing the prefix until it errors, then bisecting back to the last good size.
    """
    size = 16
    good = 0
    while size <= limit:
        out, finished = decodes(data, offset, size)
        if out is None:
            break
        if finished:
            return out, size
        good = size
        size *= 2
    else:
        return None
    low, high = good, min(size, limit)    # low decodes, high errors
    if low == 0:
        # shorter than 16 bytes in total: too small to be an asset
        return None
    while high - low > 1:
        middle = (low + high) // 2
        out, finished = decodes(data, offset, middle)
        if out is None:
            high = middle
        else:
            low = middle
    out, finished = decodes(data, offset, low)
    return (out, low) if finished else None


def extension(output):
    for magic, ext in MAGICS.items():
        if output.startswith(magic):
            return ext
    text = output[:512]
    bad = sum(1 for b in text if b < 9 or 13 < b < 32 or b == 127)
    if bad > len(text) // 100:
        return None
    lowered = text.lstrip().lower()
    if lowered.startswith((b"<!doctype", b"<html")):
        return ".html"
    if lowered.startswith((b"{", b"[")):
        return ".json"
    return ".js"


def scan(data, ranges):
    streams = []
    for start, end in ranges:
        offset = start
        while offset < end - MIN_OUTPUT:
            found = stream_at(data, offset, end - offset)
            if found and len(found[0]) >= MIN_OUTPUT and extension(found[0]):
                streams.append((offset, found[0]))
                offset += found[1]
            else:
                offset += 1
    return streams


def without_dictionary(data, ranges):
    skip = data.find(DICTIONARY_START)
    if skip == -1:
        return ranges
    kept = []
    for start, end in ranges:
        if start < skip + DICTIONARY_SIZE and skip < end:
            kept += [(start, skip), (skip + DICTIONARY_SIZE, end)]
        else:
            kept.append((start, end))
    return [(start, end) for start, end in kept if start < end]


def assets(path):
    """Brotli-compressed assets in the executable: [(offset, bytes)]."""
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        ranges = [(offset, offset + size) for segment, section, offset, size in macho.sections(path)
                  if section in DATA_SECTIONS]
        streams = scan(data, without_dictionary(data, ranges))
        if not streams:
            streams = scan(data, without_dictionary(data, [(0, len(data))]))
        return streams


def extract(bundle, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for attribute, value in attributes(bundle.executable).items():
        destination = os.path.join(out_dir, "xattr_" + attribute.replace("/", "_"))
        with open(destination, "wb") as f:
            f.write(value)
        written.append(destination)
    if brotli is None:
        print("note: install the 'brotli' package to extract the embedded frontend assets")
        return written
    for offset, output in assets(bundle.executable):
        destination = os.path.join(out_dir, "asset_" + format(offset, "x") + extension(output))
        with open(destination, "wb") as f:
            f.write(output)
        written.append(destination)
    return written
