import mmap
import struct

FAT_MAGIC = 0xcafebabe
FAT_MAGIC_64 = 0xcafebabf
MH_MAGIC = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf

LC_SEGMENT_64 = 0x19

DYLIB_COMMANDS = {0xc, 0x80000018, 0x8000001f, 0x80000023}


def slices(data):
    """Yield the (offset) of every Mach-O image in a thin or fat file."""
    if len(data) < 8:
        return
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack(">I", data[4:8])[0]
        size = 20 if magic == FAT_MAGIC else 32
        for i in range(min(count, 64)):
            entry = data[8 + i * size: 8 + (i + 1) * size]
            if magic == FAT_MAGIC:
                offset = struct.unpack(">I", entry[8:12])[0]
            else:
                offset = struct.unpack(">Q", entry[8:16])[0]
            yield offset
    elif struct.unpack("<I", data[:4])[0] in (MH_MAGIC, MH_MAGIC_64):
        yield 0


def slice_ranges(data):
    """(start, end) of every Mach-O image; a non-fat file is one range."""
    starts = sorted(slices(data))
    if not starts:
        return [(0, len(data))]
    return [(start, starts[i + 1] if i + 1 < len(starts) else len(data))
            for i, start in enumerate(starts)]


def dylibs(path):
    """Names of the libraries/frameworks a Mach-O links against (all architectures)."""
    names = []
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for base in slices(data):
                magic = struct.unpack("<I", data[base:base + 4])[0]
                if magic not in (MH_MAGIC, MH_MAGIC_64):
                    continue
                header = 32 if magic == MH_MAGIC_64 else 28
                ncmds = struct.unpack("<I", data[base + 16:base + 20])[0]
                pos = base + header
                for _ in range(ncmds):
                    cmd, cmdsize = struct.unpack("<II", data[pos:pos + 8])
                    if cmdsize < 8:
                        break
                    if cmd in DYLIB_COMMANDS:
                        name_offset = struct.unpack("<I", data[pos + 8:pos + 12])[0]
                        raw = data[pos + name_offset:pos + cmdsize]
                        name = raw.split(b"\x00")[0].decode("utf-8", "replace")
                        if name not in names:
                            names.append(name)
                    pos += cmdsize
    except (OSError, ValueError, struct.error):
        pass
    return names


def contains(path, *needles):
    """Needles (bytes) that appear anywhere in the file."""
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return [n for n in needles if data.find(n) != -1]
    except (OSError, ValueError):
        return []


def sections(path):
    """(segment, section, file_offset, size) of every 64-bit section, across all slices."""
    found = []
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for base in slices(data):
                if struct.unpack("<I", data[base:base + 4])[0] != MH_MAGIC_64:
                    continue
                ncmds = struct.unpack("<I", data[base + 16:base + 20])[0]
                pos = base + 32
                for _ in range(ncmds):
                    cmd, cmdsize = struct.unpack("<II", data[pos:pos + 8])
                    if cmdsize < 8:
                        break
                    if cmd == LC_SEGMENT_64:
                        nsects = struct.unpack("<I", data[pos + 64:pos + 68])[0]
                        for i in range(nsects):
                            sect = pos + 72 + i * 80
                            sectname = data[sect:sect + 16].split(b"\x00")[0].decode()
                            segname = data[sect + 16:sect + 32].split(b"\x00")[0].decode()
                            size = struct.unpack("<Q", data[sect + 40:sect + 48])[0]
                            offset = struct.unpack("<I", data[sect + 48:sect + 52])[0]
                            if offset:
                                found.append((segname, sectname, base + offset, size))
                    pos += cmdsize
    except (OSError, ValueError, struct.error):
        pass
    return found
