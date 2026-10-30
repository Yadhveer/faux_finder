import json
import os
import shutil
import struct

import modules.macho as macho

name = "Electron"


def detect(bundle):
    evidence = []
    if bundle.executable:
        for lib in macho.dylibs(bundle.executable):
            if "Electron Framework" in lib:
                evidence.append("links " + lib)
    if bundle.has("Frameworks", "Electron Framework.framework"):
        evidence.append("Contents/Frameworks/Electron Framework.framework exists")
    if not evidence:
        return []
    if bundle.has("Resources", "app.asar"):
        evidence.append("Contents/Resources/app.asar exists")
    elif bundle.has("Resources", "app"):
        evidence.append("Contents/Resources/app/ exists (unpacked)")
    return evidence


def read_header(f):
    """Parse an ASAR header: a Chromium pickle holding a JSON file tree."""
    prefix = f.read(16)
    if len(prefix) < 16:
        raise ValueError("not an asar archive")
    header_size = struct.unpack("<I", prefix[4:8])[0]
    json_size = struct.unpack("<I", prefix[12:16])[0]
    tree = json.loads(f.read(json_size))
    return tree, 8 + header_size


def safe_join(root, relative):
    target = os.path.realpath(os.path.join(root, relative))
    if not target.startswith(os.path.realpath(root) + os.sep):
        raise ValueError("asar entry escapes output directory: " + relative)
    return target


def unpack(asar_path, out_dir):
    written = []
    unpacked_dir = asar_path + ".unpacked"
    with open(asar_path, "rb") as f:
        tree, base = read_header(f)

        def walk(node, relative):
            for entry, meta in node.get("files", {}).items():
                path = os.path.join(relative, entry)
                if "files" in meta:
                    walk(meta, path)
                    continue
                if "link" in meta:
                    continue
                target = safe_join(out_dir, path)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                if meta.get("unpacked"):
                    shutil.copyfile(os.path.join(unpacked_dir, path), target)
                else:
                    f.seek(base + int(meta["offset"]))
                    with open(target, "wb") as out:
                        out.write(f.read(meta["size"]))
                written.append(target)

        walk(tree, "")
    return written


def extract(bundle, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    asar_path = os.path.join(bundle.resources, "app.asar")
    if os.path.isfile(asar_path):
        return unpack(asar_path, out_dir)
    app_dir = os.path.join(bundle.resources, "app")
    if os.path.isdir(app_dir):
        shutil.copytree(app_dir, out_dir, dirs_exist_ok=True)
        return [os.path.join(out_dir, p) for p in os.listdir(out_dir)]
    raise FileNotFoundError("no app.asar or app/ directory in Contents/Resources")
