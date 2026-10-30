import os
import shutil

import modules.macho as macho

name = "Platypus"


def detect(bundle):
    """Return a list of evidence strings; empty if this isn't a Platypus app."""
    evidence = []
    if bundle.has("Resources", "script"):
        evidence.append("Contents/Resources/script exists")

    settings = bundle.load_resource_plist("AppSettings.plist")
    creator = str(settings.get("Creator", ""))
    if "Platypus" in creator:
        evidence.append("AppSettings.plist Creator: " + creator)
    for key, value in settings.items():
        if "interpreter" in key.lower():
            evidence.append("AppSettings.plist " + key + ": " + str(value))

    if bundle.executable and macho.contains(bundle.executable, b"ScriptExec"):
        evidence.append("binary contains ScriptExec* classes")

    # the script alone is too generic (it's just a file name): require a second signal
    signals = [e for e in evidence if not e.startswith("AppSettings.plist Interpreter")]
    return evidence if len(signals) >= 2 else []


def extract(bundle, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    source = os.path.join(bundle.resources, "script")
    destination = os.path.join(out_dir, "script")
    shutil.copyfile(source, destination)
    return [destination]
