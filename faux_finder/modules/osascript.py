import os
import shutil
import subprocess

name = "AppleScript (osacompile)"

SCPT_MAGIC = b"FasdUAS"


def script_path(bundle):
    return os.path.join(bundle.resources, "Scripts", "main.scpt")


def detect(bundle):
    evidence = []
    if bundle.info.get("CFBundleSignature") == "aplt":
        evidence.append("CFBundleSignature is 'aplt'")
    if bundle.executable and os.path.basename(bundle.executable) == "applet":
        evidence.append("executable is the stock 'applet' stub")
    path = script_path(bundle)
    if os.path.isfile(path):
        evidence.append("Contents/Resources/Scripts/main.scpt exists")
        with open(path, "rb") as f:
            if f.read(len(SCPT_MAGIC)) == SCPT_MAGIC:
                evidence.append("main.scpt is a compiled AppleScript (FasdUAS)")
    return evidence if len(evidence) >= 2 else []


def extract(bundle, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    compiled = os.path.join(out_dir, "main.scpt")
    shutil.copyfile(script_path(bundle), compiled)
    written = [compiled]

    result = subprocess.run(["osadecompile", compiled], capture_output=True, text=True)
    if result.returncode == 0:
        source = os.path.join(out_dir, "main.applescript")
        with open(source, "w") as f:
            f.write(result.stdout)
        written.append(source)
    else:
        print("osadecompile failed (run-only script?): " + result.stderr.strip())
    return written
