import argparse
import os
import sys

import modules.bundle as bundle_module
import modules.platypus as platypus
import modules.electron as electron
import modules.osascript as osascript
import modules.pyinstaller as pyinstaller
import modules.tauri as tauri

WRAPPERS = [platypus, electron, osascript, pyinstaller, tauri]


def build_parser():
    parser = argparse.ArgumentParser(
        prog= "faux_finder",
        description= "detect and extract faux scripts posing as Mach-O apps"
    )
    parser.add_argument("path",
                        help="specify the path of the .app bundle to check")
    parser.add_argument("-o", "--output", action="store", type=str,
                        help="specify the directory to extract the script(s) to")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        parser.exit(2, message="The target does not exist in the path specified\n")

    app = bundle_module.Bundle(args.path)
    if not app.is_app():
        parser.exit(2, message="The target is not an app bundle (no Contents/Info.plist)\n")

    matches = []
    for wrapper in WRAPPERS:
        evidence = wrapper.detect(app)
        if evidence:
            matches.append((wrapper, evidence))

    if not matches:
        print("No known script wrapper detected")
        return 1

    for wrapper, evidence in matches:
        print("Application is a faux app created using " + wrapper.name)
        for line in evidence:
            print("  - " + line)

    if args.output:
        for wrapper, _ in matches:
            out_dir = os.path.join(args.output, wrapper.__name__.split(".")[-1])
            try:
                written = wrapper.extract(app, out_dir)
            except Exception as e:
                print("Extraction failed for " + wrapper.name + ": " + repr(e), file=sys.stderr)
                return 2
            print("Extracted " + str(len(written)) + " file(s) to " + out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
