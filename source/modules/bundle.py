import os
import plistlib


class Bundle:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.contents = os.path.join(self.path, "Contents")
        self.resources = os.path.join(self.contents, "Resources")
        self.info = self._load_plist(os.path.join(self.contents, "Info.plist"))
        name = self.info.get("CFBundleExecutable")
        self.executable = os.path.join(self.contents, "MacOS", name) if name else None

    def _load_plist(self, plist_path):
        try:
            with open(plist_path, "rb") as f:
                return plistlib.load(f)
        except (OSError, plistlib.InvalidFileException, ValueError):
            return {}

    def load_resource_plist(self, name):
        return self._load_plist(os.path.join(self.resources, name))

    def has(self, *relative):
        return os.path.exists(os.path.join(self.contents, *relative))

    def is_app(self):
        return os.path.isdir(self.contents) and bool(self.info)
