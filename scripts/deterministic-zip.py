#!/usr/bin/env python3
"""Writes a zip whose bytes depend only on the files it holds.

    deterministic-zip.py <out.zip> <dir>

Entries are the regular files under <dir>, relative to it, in byte order of
their path. Every entry gets the same timestamp (SOURCE_DATE_EPOCH, required,
in UTC), mode 0644 (0755 when the owner can execute the file), no directory
entries, no extra fields, and deflate at level 9. Two runs on the same tree
with the same Python and zlib give the same bytes. Symbolic links are
refused: a release archive has no reason to carry one.
"""

import os
import stat
import sys
import time
import zipfile


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: deterministic-zip.py <out.zip> <dir>", file=sys.stderr)
        return 64
    out, root = sys.argv[1], sys.argv[2]
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch or not epoch.isdigit():
        print("SOURCE_DATE_EPOCH must be set to a Unix time", file=sys.stderr)
        return 64
    # The zip format cannot store a date before 1980.
    stamp = time.gmtime(max(int(epoch), 315532800))[:6]

    paths = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                print(f"refusing a symbolic link: {full}", file=sys.stderr)
                return 1
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            paths.append((rel.encode("utf-8"), rel, full))
    if not paths:
        print(f"no files under {root}", file=sys.stderr)
        return 1
    paths.sort()

    tmp = out + ".tmp"
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for _, rel, full in paths:
            mode = 0o755 if os.stat(full).st_mode & stat.S_IXUSR else 0o644
            info = zipfile.ZipInfo(rel, date_time=stamp)
            info.create_system = 3  # Unix, so the mode below is honoured
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as f:
                zf.writestr(info, f.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    os.replace(tmp, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
