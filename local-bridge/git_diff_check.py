"""Run a protected whitespace check without opening bridge-blocked files."""
import os
from pathlib import Path
import subprocess
import sys

from files import BLOCKED_DIRECTORIES, BLOCKED_SUFFIXES, SECRET_NAMES, SECRET_PREFIXES


GIT = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
       "-c", "core.hooksPath=" + os.devnull, "-c", "core.pager=cat"]


def blocked(path):
    parts = [part.casefold() for part in Path(path).parts]
    return any(part in BLOCKED_DIRECTORIES or part in SECRET_NAMES or part.startswith(SECRET_PREFIXES)
               or Path(part).suffix in BLOCKED_SUFFIXES for part in parts)


def run(args):
    return subprocess.run(GIT + args, capture_output=True, cwd=Path.cwd())


def main():
    listing = run(["ls-files", "--cached", "-z", "--"])
    if listing.returncode:
        sys.stderr.buffer.write(listing.stderr)
        return listing.returncode
    paths = [raw.decode("utf-8", "surrogateescape") for raw in listing.stdout.split(b"\0") if raw]
    paths = [path for path in paths if not blocked(path)]
    for start in range(0, len(paths), 500):
        result = run(["diff", "--check", "--no-ext-diff", "--no-textconv", "--no-renames", "--",
                      *paths[start:start + 500]])
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
