#!/usr/bin/env python3
import sys
from typing import List

from warnings import warn

warn(
    "The file prof.py will be removed in 2023. It was probably introduced for "
    "testing purposes a long time ago, and no longer relevant. Feel free to create a "
    "GitHub issue if you disagree.",
    DeprecationWarning,
)


def prof_main(argv: List[str]) -> int:
    import hotshot.stats  # type: ignore[import]

    def usage() -> int:
        print("usage: %s module.function [args ...]" % argv[0])
        return 100

    args = argv[1:]
    if len(args) < 1:
        return usage()
    name = args.pop(0)
    prof = name + ".prof"
    i = name.rindex(".")
    (modname, funcname) = (name[:i], name[i + 1 :])

    # Type error: fromlist expects sequence of strings; presumably the intent
    # is to retrieve the named module rather than a top-level package (as in
    # "when a non-empty fromlist argument is given...").
    module = __import__(modname, fromlist=1)  # type: ignore[arg-type]

    func = getattr(module, funcname)
    if args:
        args.insert(0, argv[0])
        profile = hotshot.Profile(prof)
        profile.runcall(lambda: func(args))
        profile.close()
    else:
        stats = hotshot.stats.load(prof)
        stats.strip_dirs()
        stats.sort_stats("time", "calls")
        stats.print_stats(1000)
    return 0


if __name__ == "__main__":
    sys.exit(prof_main(sys.argv))
