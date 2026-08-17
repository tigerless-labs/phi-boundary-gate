from __future__ import annotations

import contextlib
import io
import sys
from typing import Sequence

from .cli import main as legacy_main
from .external_cli import main as external_main


_EXTERNAL_COMMAND = "scan-external-trace"


def _merged_help() -> int:
    buffer = io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buffer):
            result = legacy_main(["--help"])
            if isinstance(result, int):
                code = result
    except SystemExit as exc:
        if isinstance(exc.code, int):
            code = exc.code

    legacy_help = buffer.getvalue().rstrip()
    if legacy_help:
        print(legacy_help)
    print()
    print("additional commands:")
    print(
        "  scan-external-trace   Normalize an external JSONL trace and scan "
        "it in one step."
    )
    return code


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if args in (["-h"], ["--help"]):
        return _merged_help()

    if args and args[0] == _EXTERNAL_COMMAND:
        return external_main(args[1:])

    return legacy_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
