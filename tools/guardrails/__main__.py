"""Run every guardrail, or one by name.

    python -m tools.guardrails                    # all of them
    python -m tools.guardrails read_only          # just one

Every check runs even when an earlier one fails, so a contributor sees the whole
picture in a single run rather than fixing one violation to discover the next.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from tools.guardrails import ai_ban, network_isolation, no_secrets, read_only
from tools.guardrails.base import Violation, report

CHECKS: dict[str, Callable[[], list[Violation]]] = {
    "ai_ban": ai_ban.check,
    "network_isolation": network_isolation.check,
    "read_only": read_only.check,
    "no_secrets": no_secrets.check,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.guardrails")
    parser.add_argument(
        "checks",
        nargs="*",
        choices=[*CHECKS, []],
        help="Checks to run. Default: all of them.",
    )
    args = parser.parse_args(argv)
    selected = args.checks or list(CHECKS)

    failed = 0
    for name in selected:
        failed |= report(name, CHECKS[name]())
    return failed


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
