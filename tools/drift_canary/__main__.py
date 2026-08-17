"""Run the drift canary: detection-rule sources, then declarative probe endpoints.

    python -m tools.drift_canary

Prints ``drift-canary: ok`` and exits 0 when nothing has drifted. Otherwise
prints a Markdown report to stdout and exits 1, so
``.github/workflows/drift-canary.yml`` can tell whether anything needs an
issue purely from the exit code, and reuse the same stdout as the issue body
without a second run.
"""

from __future__ import annotations

from tools.drift_canary import endpoints, sources
from tools.drift_canary.base import Finding, live_fetch


def render(findings: list[Finding]) -> str:
    plural = "" if len(findings) == 1 else "s"
    lines = [f"## keyreach drift-canary: {len(findings)} finding{plural}", ""]
    lines.extend(finding.render() for finding in findings)
    return "\n".join(lines)


def main() -> int:
    findings = [*sources.check(live_fetch), *endpoints.check(live_fetch)]

    if not findings:
        print("drift-canary: ok")  # noqa: T201 - CLI output, not a log
        return 0

    print(render(findings))  # noqa: T201 - CLI output, not a log
    return 1


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
