"""Guardrail tests (roadmap R0.9).

R0.9's acceptance criterion is stated as a *failure*: "a PR that adds an AI SDK,
a direct socket in `providers/`, or a non-idempotent probe fails CI". So most of
this file plants exactly those three violations and asserts each check reports
them. A guardrail nobody has watched fail is a guardrail nobody should trust —
R0.6 found ruff's ``banned-api`` rule had been silently inert since R0.2, and
three pull requests had claimed it was enforcing.

Two kinds of test here:

* **Positive controls** — plant a violation, assert the check catches it. These
  are the ones that matter.
* **Negative controls** — assert the check passes something legitimate. Equally
  important: a check that fails valid code gets switched off, and one of these
  (``/v1/models`` must be allowed) is what keeps roadmap items R1.1 and R1.2
  possible at all.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from tools.guardrails import ai_ban, network_isolation, no_secrets, read_only
from tools.guardrails.__main__ import CHECKS, main
from tools.guardrails.base import REPO_ROOT, Violation, read_text, repo_files, report

# ---------------------------------------------------------------------------
# The repository itself is clean
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_the_repository_passes_every_guardrail(name: str) -> None:
    assert [violation.render() for violation in CHECKS[name]()] == []


def test_running_every_check_succeeds() -> None:
    assert main([]) == 0


def test_a_single_check_can_be_selected() -> None:
    assert main(["read_only"]) == 0


# ---------------------------------------------------------------------------
# ai_ban — plant an AI SDK
# ---------------------------------------------------------------------------


@pytest.fixture
def planted() -> Iterator[Path]:
    """A file inside the repo tree that the enumerator will pick up.

    Written under `tests/` rather than into `tmp_path` because every check
    resolves paths against `REPO_ROOT` and enumerates through git. Removed
    afterwards, including when the assertion fails.
    """
    path = REPO_ROOT / "tests" / "_planted_guardrail_probe.py"
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def test_ai_ban_catches_an_imported_sdk(planted: Path) -> None:
    planted.write_text("import openai\n", encoding="utf-8")

    violations = ai_ban.check_imports()

    assert any("openai" in v.message for v in violations)


def test_ai_ban_catches_an_sdk_imported_inside_a_function(planted: Path) -> None:
    """A deferred import is still an import — and is how one gets hidden."""
    planted.write_text(
        "def summarise():\n    from anthropic import Anthropic\n    return Anthropic\n",
        encoding="utf-8",
    )

    violations = ai_ban.check_imports()

    assert any("anthropic" in v.message for v in violations)


def test_ai_ban_catches_a_dynamic_import(planted: Path) -> None:
    """`importlib.import_module("openai")` is invisible to an import linter."""
    planted.write_text(
        "import importlib\nmodel = importlib.import_module('openai')\n",
        encoding="utf-8",
    )

    violations = ai_ban.check_imports()

    assert any("openai" in v.message for v in violations)


@pytest.mark.parametrize(
    "endpoint",
    [
        pytest.param("/v1/chat" + "/completions", id="openai-chat"),
        pytest.param("/v1/" + "messages", id="anthropic-messages"),
        pytest.param("/v1/" + "embeddings", id="embeddings"),
        pytest.param(":generate" + "Content", id="gemini-generate"),
    ],
)
def test_ai_ban_catches_an_inference_endpoint(planted: Path, endpoint: str) -> None:
    """Each banned endpoint is written whole into the planted file at run time.

    The parameters are composed from fragments so this test file does not itself
    contain the strings — `ai_ban` exempts only its own module and this one, and
    an exemption that has to grow is a rule that has stopped meaning anything.
    """
    planted.write_text(f"URL = 'https://api.example.invalid{endpoint}'\n", "utf-8")

    violations = [v for v in ai_ban.check_endpoints() if v.path.endswith(planted.name)]

    assert violations, endpoint
    assert "never calls a model" in violations[0].message


def test_ai_ban_allows_a_read_only_capability_probe(planted: Path) -> None:
    """The rule that keeps R1.1 and R1.2 buildable.

    `implementation_plan.md` §11 originally said to grep for "known model API
    hostnames". Enumerating what an exposed OpenAI or Gemini key can reach *is*
    the product, and doing it means naming those hosts. Listing models is a
    capability probe; running one is inference. Only the second is banned.
    """
    planted.write_text(
        "MODELS = 'https://api.openai.com/v1/models'\n"
        "GEMINI = 'https://generativelanguage.googleapis.com/v1beta/models'\n",
        encoding="utf-8",
    )

    violations = [v for v in ai_ban.check_endpoints() if v.path.endswith(planted.name)]

    assert violations == []


@pytest.mark.parametrize(
    "requirement",
    [
        pytest.param("openai>=1.0", id="openai"),
        pytest.param("langchain-community", id="langchain-family"),
        pytest.param("llama-index-core", id="llama-index-family"),
        pytest.param("google-generativeai", id="google"),
        pytest.param("Anthropic == 0.30", id="case-and-spacing"),
    ],
)
def test_ai_ban_rejects_banned_distributions(requirement: str) -> None:
    assert ai_ban._is_banned_distribution(requirement)


@pytest.mark.parametrize(
    "requirement",
    [
        pytest.param("httpx>=0.27,<1.0", id="httpx"),
        pytest.param("pydantic>=2.7", id="pydantic"),
        pytest.param("typer", id="typer"),
        # Not an AI SDK despite the substring; a prefix match without the
        # separator would wrongly reject it.
        pytest.param("torchgeo-unrelated-name", id="prefix-without-separator"),
    ],
)
def test_ai_ban_allows_the_declared_stack(requirement: str) -> None:
    assert not ai_ban._is_banned_distribution(requirement)


def test_ai_ban_reads_every_dependency_group() -> None:
    """Both runtime and dev. An SDK in `[dev]` is still an SDK in the repo."""
    assert ai_ban.check_dependencies() == []


# ---------------------------------------------------------------------------
# network_isolation — plant a direct socket in a provider
# ---------------------------------------------------------------------------


@pytest.fixture
def planted_provider() -> Iterator[Path]:
    """A file under `keyreach/providers/`, where the rule actually applies."""
    path = REPO_ROOT / "keyreach" / "providers" / "_planted_probe.py"
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("import httpx\n", id="httpx"),
        pytest.param("import socket\n", id="socket"),
        pytest.param("import requests\n", id="requests"),
        pytest.param("from urllib.request import urlopen\n", id="urllib"),
        pytest.param("import aiohttp\n", id="aiohttp"),
        pytest.param(
            "def probe():\n    import httpx\n    return httpx\n",
            id="deferred-import",
        ),
        pytest.param(
            "import importlib\nc = importlib.import_module('httpx')\n",
            id="dynamic-import",
        ),
    ],
)
def test_network_isolation_catches_a_direct_client(
    planted_provider: Path, source: str
) -> None:
    planted_provider.write_text(source, encoding="utf-8")

    violations = network_isolation.check()

    assert any(v.path.endswith("_planted_probe.py") for v in violations)


def test_network_isolation_allows_probe_context(planted_provider: Path) -> None:
    planted_provider.write_text(
        "from keyreach.core.provider import ProbeContext, Provider\n",
        encoding="utf-8",
    )

    assert network_isolation.check() == []


def test_network_isolation_holds_test_fixtures_to_the_same_rule() -> None:
    """A fixture allowed to do what a plugin may not stops proving anything."""
    guarded = network_isolation.GUARDED_PREFIXES

    assert "keyreach/providers/" in guarded
    assert "tests/cassette_providers/" in guarded


def test_network_isolation_catches_what_ruff_cannot(
    planted_provider: Path,
) -> None:
    """Independence, demonstrated rather than asserted about the source text.

    R0.6 found ruff's `banned-api` block had been inert since R0.2 because `TID`
    was missing from `select`, and three pull requests had claimed it was
    enforcing. Two mechanisms that share an implementation share its failure.

    A dynamic import is the cleanest proof the two are genuinely separate: ruff
    matches import *statements*, so `importlib.import_module("httpx")` passes it
    cleanly. This check resolves the string and rejects it.
    """
    planted_provider.write_text(
        "import importlib\nclient = importlib.import_module('httpx')\n",
        encoding="utf-8",
    )

    ruff = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--isolated",
            "--select",
            "TID251",
            "--config",
            'lint.flake8-tidy-imports.banned-api = {"httpx" = {msg = "no"}}',
            str(planted_provider),
        ],
        capture_output=True,
        text=True,
        # The whole point is to observe ruff's exit code, not to inherit it.
        check=False,
        cwd=REPO_ROOT,
    )

    assert ruff.returncode == 0, f"ruff unexpectedly caught it:\n{ruff.stdout}"
    assert any(v.path.endswith("_planted_probe.py") for v in network_isolation.check())


# ---------------------------------------------------------------------------
# read_only — plant a non-idempotent probe
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param("async def p(ctx):\n    await ctx.delete('/x')\n", "delete"),
        pytest.param("async def p(ctx):\n    await ctx.put('/x')\n", "put"),
        pytest.param("async def p(ctx):\n    await ctx.patch('/x')\n", "patch"),
        pytest.param("async def p(ctx):\n    await ctx.post('/x')\n", "post"),
        pytest.param(
            "async def p(ctx):\n    await ctx.request('GET', '/x')\n", "request"
        ),
    ],
)
def test_read_only_catches_a_non_idempotent_probe(
    planted_provider: Path, source: str, expected: str
) -> None:
    planted_provider.write_text(source, encoding="utf-8")

    violations = read_only.check()

    assert any(expected in v.message for v in violations)


def test_read_only_allows_an_annotated_post(planted_provider: Path) -> None:
    """Some RPC-style APIs answer *read* queries only over POST.

    The annotation is verbose and greppable on purpose, so every use is argued
    in review rather than waved through.
    """
    planted_provider.write_text(
        "async def p(ctx):\n    await ctx.post('/rpc', read_only_post=True)\n",
        encoding="utf-8",
    )

    assert read_only.check() == []


def test_read_only_rejects_a_falsely_annotated_post(planted_provider: Path) -> None:
    """`read_only_post=False` is not an annotation, it is a write."""
    planted_provider.write_text(
        "async def p(ctx):\n    await ctx.post('/rpc', read_only_post=False)\n",
        encoding="utf-8",
    )

    assert read_only.check() != []


def test_read_only_allows_idempotent_probes(planted_provider: Path) -> None:
    planted_provider.write_text(
        "async def p(ctx):\n" "    await ctx.get('/a')\n" "    await ctx.head('/b')\n",
        encoding="utf-8",
    )

    assert read_only.check() == []


def test_read_only_checks_declarative_probes(planted_provider: Path) -> None:
    """`implementation_plan.md` §8 probes are YAML, so AST scanning misses them."""
    path = planted_provider.with_suffix(".yml")
    path.write_text("service: X\nprobes:\n  - method: DELETE\n    path: /x\n", "utf-8")
    try:
        violations = read_only.check()

        assert any("DELETE" in v.message for v in violations)
    finally:
        path.unlink(missing_ok=True)


def test_read_only_allows_idempotent_declarative_probes(
    planted_provider: Path,
) -> None:
    path = planted_provider.with_suffix(".yml")
    path.write_text("service: X\nprobes:\n  - method: GET\n    path: /x\n", "utf-8")
    try:
        assert read_only.check() == []
    finally:
        path.unlink(missing_ok=True)


def test_read_only_does_not_police_the_http_layer() -> None:
    """`core/http.py` names every method because it implements the denial."""
    guarded = read_only.guarded_files()

    assert "keyreach/core/http.py" not in guarded


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def test_repo_files_can_filter_by_suffix() -> None:
    python_files = repo_files(suffixes=(".py",))

    assert python_files
    assert all(path.endswith(".py") for path in python_files)


def test_repo_files_are_sorted() -> None:
    """So a failure lists violations in the same order on every machine."""
    paths = repo_files()

    assert paths == sorted(paths)


def test_read_text_returns_none_for_a_missing_file() -> None:
    """A guardrail that crashes on an odd file is one people switch off."""
    assert read_text("does/not/exist.py") is None


def test_violation_renders_a_clickable_location() -> None:
    assert Violation("a.py", 7, "bad").render() == "a.py:7: bad"


@pytest.mark.parametrize("suffix", [".py", ".yml"], ids=["python", "declarative"])
def test_every_check_skips_an_undecodable_file(
    planted_provider: Path, suffix: str
) -> None:
    """A corrupt or binary file must not take the whole pipeline down.

    Planted under `keyreach/providers/` so it lands in the scan set of every
    check at once, in both the Python and the declarative-probe paths.
    """
    path = planted_provider.with_suffix(suffix)
    path.write_bytes(b"\xfe\xff\x00 not valid utf-8 \xff")
    try:
        assert read_text(f"keyreach/providers/_planted_probe{suffix}") is None
        for check in CHECKS.values():
            assert check() == []
    finally:
        path.unlink(missing_ok=True)


def test_a_dynamic_import_of_a_non_string_is_ignored(planted: Path) -> None:
    """`import_module(name)` with a computed argument cannot be resolved here.

    Silently ignoring it is correct — guessing would produce false positives —
    but it is a real limit, so it is recorded rather than left implicit.
    """
    planted.write_text(
        "import importlib\nMOD = 123\nc = importlib.import_module(MOD)\n"
        "d = importlib.import_module(456)\n",
        encoding="utf-8",
    )

    assert ai_ban.check_imports() == []


@pytest.mark.parametrize(
    "module",
    [ai_ban, network_isolation, read_only, no_secrets],
    ids=["ai_ban", "network_isolation", "read_only", "no_secrets"],
)
def test_each_check_has_a_working_entrypoint(module: ModuleType) -> None:
    """Each runs standalone, so CI can name the failing rule in the job title."""
    assert module.main() == 0


def test_report_is_quiet_on_success(capsys: pytest.CaptureFixture[str]) -> None:
    assert report("demo", []) == 0
    assert capsys.readouterr().out == "demo: ok\n"


def test_report_annotates_each_violation(capsys: pytest.CaptureFixture[str]) -> None:
    """GitHub's annotation format, so a failure lands on the line in the diff."""
    code = report("demo", [Violation("a.py", 7, "bad")])
    out = capsys.readouterr().out

    assert code == 1
    assert "::error file=a.py,line=7::bad" in out
    assert "1 violation" in out


def test_report_pluralises(capsys: pytest.CaptureFixture[str]) -> None:
    report("demo", [Violation("a.py", 1, "x"), Violation("b.py", 2, "y")])

    assert "2 violations" in capsys.readouterr().out
