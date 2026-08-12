"""Packaging-metadata guards (roadmap R0.2).

R0.2's acceptance criterion is "``pyproject.toml`` (Apache-2.0, Python 3.11+,
deps per ``implementation_plan.md`` §1, **no AI/LLM deps**)". These tests assert
exactly that, so the claim is checked rather than asserted in a README.

Scope note: this is *not* the ``ai_ban`` guardrail. That one — roadmap item
**R0.9**, ``implementation_plan.md`` §11 — greps source and the resolved
dependency tree for AI/LLM SDK imports and model API hostnames, and fails CI.
What follows is the much narrower check that belongs to R0.2: nothing in the
*declared* dependencies is an AI/LLM SDK.
"""

from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"

# Distribution names of AI/LLM SDKs and model-access clients. Adding any of
# these to keyreach is not a judgement call — it is banned outright, because
# keyreach handles live secrets and every verdict must trace to a rule rather
# than to a model (plan.md §1, CLAUDE.md hard rule #1).
#
# Not exhaustive, and not meant to be: R0.9 replaces this with a maintained
# denylist plus a source scan. Keep names PEP 503 normalized (lowercase, with
# runs of `-`, `_` and `.` collapsed to a single `-`).
AI_SDK_DENYLIST = frozenset(
    {
        "ai21",
        "anthropic",
        "boto3-bedrock",
        "cohere",
        "dspy",
        "dspy-ai",
        "google-cloud-aiplatform",
        "google-genai",
        "google-generativeai",
        "groq",
        "guidance",
        "huggingface-hub",
        "instructor",
        "langchain",
        "langchain-core",
        "litellm",
        "llama-cpp-python",
        "llama-index",
        "mistralai",
        "ollama",
        "openai",
        "replicate",
        "sentence-transformers",
        "tiktoken",
        "together",
        "transformers",
        "vertexai",
        "vllm",
    }
)


def _normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


@pytest.fixture(scope="module")
def pyproject() -> dict[str, Any]:
    with PYPROJECT.open("rb") as handle:
        data: dict[str, Any] = tomllib.load(handle)
    return data


def _declared_requirements(pyproject: dict[str, Any]) -> dict[str, list[str]]:
    """Every declared requirement, grouped by the table it came from."""
    project = pyproject["project"]
    groups: dict[str, list[str]] = {
        "dependencies": list(project.get("dependencies", []))
    }
    for extra, requirements in project.get("optional-dependencies", {}).items():
        groups[f"optional-dependencies.{extra}"] = list(requirements)
    groups["build-system.requires"] = list(pyproject["build-system"]["requires"])
    return groups


def _requirement_name(requirement: str) -> str:
    """Extract the distribution name from a PEP 508 requirement string."""
    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    assert match is not None, f"unparsable requirement: {requirement!r}"
    return _normalize(match.group(1))


def test_no_ai_llm_sdk_is_declared_anywhere(pyproject: dict[str, Any]) -> None:
    """Hard rule #1: no AI/LLM dependency, in any group, ever.

    keyreach *probes* AI providers' endpoints with a user-supplied key — that is
    the product — but it must never import their SDKs to call a model.
    """
    offenders: list[str] = []
    for group, requirements in _declared_requirements(pyproject).items():
        offenders.extend(
            f"{group}: {requirement}"
            for requirement in requirements
            if _requirement_name(requirement) in AI_SDK_DENYLIST
        )

    assert not offenders, (
        "AI/LLM dependency declared, which keyreach forbids absolutely "
        f"(plan.md §1): {offenders}"
    )


def test_declares_the_stack_fixed_in_the_implementation_plan(
    pyproject: dict[str, Any],
) -> None:
    """Runtime deps must match implementation_plan.md §1 — no more, no less.

    Deliberately exact. An undeclared dependency breaks installs; an unexpected
    one is scope creep that never got reviewed against the plan.
    """
    expected = {"typer", "httpx", "rich", "pydantic", "jinja2", "pyyaml"}
    declared = {
        _requirement_name(requirement)
        for requirement in pyproject["project"]["dependencies"]
    }

    assert declared == expected


def test_every_runtime_dependency_is_version_bounded(
    pyproject: dict[str, Any],
) -> None:
    """An unbounded dependency is a future surprise breakage in someone's report."""
    unbounded = [
        requirement
        for requirement in pyproject["project"]["dependencies"]
        if not re.search(r"[<>=~!]", requirement)
    ]

    assert not unbounded, f"unbounded runtime dependencies: {unbounded}"


def test_license_is_apache_2_0(pyproject: dict[str, Any]) -> None:
    """plan.md §10: permissive, with a patent grant."""
    project = pyproject["project"]

    assert project["license"] == "Apache-2.0"
    assert "LICENSE" in project["license-files"]
    assert "NOTICE" in project["license-files"]


def test_requires_python_3_11_or_newer(pyproject: dict[str, Any]) -> None:
    assert pyproject["project"]["requires-python"] == ">=3.11"


def test_console_script_points_at_the_exit_code_wrapper(
    pyproject: dict[str, Any],
) -> None:
    """`run`, not `app` — and the difference is the exit-code contract.

    Pointing the binary straight at the typer app would let click's exit code 2
    for a malformed command line reach the shell, where `implementation_plan.md`
    §12 says 2 means "a finding at or above --fail-on". `keyreach.cli.run` is the
    single place that mapping happens, so it has to be what actually runs.
    """
    assert pyproject["project"]["scripts"] == {"keyreach": "keyreach.cli:run"}


def test_version_is_single_sourced_from_the_package(
    pyproject: dict[str, Any],
) -> None:
    """Guards against someone reintroducing a hardcoded version in pyproject."""
    assert "version" in pyproject["project"]["dynamic"]
    assert pyproject["tool"]["hatch"]["version"]["path"] == "keyreach/__init__.py"


def test_report_templates_are_importable_package_data() -> None:
    """The Markdown template has to survive installation, not just checkout.

    ``PackageLoader`` reads it through the import system, so this fails the same
    way a wheel missing the file would — a report that renders from the source
    tree and crashes for an installed user is the failure mode being guarded.
    """
    templates = resources.files("keyreach.report") / "templates"

    assert (templates / "report.md.j2").is_file()
