# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

keyreach is built in public: each entry below corresponds to a roadmap item in
[`ROADMAP.md`](ROADMAP.md) that landed via its own pull request. Add an entry
under `Unreleased` in the same pull request as any user-visible change.

## [Unreleased]

### Added

- Base open-source repository structure (roadmap item **R0.1**): Apache-2.0
  `LICENSE`, `NOTICE`, `CREDITS.md`, `THIRD_PARTY_LICENSES.md`, `README.md`,
  `ROADMAP.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, this
  changelog, `.gitignore`, GitHub issue and pull request templates, and a
  hygiene-only CI workflow.
- Project scaffold (roadmap item **R0.2**): `pyproject.toml` (Apache-2.0,
  Python 3.11+, hatchling, the stack fixed in `implementation_plan.md` §1 and
  **no AI/LLM dependencies**), the `keyreach` package with a PEP 561 `py.typed`
  marker, and the `keyreach` console script.
- `keyreach --help` and `keyreach --version`. Deliberately nothing else: the
  pipeline behind the CLI is built one roadmap item at a time, and the full
  flag surface is specified in `implementation_plan.md` §12 for **R1.5**.
- Test harness (pytest) covering the CLI scaffold and the packaging metadata,
  including a guard that no AI/LLM SDK appears in any declared dependency
  group. The full `ai_ban` source-and-dependency scan remains **R0.9**.
- Developer tooling: `.pre-commit-config.yaml` (ruff, black, mypy, markdownlint,
  plus `detect-private-key` to catch un-scrubbed cassettes before they become
  permanent git history) and a checked-in `.markdownlint-cli2.jsonc` shared by
  pre-commit, CI, and local runs.
- `keyreach` reserved on PyPI with a `0.1.0.dev0` placeholder. `pip install
  keyreach` deliberately resolves nothing — pip skips pre-releases by default —
  so the name is held without shipping a tool that cannot do anything yet. The
  first real release is `0.1.0`, roadmap item **R1.6**.
- `.github/workflows/publish.yml` — tag-triggered PyPI publishing via **Trusted
  Publishing (OIDC)**, so no long-lived API token is stored in the repository,
  in an environment secret, or on a maintainer's machine. Pulled forward from
  R1.6. It refuses to publish if the git tag does not match `__version__`, or if
  the test suite fails.

### Changed

- The CI workflow no longer generates its markdownlint config inline; it reads
  the checked-in `.markdownlint-cli2.jsonc`. CI remains hygiene-only —
  ruff/black/mypy/pytest are wired into it in **R0.9**, which owns the pipeline.

### Deprecated

- *Nothing yet.*

### Removed

- *Nothing yet.*

### Fixed

- *Nothing yet.*

### Security

- *Nothing yet.*

---

No releases yet. The first release, `v0.1.0`, is roadmap item **R1.6** and ships
once keyreach covers ≥10 providers across ≥4 categories (cloud, AI, payment,
comms). See [`ROADMAP.md`](ROADMAP.md).

<!-- Link definitions are added here as releases are tagged, e.g.:
[Unreleased]: https://github.com/Phantom-IN/keyreach/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Phantom-IN/keyreach/releases/tag/v0.1.0
-->
