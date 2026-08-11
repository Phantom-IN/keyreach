# Third-party licenses

This file reproduces the **full license text** of every third-party work whose
code or data is redistributed as part of keyreach, as required by those
licenses. It is the legal companion to [`NOTICE`](NOTICE) (short-form
attribution) and [`CREDITS.md`](CREDITS.md) (human-readable acknowledgement).

keyreach itself is licensed under the Apache License 2.0 — see
[`LICENSE`](LICENSE).

---

## Status

> **No third-party code or data has been incorporated yet.**
>
> This file is a scaffold created in the repository's first commit (roadmap item
> R0.1). The sections below are placeholders for sources keyreach *intends* to
> reuse, per [`plan.md`](plan.md) §5. Each is marked **NOT YET INCORPORATED**
> and carries no license text until the dependency or data actually lands.
>
> When a source is incorporated, the pull request that introduces it must, in
> the same change: paste the verbatim upstream license text into its section
> here, remove the **NOT YET INCORPORATED** marker, and update
> [`NOTICE`](NOTICE) and [`CREDITS.md`](CREDITS.md).

---

## Rules for adding an entry

1. **Verify the license from the upstream repository itself** — read the actual
   `LICENSE` file at the commit or release you are reusing. Never rely on a
   package index summary, a README badge, a blog post, or memory. Licenses
   change between versions.
2. **Confirm compatibility.** Permissive licenses (MIT, Apache-2.0, BSD-2/3,
   ISC, CC-BY) are compatible with Apache-2.0 redistribution.
   **AGPL/GPL/LGPL code is never copied into keyreach** — it may be studied for
   behavior and re-implemented from public API documentation, and it belongs in
   [`CREDITS.md`](CREDITS.md), not here.
3. **Reproduce the license verbatim** — the complete text plus the upstream
   copyright line(s). Do not summarize, truncate, or reformat.
4. **Record what was reused and how it was modified.** Reused-as-is vs. subset
   vs. reformatted vs. re-implemented. CC-BY in particular requires indicating
   whether changes were made.
5. **Pin the provenance.** Record the upstream URL and the specific commit SHA
   or release tag the material came from, so the reuse is auditable later.
6. **Add an inline credit header** to any source file derived from a specific
   upstream project.

Use this template:

```
## <Project name>

- **Status:** INCORPORATED (or: NOT YET INCORPORATED — planned R<x.y>)
- **Upstream:** <URL>
- **Version / commit:** <tag or SHA>
- **License:** <SPDX identifier>
- **Verified:** <YYYY-MM-DD> by <handle>, read from <URL to upstream LICENSE file>
- **What is reused:** <files, data, or rules>
- **Modifications:** <none | subset | reformatted | ...>

### License text

<verbatim upstream license text and copyright notice>
```

---

## secrets-patterns-db

- **Status:** **NOT YET INCORPORATED** — planned in roadmap item **R0.5**
  (detection layer)
- **Upstream:** <https://github.com/mazen160/secrets-patterns-db>
- **Author:** Mazin Ahmed (mazen160)
- **License:** CC-BY-4.0 (Creative Commons Attribution 4.0 International)
- **Verified:** *pending — verify from the upstream repository before reuse*
- **What will be reused:** an attributed subset of detection regular
  expressions, seeding `keyreach/patterns/detection_rules.yml`
- **Modifications:** patterns will be subset, reformatted into keyreach's rule
  schema, and re-verified. CC-BY-4.0 requires that these modifications be
  indicated — they will be noted in the pattern file header.

### License text

*To be added verbatim (CC-BY-4.0 legal code) when the patterns are
incorporated.*

---

## gitleaks

- **Status:** **NOT YET INCORPORATED** — planned in roadmap item **R0.5**
  (detection cross-check)
- **Upstream:** <https://github.com/gitleaks/gitleaks>
- **Author:** Zachary Rice and the gitleaks contributors
- **License:** MIT
- **Verified:** *pending — verify from the upstream repository before reuse*
- **What will be reused:** detection rules used to cross-check and supplement
  the seeded pattern set
- **Modifications:** subset and translated into keyreach's rule schema

### License text

*To be added verbatim (MIT license text and upstream copyright line) when rules
are incorporated.*

---

## detect-secrets (Yelp)

- **Status:** **NOT YET INCORPORATED** — reference only at present
- **Upstream:** <https://github.com/Yelp/detect-secrets>
- **License:** Apache-2.0 — **verify before any reuse**
- **What may be reused:** nothing currently planned. keyreach re-implements a
  deterministic entropy fallback informed by detect-secrets' *approach*; an
  approach is not copyrightable material, so no attribution entry is required
  unless code is actually copied.

---

## Runtime dependencies

keyreach's Python runtime dependencies (Typer, httpx, rich, pydantic, Jinja2,
PyYAML — see [`implementation_plan.md`](implementation_plan.md) §1) are
**installed from PyPI, not vendored** into this repository, so their license
texts are not reproduced here. They are all permissively licensed (MIT/BSD/
Apache-2.0), and their licenses are distributed with the packages themselves.

If a dependency is ever **vendored** into the repository, it gets a full entry
in this file.

### Verification record

Every dependency declared in `pyproject.toml` was license-checked from PyPI
package metadata (`license_expression`, falling back to `license` and then to
the `License ::` classifiers) when roadmap item **R0.2** introduced it. All are
permissive and compatible with Apache-2.0 redistribution; none is copyleft; none
is an AI/LLM SDK.

| Dependency | Group | License | Verified |
| --- | --- | --- | --- |
| typer | runtime | MIT | 2026-08-11 |
| httpx | runtime | BSD-3-Clause | 2026-08-11 |
| rich | runtime | MIT | 2026-08-11 |
| pydantic | runtime | MIT | 2026-08-11 |
| Jinja2 | runtime | BSD-3-Clause | 2026-08-11 |
| PyYAML | runtime | MIT | 2026-08-11 |
| pytest | dev | MIT | 2026-08-11 |
| pytest-cov | dev | MIT | 2026-08-11 |
| respx | dev | BSD-3-Clause | 2026-08-11 |
| syrupy | dev | MIT | 2026-08-11 |
| ruff | dev | MIT | 2026-08-11 |
| black | dev | MIT | 2026-08-11 |
| mypy | dev | MIT | 2026-08-11 |
| pre-commit | dev | MIT | 2026-08-11 |
| build | dev | MIT | 2026-08-11 |
| twine | dev | Apache-2.0 | 2026-08-11 |
| hatchling | build | MIT | 2026-08-11 |

Re-check this table whenever a dependency is added or a major version is bumped.
Roadmap item **R0.9** wires the CI guardrails that make the AI/LLM half of this
check automatic; `tests/test_packaging.py` already fails if an AI/LLM SDK is
declared in any group.

---

## Projects studied but not copied

The following are **not** listed here because no code or data from them is
redistributed. They are acknowledged in [`CREDITS.md`](CREDITS.md):

- **TruffleHog** (AGPL-3.0) — behavior studied, re-implemented from public docs
- **ScoutSuite** (GPL) — studied only
- **Pacu** — enumeration approach studied only; exploitation is out of scope
- **KeyHacks**, **gmapsapiscanner**, **enumerate-iam**, **Prowler**, **nuclei** —
  methodology and design references

If any of these ever contribute actual code or data to keyreach, the copyleft
ones must be rejected outright, and the permissive ones get a full entry above
with verified license text.
