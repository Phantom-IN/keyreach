# Third-party licenses

This file reproduces the **full license text** of every third-party work whose
code or data is redistributed as part of keyreach, as required by those
licenses. It is the legal companion to [`NOTICE`](NOTICE) (short-form
attribution) and [`CREDITS.md`](CREDITS.md) (human-readable acknowledgement).

keyreach itself is licensed under the Apache License 2.0 — see
[`LICENSE`](LICENSE).

---

## Status

> **No third-party code or data is incorporated into keyreach.**
>
> The two sources this file was scaffolded for — secrets-patterns-db and
> gitleaks — were evaluated in roadmap item **R0.5** and **neither is reused**.
> Their sections below record the verification and its outcome, which is the
> point of keeping them: a licensing decision is only auditable if the reasoning
> survives.
>
> keyreach's detection patterns are instead written from each provider's own
> public API documentation, with every rule citing its source URL.
>
> When a source *is* incorporated, the pull request that introduces it must, in
> the same change: paste the verbatim upstream license text into its section
> here, and update [`NOTICE`](NOTICE) and [`CREDITS.md`](CREDITS.md).

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

- **Status:** **NOT REUSED** — resolved in roadmap item **R0.5**
- **Upstream:** <https://github.com/mazen160/secrets-patterns-db>
- **Author:** Mazin Ahmed (mazen160)
- **License:** **CC-BY-SA-4.0**, read from `LICENSE.md` at commit
  `24984df1a3f78475132ed183cebce4452b601161`
- **Verified:** 2026-08-11
- **What is reused:** nothing
- **Modifications:** not applicable

This entry previously planned an attributed reuse under CC-BY-4.0, seeding
`keyreach/patterns/detection_rules.yml`. Verifying the license from the upstream
repository — rule 1 above — showed the assumption was wrong on two independent
grounds:

1. **The license is CC-BY-SA-4.0, not CC-BY-4.0.** `LICENSE.md` opens with
   "Attribution-ShareAlike 4.0 International". ShareAlike requires adaptations to
   be licensed under the same terms, and rule 2 above permits reuse only from
   MIT / Apache-2.0 / BSD / ISC / CC-BY sources. The repository's `README.md`
   separately states "This work is licensed under a Creative Commons Attribution
   4.0 International License", contradicting its own license file. Where a grant
   is ambiguous, the conservative reading governs — a permissive claim in a
   README does not override the license file, and only the author can resolve
   the discrepancy.
2. **It self-declares AGPL content.** The same `README.md` states "Trufflehog
   data is licensed under the AGPL". The rule set carries no per-rule
   provenance, so TruffleHog-derived entries cannot be identified and excluded.
   Copying TruffleHog is forbidden outright.

**Outcome:** nothing is copied. keyreach's detection patterns are written from
each provider's own public API documentation, and every rule records the vendor
documentation URL it came from. This is the same treatment
[`CREDITS.md`](CREDITS.md) already prescribes for AGPL prior art: study the
behaviour, re-implement from primary sources. secrets-patterns-db remains
credited there as prior art that was studied, which requires no attribution
here.

### License text

Not applicable — no material is redistributed.

---

## gitleaks

- **Status:** **NOT REUSED** — resolved in roadmap item **R0.5**
- **Upstream:** <https://github.com/gitleaks/gitleaks>
- **Author:** Zachary Rice and the gitleaks contributors
- **License:** MIT, verified 2026-08-11
- **What is reused:** nothing

MIT would permit reuse with attribution, and the license was verified. But
nothing has been copied: gitleaks serves as a behavioural cross-check, and
comparing behaviour is not reuse. It is credited in
[`CREDITS.md`](CREDITS.md).

If rules are ever reused, this section gains the verbatim MIT license text and
upstream copyright line, and [`NOTICE`](NOTICE) gains an attribution entry, in
the same pull request.

### License text

Not applicable — no material is redistributed.

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
| pytest-asyncio | dev | Apache-2.0 | 2026-08-11 |
| pytest-cov | dev | MIT | 2026-08-11 |
| ruff | dev | MIT | 2026-08-11 |
| black | dev | MIT | 2026-08-11 |
| mypy | dev | MIT | 2026-08-11 |
| types-PyYAML | dev | Apache-2.0 | 2026-08-11 |
| pre-commit | dev | MIT | 2026-08-11 |
| build | dev | MIT | 2026-08-11 |
| twine | dev | Apache-2.0 | 2026-08-11 |
| hatchling | build | MIT | 2026-08-11 |

Re-check this table whenever a dependency is added or a major version is bumped.
The `ai_ban` guardrail (roadmap **R0.9**, `tools/guardrails/ai_ban.py`) makes
the AI/LLM half of this check automatic in CI, in pre-commit and under `pytest`.

---

## Projects studied but not copied

The following are **not** listed here because no code or data from them is
redistributed. They are acknowledged in [`CREDITS.md`](CREDITS.md):

- **TruffleHog** (AGPL-3.0) — behavior studied, re-implemented from public docs
- **ScoutSuite** (GPL) — studied only
- **Pacu** — enumeration approach studied only; exploitation is out of scope
- **KeyHacks**, **enumerate-iam**, **Prowler**, **nuclei** — methodology and
  design references
- **gmapsapiscanner** (MIT, verified 2026-08-11) — the blueprint for
  `keyreach/providers/google.py` (roadmap R1.1). Its license *would* permit
  reuse with attribution, and it is listed here rather than above because
  nothing was in fact copied: it established which Google APIs are worth
  probing, and every endpoint, parameter and success rule was then written from
  Google's own documentation, each probe citing its source page. Credited
  inline in the provider and in [`CREDITS.md`](CREDITS.md). If code or data
  from it is ever redistributed, move it into the table above with the full MIT
  text.

If any of these ever contribute actual code or data to keyreach, the copyleft
ones must be rejected outright, and the permissive ones get a full entry above
with verified license text.
