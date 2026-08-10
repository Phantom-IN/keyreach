---
name: Bug report
about: Something in keyreach behaves incorrectly
title: "[bug] "
labels: ["bug", "triage"]
assignees: ""
---

<!--
⚠️ SECURITY ISSUES: do NOT report a vulnerability in keyreach here.
   Follow the private disclosure process in SECURITY.md instead.

⚠️ NEVER PASTE A REAL API KEY into this issue — not even a partial one, not
   even an expired one. Use a synthetic example (e.g. `AIzaSyEXAMPLE...`,
   `sk-EXAMPLE...`) or the masked form keyreach prints by default.
   If you accidentally paste one: rotate it immediately, then edit the issue.
-->

## Summary

<!-- One or two sentences: what went wrong. -->

## Which part of keyreach?

<!-- Tick all that apply. -->

- [ ] Detection (wrong provider identified, or none)
- [ ] Validation (valid key reported invalid, or vice versa)
- [ ] Enumeration (missing, spurious, or wrong capability)
- [ ] Scoring (severity band or rationale looks wrong)
- [ ] Reporting (terminal / JSON / Markdown / HTML output)
- [ ] CLI / flags / exit codes
- [ ] Packaging, install, or CI
- [ ] Docs
- [ ] Other / not sure

## Steps to reproduce

<!-- Redact the key. Show the masked form or a synthetic placeholder. -->

```console
$ keyreach <MASKED_OR_SYNTHETIC_KEY> --json
```

1.
2.
3.

## Expected behavior

<!-- What should have happened, and why — cite plan.md / implementation_plan.md
     if the expectation comes from the docs. -->

## Actual behavior

<!-- What actually happened. Paste output — MASKED. Include the full traceback
     if there is one, redacting any key or account identifier. -->

```
```

## Determinism check

<!-- Determinism is a hard guarantee (plan.md §1). If the same input produced
     different output across runs, that is a serious bug — say so here. -->

- [ ] I ran it twice with the same input and got **identical** output
- [ ] I ran it twice and got **different** output ⚠️
- [ ] Not applicable / didn't check

## Environment

| | |
| --- | --- |
| keyreach version (`keyreach --version`) | |
| Install method (pipx / pip / from source) | |
| Python version (`python --version`) | |
| OS and version | |
| Provider / key type involved | |

## Additional context

<!-- Anything else: a cassette that reproduces it, a provider API change you
     suspect, related issues. If a provider's API appears to have drifted, note
     what changed — that helps us update the fixture and the golden file. -->
