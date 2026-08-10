---
name: Feature request
about: Suggest a capability or improvement for keyreach
title: "[feat] "
labels: ["enhancement", "triage"]
assignees: ""
---

<!--
Requesting support for a NEW PROVIDER? Use the "New provider" template instead —
it asks the provider-specific questions we need.

Please skim plan.md §4 (non-goals) and ROADMAP.md before filing. A few things
are permanently out of scope no matter how useful they'd be:
  • secret scanning (crawling repos/buckets/images to FIND keys)
  • exploitation, privilege escalation, lateral movement
  • continuous cloud posture management (CSPM)
  • ANY AI/LLM feature — no model calls, no "smart" heuristics, ever
-->

## Problem

<!-- What can't you do today? Describe the situation, not the solution.
     Concrete beats abstract: "when I triage a leaked Stripe key I have to
     hand-check X because keyreach doesn't report Y." -->

## Proposed solution

<!-- What should keyreach do? Include the CLI surface if relevant. -->

```console
$ keyreach KEY --your-proposed-flag
```

## Alternatives considered

<!-- Other ways to solve it, and why they're worse. Including "do nothing". -->

## Scope check

Please confirm this fits keyreach's scope
([`plan.md`](../../plan.md) §3–§4):

- [ ] This is **not** secret scanning (finding keys) — keyreach starts from a key
      you already have
- [ ] This is **not** exploitation, privilege escalation, or lateral movement
- [ ] This requires **no** AI/LLM call and **no** fuzzy heuristic — it can be
      decided by explicit rules
- [ ] This can be done **read-only** (no writes, deletes, or spend)
- [ ] This produces **deterministic** output (same input ⇒ same result)

<!-- If you can't tick one of these, file it anyway and explain — maybe the
     scope line is in the wrong place, and that's a discussion worth having.
     But be aware the AI/LLM and read-only lines will not move. -->

## Roadmap

<!-- Does this map to an existing ROADMAP.md item, or is it new? -->

- Related roadmap item(s):
- [ ] I'd be willing to implement this

## Impact

<!-- Who benefits, and how much? For provider or capability work: how often does
     this key type leak, and what's the blast radius when it does? keyreach
     prioritizes by leak frequency × blast radius (plan.md §8). -->

## Additional context

<!-- Links to provider docs, prior art, bounty write-ups, screenshots. If prior
     art exists, note its license — we can only reuse permissive/CC-BY sources
     (CREDITS.md). -->
