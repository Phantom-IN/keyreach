# Credits

keyreach stands on a decade of open security tooling. This file is the
human-readable thank-you list: who built the prior art, what keyreach learns
from or reuses, and — importantly — what it deliberately does **not** copy.

Two different things live here:

- **Credit** — acknowledgement of people and projects whose ideas, research, or
  documentation shaped keyreach. Everything in this file gets credit.
- **Attribution** — the legally required notice for code or data actually
  redistributed inside keyreach. That lives in [`NOTICE`](NOTICE) and
  [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md), and only applies to a
  subset of the projects below.

> **License discipline** (see [`plan.md`](plan.md) §5 and §10): keyreach is
> Apache-2.0. **AGPL/GPL code is never copied in.** Where a project below is
> AGPL/GPL, we study its observable behavior and re-implement from public API
> documentation — nothing more. Every license is re-verified from the upstream
> repository before any reuse.

Legend:

| Marker | Meaning |
| --- | --- |
| 📖 **Studied only** | Copyleft or otherwise incompatible. Behavior studied; nothing copied. |
| ♻️ **Reusable** | Permissive/CC-BY. May be reused **with attribution** in `NOTICE`. |
| 💡 **Reference** | Design, methodology, or UX inspiration. No code reuse planned. |

---

## Detection & scanning

### TruffleHog — Truffle Security 📖 Studied only

<https://github.com/trufflesecurity/trufflehog> · AGPL-3.0

The closest comparable prior art and the current state of the art: it finds,
verifies, and (via `analyze`) enumerates permissions and resources for
credentials across many providers. **We learn from its behavior only** — how
credential verification and permission analysis are framed — and re-implement
from public provider documentation. No TruffleHog code or detector data is
copied into keyreach. keyreach differentiates on single-key ergonomics,
AI-provider depth, transparent computed severity, and disclosure-ready reports.

### secrets-patterns-db — Mazin Ahmed (mazen160) ♻️ Reusable

<https://github.com/mazen160/secrets-patterns-db> · CC-BY-4.0

The largest open, format-agnostic, confidence-tagged database of secret
patterns (1600+ regexes). keyreach **seeds its detection ruleset from an
attributed subset** of this database. Reuse requires attribution under CC-BY-4.0
— recorded in [`NOTICE`](NOTICE) and in the pattern file header.

### gitleaks — Zachary Rice and contributors ♻️ Reusable

<https://github.com/gitleaks/gitleaks> · MIT

A well-curated, battle-tested ruleset. keyreach **cross-checks and supplements**
its detection patterns against gitleaks rules. MIT reuse requires the license
text and copyright notice, reproduced in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) when rules are reused.

### detect-secrets — Yelp ♻️ Reusable (verify before reuse)

<https://github.com/Yelp/detect-secrets> · Apache-2.0 (verify at reuse time)

Entropy-based detection plugins. keyreach learns its **entropy fallback** for
generic, prefix-less tokens from this approach and re-implements it as a
deterministic Shannon-entropy threshold. Any direct reuse gets an attribution
entry.

---

## Validation & capability-enumeration methodology

### KeyHacks — streaak 💡 Reference

<https://github.com/streaak/keyhacks>

The community cookbook of per-provider validation recipes across 80+ providers,
and keyreach's **primary methodology source**: which endpoint proves a given key
is live. *Which endpoint to call is a fact, not an expressive work* — keyreach
re-implements each recipe and **re-verifies it against current provider
documentation**, since cookbook recipes drift.

### gmapsapiscanner — Ozgur Alp 💡 Reference (verify license before reuse)

<https://github.com/ozguralp/gmapsapiscanner>

A Google `AIza` key scanner probing ~20 Google APIs (Maps, Places, Geocode,
Roads, FCM, and Gemini Files), with cost annotations per endpoint. This is the
**blueprint for keyreach's Google provider** (roadmap R1.1). Its author's own
stated roadmap — cover *all* Google APIs for greater impact — is essentially
what the keyreach Google plugin aims to be. Endpoint lists and cost annotations
are factual; the license is verified before reusing anything expressive, and the
provider file carries an inline credit header.

### enumerate-iam — Andrés Riancho 💡 Reference

<https://github.com/andresriancho/enumerate-iam>

The model for **AWS read-only permission inference**. It is noisy by design —
which is exactly why keyreach makes this style of enumeration **opt-in, flagged,
and loudly warned** rather than default (see [`plan.md`](plan.md) §11).

### Pacu — Rhino Security Labs 📖 Studied only

<https://github.com/RhinoSecurityLabs/pacu> · BSD-3-Clause (verify) —
**enumeration modules studied only; exploitation modules explicitly out of scope**

An AWS exploitation framework. keyreach studies **only its enumeration
modules** as a reference for inferring effective permissions. keyreach is
explicitly **not** an exploitation framework: no privilege escalation, no
lateral movement, no destructive actions ([`plan.md`](plan.md) §4).

### GCPBucketBrute — Rhino Security Labs 📖 Studied only

<https://github.com/RhinoSecurityLabs/GCPBucketBrute>

A reference for enumerating reachable cloud resources and inferring effective
permissions on GCP. Studied for enumeration technique only.

---

## Architecture, severity & reporting references

### Prowler 💡 Reference

<https://github.com/prowler-cloud/prowler> · Apache-2.0 (verify at reuse time)

A mature, multi-cloud assessment tool with a proven **check architecture,
severity model, and multi-format reporting**. A design to learn from, especially
for keeping hundreds of checks maintainable. keyreach is not a CSPM platform —
continuous posture management stays Prowler's domain.

### ScoutSuite — NCC Group 📖 Studied only

<https://github.com/nccgroup/ScoutSuite> · GPL-2.0 (verify)

Turns enumerated cloud permissions into a navigable report. **Studied only** for
how enumerated permissions become a usable report artifact — no code copied.

### nuclei — ProjectDiscovery 💡 Reference

<https://github.com/projectdiscovery/nuclei> · MIT (verify at reuse time)

Its declarative **"request → match → verdict"** template model is the reference
for keyreach's rule-based, deterministic YAML probe format (roadmap R2.8,
[`implementation_plan.md`](implementation_plan.md) §8). Match rules stay strict
and mechanical — status codes, header presence, JSON field presence — never
model-judged.

### SecurityWall API Key Checker 💡 Reference (UX)

Web tool that identifies key type against 400+ patterns and *suggests*
validation commands without executing them. A useful UX contrast: keyreach
**executes** read-only probes and produces severity plus a report automatically
and deterministically.

---

## Wider thanks

- Every bug bounty hunter and triager who has publicly documented what a leaked
  key actually reaches. Those write-ups are the reason a severity model can be
  argued from evidence rather than assertion.
- The provider security and documentation teams whose public API docs make
  read-only, non-destructive validation possible in the first place.

---

## Adding a credit

If you contribute a provider derived from prior art:

1. Add an **inline credit header** in the provider source file naming the
   upstream project, its author, its license, and its URL.
2. Add an entry to this file describing what was learned or reused.
3. If code or data is actually **redistributed**, also add the attribution to
   [`NOTICE`](NOTICE) and the full license text to
   [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) — in the same pull
   request.
4. **Verify the license from the upstream repository itself** before reusing
   anything. If it is AGPL/GPL: study only, mark it 📖, and re-implement from
   public documentation.

If your work is listed here and you would like the wording, the link, or the
attribution changed — or removed — please open an issue. We will fix it.
