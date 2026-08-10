---
name: New provider
about: Request or propose support for a new API key provider
title: "[provider] "
labels: ["provider", "enhancement", "triage"]
assignees: ""
---

<!--
⚠️ NEVER PASTE A REAL API KEY into this issue. Use a synthetic, structurally
   representative example with the real characters replaced — e.g.
   `sk_live_EXAMPLEEXAMPLEEXAMPLE`. We need the SHAPE of the key, not a key.

This template collects everything needed to build a provider plugin. You do not
have to answer every question — file it with what you know and we'll fill in the
gaps. But the more of this you can answer, the faster it ships.

Building it yourself? 🙌 Read the provider checklist in CLAUDE.md ("How to add a
provider") and the interface contract in implementation_plan.md §4 first, then
tick "I'd like to implement this" below. Target: ~30 minutes for a simple
provider.
-->

## Provider

| | |
| --- | --- |
| **Name** | <!-- e.g. Stripe, Datadog, Supabase --> |
| **Category** | <!-- cloud / ai / payment / comms / email / devtools / database / monitoring / auth / other --> |
| **API docs URL** | |
| **Key rotation / revocation guide URL** | |

## Key format

<!-- How is this key recognized? Prefixes, length, charset, checksum. This drives
     detect() and the entry in patterns/detection_rules.yml. -->

- **Prefix / distinctive structure:** <!-- e.g. `sk_live_`, `SG.`, `AIza` -->
- **Length / charset:**
- **Synthetic example** (fake characters only): `` ` `` <!-- e.g. sk_live_EXAMPLE1234567890 --> `` ` ``
- **Variants** (test vs live, restricted vs full, scoped tokens):
- **Collision risk:** <!-- does the prefix overlap with another provider's? -->

## Validation

<!-- The single cheapest READ-ONLY call that proves the key is live and says
     whose account it is. This becomes validate(). -->

- **Endpoint:**
- **Method:** <!-- must be GET or another idempotent method where possible -->
- **Auth style:** <!-- Bearer header / X-Api-Key header / query param / basic auth -->
- **What a valid key returns:**
- **What an invalid or expired key returns:** <!-- status code + body shape -->
- **Identity available from the response:** <!-- account, org, project, plan/tier -->

## Capability probes

<!-- The read-only endpoints that map what the key can reach. This becomes
     enumerate(). One row per probe. KEEP THIS MINIMAL — every probe is
     authentication traffic and a log entry on someone's production service. -->

| Endpoint | Method | Proves what capability | Access level (read/write/admin) | Touches private/user data? | Can incur cost? |
| --- | --- | --- | --- | --- | --- |
| | | | | | |
| | | | | | |

**Notes on the flags** — these drive the computed severity, so accuracy matters
more here than anywhere else in the plugin
([`plan.md`](../../plan.md) §6):

- **`data_sensitive`** — does this reach private or user data (customer records,
  uploaded files, messages, PII)?
- **`incurs_cost`** — can it spend money or send communications (LLM inference
  billing, cloud spend, SMS/email sending, payment operations)?

## Restrictions

<!-- Can this key type be restricted (referrer / IP / app / scope / expiry)?
     How is a restricted key's failure distinguishable from an invalid one?
     Restriction signals can DOWNGRADE severity, so we need to detect them. -->

## Read-only safety

- [ ] Every probe above is **non-destructive** — no writes, deletes, or spend
- [ ] Any probe that must use POST is a **read** operation on an RPC-style API
      (list it here with justification — the HTTP layer default-denies POST):

<!-- justification, if applicable -->

## Impact

<!-- Why is this provider worth adding? keyreach prioritizes by
     leak frequency × blast radius (plan.md §8). -->

- **How often does this key type leak in the wild?**
- **What's the worst case when it does?**
- **Public write-ups / CVEs / bounty reports:**

## Prior art & licensing

<!-- Is there an existing tool or KeyHacks-style recipe for this provider? -->

- **Existing tool / recipe:**
- **Its license:** <!-- verify from the upstream repo itself, not a summary -->

⚠️ keyreach is Apache-2.0 and **never copies AGPL/GPL code**. Copyleft prior art
may be *studied* and re-implemented from public API docs only. Permissive
(MIT/Apache/BSD/CC-BY) sources may be reused **with attribution** in
[`NOTICE`](../../NOTICE), [`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md),
and [`CREDITS.md`](../../CREDITS.md), plus an inline credit header in the
provider file.

## Fixtures

<!-- Every provider ships recorded cassettes for BOTH a valid and an
     invalid/expired key, so CI never needs a live key. -->

- [ ] I can record fixtures with a **throwaway key I own** and scrub them before
      committing
- [ ] I cannot record fixtures — someone else will need to

## Contribution

- [ ] I'd like to implement this myself
- [ ] I'm requesting it; someone else should build it

<!-- If implementing: open a tracking issue (this one counts), branch as
     feat/<roadmap-id>-<slug> — or feat/provider-<name> if it's not on the
     roadmap — and follow CONTRIBUTING.md. -->
