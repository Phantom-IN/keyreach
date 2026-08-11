# keyreach — Project Plan

> **Name:** `keyreach`
>
> **One-line pitch:** Paste any leaked API key — cloud, AI, payment, comms, dev-tool, database, or SaaS — and get a full capability map plus a disclosure-ready security report with a computed severity, in one command.
>
> **Audience:** Bug bounty hunters, pentesters, red teams, and blue teams doing exposure triage.
>
> **Status:** Planning.

This document is the **product plan** — *what* keyreach is and *why*. It contains no implementation detail. For codebase structure, interfaces, and build mechanics, see `implementation_plan.md`. For working rules while building, see `CLAUDE.md`.

---

## 1. Core principles

These are non-negotiable and shape every decision downstream.

1. **Deterministic and rule-based — no AI/LLM, ever.** keyreach contains **zero** AI or LLM calls anywhere in its runtime. All detection, validation, capability enumeration, severity scoring, and report generation are driven by explicit rules, patterns, and provider API responses. This is a hard requirement for three reasons:
   - **Security:** keyreach handles live secrets. Sending a key to an external model would itself be a credential leak. That must never happen.
   - **Reproducibility:** the same key against the same provider state must always yield the same capability map, severity, and report. Findings that can't be reproduced can't be reported.
   - **Auditability & trust:** every verdict must be traceable to a concrete rule and a concrete API response, so a hunter (or a triager on the receiving end) can verify exactly why the tool said what it said.
2. **Read-only by default.** Every probe is non-destructive. keyreach never writes, deletes, or spends money in its default operation.
3. **Single-key ergonomics.** One key in, full picture out. No scanning workflow to wade through.
4. **Transparent severity.** Severity is derived from enumerated capabilities with a visible rationale — never a hardcoded per-provider label.
5. **Authorized use only.** Built for keys you own or are explicitly authorized to test (bounty scope or engagement).

---

## 2. Problem statement

When a hunter finds an exposed key (a Google `AIza…` key, an OpenAI `sk-…` key, an AWS `AKIA…` key, a Stripe `sk_live_…` key, a Slack `xoxb-…` token, and so on), the value of the finding depends entirely on **what that key can actually do**. Today, answering that requires chaining many single-purpose tools and hand-assembling a report:

- A different tool per provider (one scanner for Google Maps keys, another for AWS IAM, ad-hoc `curl` recipes for everything else).
- No unified "what is the blast radius" answer across providers.
- No automatic severity classification, so the same finding is argued inconsistently.
- No disclosure-ready output — the report is hand-written every single time.

keyreach collapses this into one deterministic command: detect → validate → enumerate → score → report.

---

## 3. Goals

- **G1 — Universal input:** accept a single key, a file/stdin of keys, or an "unknown" key and deterministically identify the provider.
- **G2 — All key classes, not just cloud/AI:** cloud, AI/LLM, payment, communications, email/marketing, dev platforms, databases/data infra, monitoring/observability, CDN/edge, auth/identity, and generic bearer/JWT tokens (see §8).
- **G3 — Capability enumeration:** for a valid key, map exactly which services, scopes, resources, and permission levels it can reach — read-only.
- **G4 — Severity scoring:** compute an Info / Low / Medium / High / Critical rating from the enumerated capabilities, with a transparent, rule-based rationale (§6).
- **G5 — Disclosure-ready reporting:** emit reports suitable for pasting straight into HackerOne/Bugcrowd, with masked key, evidence, impact, and remediation (§7).
- **G6 — Extensible:** adding a new provider is a small, self-contained contribution (§9).
- **G7 — Safe, legal, deterministic:** read-only, authorized-use framing, no bundled exploitation, no nondeterministic components.

---

## 4. Non-goals

- **Not a secret scanner.** keyreach does not crawl repos, S3, or Docker images to *find* secrets — that is TruffleHog / gitleaks / Nosey Parker territory. keyreach consumes a key that's already been found (optionally piped in from those tools). This is a deliberate wedge, not a gap.
- **Not an exploitation framework.** No privilege escalation, lateral movement, or destructive actions (that is Pacu's domain).
- **Not a defensive CSPM/audit platform.** Continuous posture management across a whole cloud estate is Prowler/ScoutSuite's job.
- **No AI features.** No LLM-assisted classification, no "smart" heuristics that call a model. If a capability can't be decided by a rule, it is reported as `unknown`, never guessed by a model.

---

## 5. Prior art, resources & credits

keyreach stands on existing work. This section records what exists, what we reuse or learn from, and who to credit. A running `CREDITS.md`, `NOTICE`, and `THIRD_PARTY_LICENSES.md` must be maintained in the repo.

> **License discipline (product policy):** keyreach targets a permissive license (§10). **AGPL/GPL code cannot be copied in.** Where a resource is AGPL/GPL we may only *study behavior* and re-implement from public API documentation. Where a resource is MIT / Apache-2.0 / BSD / CC-BY we may reuse with attribution. Every third-party license must be re-verified from its repo before any code or data is reused.

### 5.1 Closest comparable — study, don't copy
- **TruffleHog** (Truffle Security) — the state of the art: finds, verifies, and (via its `analyze` command) enumerates permissions/resources for credentials across many providers, though deep permission analysis covers only a minority of its detectors. **AGPL-3.0** — behavioral study only; re-implement from public docs. keyreach differentiates by single-key ergonomics, AI-provider depth, transparent severity, and disclosure reports, and by being fully deterministic and scan-free.

### 5.2 Detection patterns
- **secrets-patterns-db** (Mazin Ahmed / mazen160) — the largest open pattern database (1600+ regexes), format-agnostic, confidence-tagged. **Studied only; not reused.** This entry originally read "CC-BY-4.0 — reusable with attribution, ideal to seed detection". Verifying that from the upstream repository before reuse (as §10 requires) showed the assumption was wrong, on two independent grounds:
  - Its `LICENSE.md` is **CC-BY-SA-4.0** ("Attribution-ShareAlike 4.0 International"), not CC-BY-4.0. ShareAlike obliges adaptations to carry the same license, which does not fit a permissively-licensed project. Its `README.md` separately claims CC-BY-4.0, contradicting its own license file; an ambiguous grant is read conservatively.
  - That `README.md` also states *"Trufflehog data is licensed under the AGPL"*, and the rule set carries no per-rule provenance, so AGPL-derived entries cannot be identified and excluded. Copying TruffleHog is forbidden outright (§5.1).

  keyreach therefore writes its detection patterns from **each provider's own public API documentation**, the same treatment §5.1 already mandates for AGPL prior art. A key's prefix and length are published facts about a format, not expressive work. Every rule records the vendor documentation URL it came from.
- **gitleaks** — MIT-licensed scanner with a well-curated ruleset. **MIT** — reusable with notice; currently used as a behavioural cross-check only, with nothing copied.
- **detect-secrets** (Yelp) — entropy-based detection plugins. Permissive (verify) — the entropy fallback for generic tokens is learned from its *approach* and re-implemented; no code reused.

### 5.3 Validation & capability-enumeration methodology
- **KeyHacks** (streaak) — the community cookbook of per-provider validation recipes across ~80+ providers. Primary methodology source; expect drift, re-verify each recipe against live docs. Methods (which endpoint to hit) are facts and freely re-implementable.
- **gmapsapiscanner** (Ozgur Alp) — Google `AIza` key scanner probing ~20 Google APIs (Maps, Places, Geocode, Roads, FCM, and Gemini Files). Blueprint for the Google provider; its author's own roadmap was to cover *all* Google APIs for greater impact — essentially our Google plugin. Reuse endpoint list and cost annotations (verify license; endpoints are factual).
- **enumerate-iam** (Andrés Riancho) — model for AWS read-only permission inference. Noisy by design, so this style of enumeration is opt-in and flagged in keyreach.
- **Pacu** / **GCPBucketBrute** (Rhino Security Labs) — study *enumeration* modules only (not exploitation) as a reference for inferring effective permissions and enumerating cloud resources.

### 5.4 Architecture & report references
- **Prowler** — multi-cloud assessment with a mature check architecture, severity model, and multi-format reports. Permissive (verify) — a proven design to learn from.
- **ScoutSuite** (NCC Group) — turns enumerated cloud permissions into a navigable report. GPL (verify) — study only.
- **nuclei** (ProjectDiscovery) — templated request engine; its declarative "request → match → verdict" model is a useful reference for a rule-based, deterministic probe format. MIT (verify).

### 5.5 UX reference
- **SecurityWall API Key Checker** (web) — identifies key type against 400+ patterns and *suggests* validation commands without executing them. keyreach's differentiator: it executes read-only probes and produces severity + report automatically and deterministically.

### 5.6 Credits policy
Credit, at minimum: TruffleHog (Truffle Security), KeyHacks (streaak), secrets-patterns-db (Mazin Ahmed), gmapsapiscanner (Ozgur Alp), enumerate-iam (Andrés Riancho), Pacu & GCPBucketBrute (Rhino Security Labs), gitleaks, detect-secrets (Yelp), Prowler, ScoutSuite (NCC Group), and nuclei (ProjectDiscovery) — in `CREDITS.md`, with required license text in `NOTICE`/`THIRD_PARTY_LICENSES.md` for anything reused, and inline attribution in any provider derived from a specific upstream.

---

## 6. Severity model (conceptual)

Severity is **computed deterministically from the capabilities keyreach actually confirmed** — never assigned per provider by name. The same set of confirmed capabilities always produces the same band and the same rationale.

**What drives severity:** the worst confirmed access level (read / write / admin), whether the key can reach **private or user data**, whether it can incur **direct financial cost** (LLM inference billing, cloud spend, SMS/email sending, payment operations), the **breadth** of reachable services, and whether restrictions (referrer/IP/app) appear to block real-world abuse (recorded and used to downgrade).

**Bands:**
- **Critical** — write/admin to sensitive data or money movement (e.g. a live payment key that can charge/refund; a cloud key with broad write/admin; a database key with read/write to production data). The privileged access and the sensitive reach must be **the same confirmed capability**: write access *here* plus sensitive data *there* is not write access to sensitive data, and a Critical filed on that pairing would not survive triage.
- **High** — read access to private user data, or the ability to spend money / send communications at scale (e.g. a key that can reach an LLM provider's uploaded-files or cached-content endpoints; a mail-sending key; an SMS-capable key).
- **Medium** — meaningful non-public functionality without direct data exfiltration or spend, or restricted-but-bypassable keys.
- **Low** — limited, largely public functionality; quota/billing nuisance only.
- **Info** — valid but effectively harmless.

**How restrictions are treated.** A restriction (referrer/IP/app) that appears to block use lowers the band by **one**, and only when it holds for *every* confirmed capability — a referrer check on one of five reachable services does not shrink the blast radius of the other four. It never lowers a band to Info from above. keyreach can observe that a restriction appears to be in force; it cannot prove the restriction holds, and HTTP referrer and IP restrictions are routinely bypassed by sending the header the check expects. That is exactly why "restricted-but-bypassable" sits at Medium above rather than being dismissed, and why collapsing a live payment key to Info on the strength of a spoofable header would be the worst mistake the severity model could make. An earlier draft of this section read "Info — valid but effectively harmless **or fully restricted**", which contradicted the Medium band directly above it; the safer reading wins.

**Every rating ships with its rationale** — the specific confirmed capabilities that drove the band. That rationale *is* the bounty argument, and it lets the receiving team verify the claim.

> Context to encode in docs: some programs historically rate, say, a bare Maps-only key as informational. keyreach's job is to surface the *full* reachable set (including any data or billing capabilities) with evidence, so a higher rating is justified by proof rather than assertion.

---

## 7. Reporting (conceptual)

A keyreach report is a self-contained, deterministic finding. Formats: terminal (default), and file outputs suitable for disclosure and for machine consumption.

**Every report contains:**
1. Title, computed **severity**, and a one-line impact statement.
2. **Masked** key fingerprint (the full secret is never shown unless explicitly opted in).
3. Provider, category, and detection timestamp.
4. **Validity & identity** — account / org / project / plan-or-tier where available.
5. **Capability map** — each reachable service with its access level, detail, and resource reference.
6. **Severity rationale** — which confirmed capabilities produced the band.
7. **Evidence** — for each capability, a masked, read-only request and a benign response summary that proves the access. This is what turns an informational report into a proven-impact one.
8. **Remediation** — provider-specific rotation/restriction guidance.
9. **Attribution footer** — tool name and version, for reproducibility.
10. **What could not be determined** — probes that failed, and why nothing was probed when nothing was. Added while building the reporting layer: without it, a run where three probes errored renders identically to one where three probes came back empty, and a partial capability map reads as a complete one. An absent finding is not the same as a negative finding, and a report that cannot tell the difference invites a reader to conclude more than keyreach established.

**On what the report must not claim.** A key nobody could identify was never tested, and a report for one says "not probed" rather than "not valid" — the second asserts that a provider refused the key, which is a stronger and different statement. The same discipline applies to the title and the impact line: both are derived from confirmed capabilities, never from the provider's name or the key's shape.

The report is stable: re-running the same key against the same provider state reproduces the same report byte-for-byte (modulo the timestamp).

---

## 8. Provider coverage roadmap (all key classes)

Prioritized by *leak frequency × blast radius*. Archetypes ship first (one cloud multi-service key, one AI key, one IAM-style key) to prove the model; breadth follows.

- **Cloud / infra:** Google Cloud `AIza` keys (Maps/Places/Geocode/Roads/Gemini/YouTube/FCM), AWS `AKIA`/`ASIA`, Azure & Azure DevOps, DigitalOcean, Cloudflare, Vercel, Netlify, Railway, Fly.io, Render, Heroku, Scaleway, Linode/Vultr.
- **AI / LLM (priority differentiator):** OpenAI, Anthropic, Google Gemini, Groq, Mistral, Cohere, Perplexity, HuggingFace, Replicate, ElevenLabs, Deepgram, Stability AI.
- **Payment / financial:** Stripe (live/test/restricted), PayPal, Square, Razorpay, Paystack, Flutterwave, Coinbase, Plaid, Brex.
- **Communications / messaging:** Slack, Twilio, Discord, Telegram, PubNub, Zoom.
- **Email / marketing:** SendGrid, Mailgun, Postmark, Resend, Mailchimp, HubSpot, Intercom.
- **Dev platforms / source / CI:** GitHub, GitLab, Bitbucket, npm, PyPI, Docker Hub, JFrog, CircleCI, Jenkins.
- **Databases / data infra:** MongoDB Atlas, Redis, PlanetScale, Neon, Supabase, Firebase, Turso, Snowflake; vector DBs Pinecone, Weaviate, Qdrant.
- **Monitoring / observability / secrets:** Datadog, New Relic, Sentry, Grafana, PostHog, Doppler, HashiCorp Vault, LaunchDarkly.
- **Auth / identity:** Auth0, Okta, Clerk, Firebase Auth.
- **Generic:** bearer/JWT inspector (decode and validate claims deterministically) and a user-directed generic bearer probe.

---

## 9. Extensibility (product view)

Adding a provider must be a small, self-contained, well-credited contribution: a way to recognize the key, a cheap read-only validity/identity check, a set of read-only capability probes, and provider metadata (docs, rotation guidance, upstream credit). Contributors should be able to add one quickly, and every provider must ship with recorded fixtures so it can be tested without a live key. Mechanics live in `implementation_plan.md`.

---

## 10. Licensing

- keyreach will be **permissively licensed** (Apache-2.0 recommended for its patent grant; MIT acceptable).
- Everything reused must be license-compatible and attributed: CC-BY (secrets-patterns-db) and MIT/Apache/BSD sources are fine with proper `NOTICE` attribution; AGPL/GPL work stays at arm's length (studied, never copied).

---

## 11. Safety, OpSec & ethics

- **Read-only by default;** any aggressive/permission-brute mode (if ever added) is off by default, explicitly flagged, and loudly warned.
- **Authorized-use framing** in `README.md` and `SECURITY.md`, with a first-run reminder.
- **OpSec awareness:** validation generates auth traffic and logs on the target service; keyreach keeps probe counts minimal, supports rate limiting/delays, and never hammers endpoints.
- **Masking** of keys in all output by default.
- **No exploitation modules** — keyreach stays a scoping-and-reporting tool.
- **No data exfiltration** — because there are no AI/LLM calls, keys and responses never leave the user's machine except as the direct, read-only API probes the tool makes to the key's own provider.

---

## 12. Risks & mitigations

| Risk | Mitigation |
|---|---|
| **API drift** (the thing that erodes cookbook-style tools) | Deterministic, declarative probes plus a scheduled drift-detection check that flags when provider responses change shape. |
| **A larger incumbent expands its permission analysis** | Compete on single-key UX, AI-provider depth, transparent severity, and disclosure reporting — not raw provider count. |
| **Abuse potential** | Read-only default, authorized-use framing, no exploitation modules, masking. |
| **License contamination** | Strict no-AGPL/GPL-copy rule; verify every reused license; maintain `NOTICE`. |
| **Nondeterminism creeping in** | Absolute ban on AI/LLM and on unseeded randomness or hidden time/network dependence in verdicts (enforced in `implementation_plan.md` and `CLAUDE.md`). |
| **Noisy enumeration alerting defenders** | Minimal probe counts, rate limiting, opt-in gating for anything aggressive. |

---

## 13. Definition of done — v0.1 (product outcomes)

- `keyreach <key>` deterministically detects, validates, enumerates, scores, and reports for **≥10 providers across ≥4 categories** (must include cloud, AI, payment, and comms).
- Disclosure-ready and machine-readable reports, each with a computed severity, a visible rationale, per-capability evidence, and remediation.
- Detection seeded from an attributed open pattern set.
- Zero AI/LLM calls anywhere; identical inputs reproduce identical findings.
- Complete repo governance docs present and accurate: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CREDITS.md`, `NOTICE`, `LICENSE`.

---

## 14. Open decisions

- Final license: Apache-2.0 (recommended) vs MIT.
- Implementation language (see `implementation_plan.md` for the recommendation and trade-offs) — does not affect this product plan.
- Which exact 10–15 providers ship in v0.1 from the roadmap in §8.
