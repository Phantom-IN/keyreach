# keyreach

> Paste any leaked API key — cloud, AI, payment, comms, dev-tool, database, or
> SaaS — and get a full capability map plus a disclosure-ready security report
> with a computed severity, in one command.

[![Status: early — building in public](https://img.shields.io/badge/status-early%20%C2%B7%20building%20in%20public-orange)](ROADMAP.md)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![No AI/LLM](https://img.shields.io/badge/AI%2FLLM-none%20by%20design-brightgreen)](#core-principles)
[![Read-only by default](https://img.shields.io/badge/probes-read--only-brightgreen)](SECURITY.md)
[![CI](https://github.com/Phantom-IN/keyreach/actions/workflows/ci.yml/badge.svg)](https://github.com/Phantom-IN/keyreach/actions/workflows/ci.yml)
<!-- A PyPI badge is added in roadmap item R1.6, once the package is published.
     Coverage is enforced at 100% by CI (pyproject.toml, [tool.coverage.report]
     fail_under) rather than reported by a third-party badge service, which
     would mean sending build data to another host for a number CI already
     gates on. -->

> **⚠️ Status: early — building in public**
>
> **Four providers work; the CLI does not expose them yet.** The whole
> pipeline — detect → validate → enumerate → score → report — is built, and
> **Google `AIza`**, **OpenAI `sk-…`**, **Anthropic `sk-ant-…`** and **AWS
> `AKIA`/`ASIA`** credentials are supported, each scored with a rationale. But
> the CLI still answers only `--help` and `--version` — wiring the pipeline
> behind it is **R1.5** — so today that capability is reachable from Python, not
> from a terminal. Everything else below the fold describes the destination.
>
> Code lands one roadmap item at a time, each on its own feature branch and
> pull request, so the whole build is auditable in the open. Follow along in
> [`ROADMAP.md`](ROADMAP.md): **R0.1**–**R0.9** (Phase 0) and **R1.1**–**R1.3**
> are done. Next is **R1.4**, the interface checkpoint, and then **R1.5**, the
> CLI that makes all of it usable from a terminal.

---

## What it is

When a hunter finds an exposed key — a Google `AIza…`, an OpenAI `sk-…`, an AWS
`AKIA…`, a Stripe `sk_live_…`, a Slack `xoxb-…` — the value of that finding
depends entirely on **what the key can actually do**. Answering that today means
chaining a different tool per provider, ad-hoc `curl` recipes for everything
else, and hand-writing the report every single time.

keyreach collapses that into one deterministic command. Give it a key you own or
are authorized to test, and it:

- identifies which provider the key belongs to, by rule;
- confirms whether it is live and whose account it belongs to;
- enumerates, **read-only**, exactly which services, scopes, and resources it
  reaches;
- computes a severity band (Info → Critical) from those confirmed capabilities,
  with a visible rationale;
- emits a disclosure-ready report — masked key, per-capability evidence, impact,
  and remediation — ready to paste into a HackerOne or Bugcrowd submission.

It is built for bug bounty hunters, pentesters, red teams, and blue teams doing
exposure triage.

## What it is NOT

keyreach is deliberately narrow. Knowing what it *won't* do is as important as
knowing what it will.

| It is not… | Because that is… |
| --- | --- |
| **A secret scanner.** keyreach never crawls repos, S3 buckets, or Docker images looking for secrets. It starts from a key you already have — optionally piped in from a scanner. | TruffleHog / gitleaks / Nosey Parker territory. This is a deliberate wedge, not a gap. |
| **An exploitation framework.** No privilege escalation, no lateral movement, no destructive actions, no spend. | Pacu's domain. keyreach stays a scoping-and-reporting tool. |
| **A CSPM / continuous audit platform.** No posture management across a whole cloud estate. | Prowler / ScoutSuite's job. |
| **An AI tool.** No LLM-assisted classification, no "smart" heuristics that call a model, ever. | See below — it is a hard architectural constraint, not a preference. |

## Core principles

These are non-negotiable and shape every decision downstream
([`plan.md`](plan.md) §1).

1. **Deterministic and rule-based — no AI/LLM, ever.** keyreach contains **zero**
   AI or LLM calls and zero AI/LLM SDK dependencies, anywhere. Detection,
   validation, enumeration, scoring, and reporting are all driven by explicit
   rules and real provider responses. Three reasons this is non-negotiable:
   - **Security** — keyreach handles live secrets. Sending a key to an external
     model would itself be a credential leak.
   - **Reproducibility** — the same key against the same provider state must
     always produce the same capability map, severity, and report. A finding you
     can't reproduce is a finding you can't report.
   - **Auditability** — every verdict traces to a concrete rule and a concrete
     API response, so both you and the team receiving your report can verify
     exactly why the tool said what it said.

   If a rule can't decide a capability, keyreach reports it as `unknown`. It
   never guesses. A CI check (`ai_ban`) fails any build that introduces an
   AI/LLM dependency or model endpoint.
2. **Read-only by default.** Every probe is non-destructive. keyreach never
   writes, deletes, or spends money in its default operation. The HTTP layer
   default-denies non-idempotent methods; anything aggressive is opt-in,
   explicitly flagged, and loudly warned.
3. **Single-key ergonomics.** One key in, full picture out. No scanning workflow
   to wade through.
4. **Transparent severity.** Severity is computed from the capabilities keyreach
   actually confirmed, with a visible rationale — never a hardcoded per-provider
   label. That rationale *is* the bounty argument.
5. **Authorized use only.** Built for keys you own or are explicitly authorized
   to test — bounty scope or engagement. See [`SECURITY.md`](SECURITY.md).

## How it works

```
detect → validate → enumerate → score → report
```

- **detect** — deterministic pattern and entropy rules identify the provider.
- **validate** — the cheapest read-only liveness and identity call.
- **enumerate** — read-only probes map which services, scopes, and resources the
  key reaches.
- **score** — a pure, rule-based function turns confirmed capabilities into a
  severity band plus rationale.
- **report** — terminal, JSON, Markdown, or HTML output; masked key, evidence,
  impact, remediation.

Provider plugins **declare** probes; the engine **executes** them through a
single shared HTTP layer that owns rate limiting, record/replay, redaction, and
the read-only guard. That is what makes determinism enforceable in one place —
see [`implementation_plan.md`](implementation_plan.md) §2.

## Install

The `keyreach` name is reserved on PyPI, but **there is no installable release
yet** — only a `0.1.0.dev0` placeholder. `pip install keyreach` resolves nothing
on purpose: pip skips pre-releases by default, so nobody installs a tool that
cannot do anything. The first real release is
[R1.6](ROADMAP.md#phase-1--archetype-providers--mvp-v01).

```console
# Not available yet — planned for v0.1.0:
pipx install keyreach
```

To run the current scaffold from source (Python 3.11+):

```console
git clone https://github.com/Phantom-IN/keyreach.git
cd keyreach
pipx install -e .        # or: pip install -e '.[dev]'
keyreach --help
```

## Usage

> **Coming soon.** Right now only `--help` and `--version` do anything. The CLI
> surface below is the specification from
> [`implementation_plan.md`](implementation_plan.md) §12, not a description of
> working software. CLI UX lands in roadmap item
> [R1.5](ROADMAP.md#phase-1--archetype-providers--mvp-v01).

```console
keyreach KEY                      # detect → validate → enumerate → score → terminal report
keyreach KEY --report md -o out.md
keyreach KEY --report html -o out.html
keyreach KEY --json               # machine-readable, schema-validated
keyreach -f keys.txt              # batch from file
cat keys.txt | keyreach -         # batch from stdin
keyreach KEY --provider google    # force provider, skip detection
keyreach KEY --no-enumerate       # validity + identity only
keyreach KEY --aggressive         # opt-in noisy enumeration; off by default
keyreach KEY --delay 500ms        # rate-limit probes
keyreach KEY --unmask             # show full key (off by default)
keyreach KEY --fail-on high       # exit nonzero if band >= high (CI gating)
```

Planned exit codes: `0` success/info, `2` a finding at or above the `--fail-on`
threshold, `1` operational error.

## Provider coverage

Prioritized by *leak frequency × blast radius*, across cloud/infra, AI/LLM,
payment, communications, email/marketing, dev platforms, databases/data infra,
monitoring, auth/identity, and a generic bearer/JWT inspector. The full target
list is [`plan.md`](plan.md) §8; the shipping order is
[`ROADMAP.md`](ROADMAP.md).

**v0.1 target:** ≥10 providers across ≥4 categories, including cloud, AI,
payment, and comms.

**Shipped so far:** `google` (cloud), `openai` (ai), `anthropic` (ai), `aws`
(cloud) — 4 providers across 2 categories.

**AWS takes two halves.** Every other provider authenticates with one string;
AWS signs each request with an access key ID *and* a secret access key, so
keyreach accepts them joined by a colon — `AKIA…:<secret>`, or
`ASIA…:<secret>:<session token>` for temporary credentials. A bare `AKIA…` is
still recognised and reported; it just cannot be probed, and keyreach says which
half is missing instead of calling the credential dead. AWS enumeration is
deliberately quiet by default: six read-only calls about the credential itself.
A wider cross-service sweep exists behind an explicit opt-in
(`--aggressive`, R1.5), because a sweep looks like reconnaissance to whoever is
watching the account.

For AI keys specifically, note what keyreach will *not* tell you: it never calls
a model, so it cannot confirm that an exposed key can run inference or spend
money, and it does not claim otherwise. Both vendors scope keys per endpoint, so
listing models does not imply generating with them. keyreach reports what it
confirmed — reachability, uploaded files, fine-tunes, organization access — and
says which claims it did not test. See [`plan.md`](plan.md) §1.

## Documentation

| Document | What it covers |
| --- | --- |
| [`plan.md`](plan.md) | The product plan — *what* keyreach is and *why*. Scope, goals, non-goals, severity model intent, report contents, safety policy. |
| [`implementation_plan.md`](implementation_plan.md) | The technical blueprint — *how* it is built. Architecture, interfaces, determinism enforcement, testing, CI guardrails, CLI spec. |
| [`ROADMAP.md`](ROADMAP.md) | Every planned item, with acceptance criteria. One item per feature branch. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Dev setup, the build-in-public workflow, commit conventions, and the hard rules. |
| [`SECURITY.md`](SECURITY.md) | Responsible use, and how to report a vulnerability in keyreach itself. |
| [`CLAUDE.md`](CLAUDE.md) | Working rules for agents and contributors touching this repo. |
| [`CREDITS.md`](CREDITS.md) | The prior art keyreach learns from and reuses. |

## Contributing

Contributions are very welcome — especially new provider plugins. The target is
that adding a provider is a small, self-contained, ~30-minute contribution:
recognize the key, one cheap read-only validity check, a set of read-only
probes, and metadata.

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md), then the provider checklist in
[`CLAUDE.md`](CLAUDE.md). Every roadmap item is tracked as an issue and lands via
its own pull request.

## Legal & ethics

**Use keyreach only against keys you own or are explicitly authorized to test** —
your own infrastructure, an in-scope bug bounty program, or a documented
engagement. Validating a key generates authentication traffic and log entries on
the target service. Testing credentials without authorization may be illegal in
your jurisdiction, regardless of how the key was exposed.

keyreach is read-only by design and ships no exploitation features, but the
responsibility for authorization is yours. The authors accept no liability for
misuse. Full policy: [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Third-party attributions are recorded in [`NOTICE`](NOTICE) and
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md). keyreach never copies
AGPL/GPL code; such projects are studied and re-implemented from public
documentation only.

## Credits

keyreach builds on work by the TruffleHog team, streaak (KeyHacks), Mazin Ahmed
(secrets-patterns-db), Ozgur Alp (gmapsapiscanner), Andrés Riancho
(enumerate-iam), Rhino Security Labs, gitleaks, Yelp (detect-secrets), Prowler,
NCC Group (ScoutSuite), and ProjectDiscovery (nuclei).

Full acknowledgements: [`CREDITS.md`](CREDITS.md).
