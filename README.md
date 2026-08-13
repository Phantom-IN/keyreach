# keyreach

> Paste any leaked API key — cloud, AI, payment, comms, dev-tool, database, or
> SaaS — and get a full capability map plus a disclosure-ready security report
> with a computed severity, in one command.

[![PyPI](https://img.shields.io/pypi/v/keyreach)](https://pypi.org/project/keyreach/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![No AI/LLM](https://img.shields.io/badge/AI%2FLLM-none%20by%20design-brightgreen)](#core-principles)
[![Read-only by default](https://img.shields.io/badge/probes-read--only-brightgreen)](SECURITY.md)
[![CI](https://github.com/Phantom-IN/keyreach/actions/workflows/ci.yml/badge.svg)](https://github.com/Phantom-IN/keyreach/actions/workflows/ci.yml)
<!-- Coverage is enforced at 100% by CI (pyproject.toml, [tool.coverage.report]
     fail_under) rather than reported by a third-party badge service, which
     would mean sending build data to another host for a number CI already
     gates on. -->

> **v0.1.0 — the first release.**
>
> **Twenty-seven providers across seven categories, usable from a terminal.**
> The whole pipeline — detect → validate → enumerate → score → report — is built
> and covered: **cloud** (`google`, `aws`), **AI** (`openai`, `anthropic`),
> **payment** (`stripe`, `razorpay`, `paystack`, `paypal`), **communications**
> (`slack`, `twilio`, `telegram`, `discord`, `zoom`), **email/marketing**
> (`sendgrid`, `mailgun`, `postmark`, `resend`, `mailchimp`), and **dev
> platforms** (`github`, `gitlab`, `bitbucket`, `npm`, `dockerhub`), and
> **databases/data infra** (`mongodb`, `supabase`, `redis`, `pinecone`). Each key is
> scored from the capabilities keyreach actually confirmed, with the rationale
> attached.
>
> Code lands one roadmap item at a time, each on its own feature branch and
> pull request, so the whole build is auditable in the open. Phase 0
> (**R0.1**–**R0.9**) and Phase 1 (**R1.1**–**R1.6**) are done; Phase 2 is under
> way. Follow along in [`ROADMAP.md`](ROADMAP.md).

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

Python 3.11+.

```console
pipx install keyreach          # recommended: isolated, on your PATH
pip install keyreach           # or into an existing environment
```

From source:

```console
git clone https://github.com/Phantom-IN/keyreach.git
cd keyreach
pipx install -e .              # or: pip install -e '.[dev]'
keyreach --help
```

keyreach depends on `httpx`, `pydantic`, `typer`, `rich`, `Jinja2` and `PyYAML`,
and on nothing else. There is no AI/LLM SDK in any dependency group, runtime or
dev, and a CI check fails the build if one appears.

## Usage

```console
$ keyreach AIza...
    __                                   __
   / /_____  __  ______  ___  ____ _____/ /_
  / //_/ _ \/ / / / ___// _ \/ __ `/ ___/ __ \
 / ,< /  __/ /_/ / /   /  __/ /_/ / /__/ / / /
/_/|_|\___/\__, /_/    \___/\__,_/\___/_/ /_/
          /____/
  v0.1.0  |  deterministic  |  read-only  |  no AI
  Use only against keys you own or are explicitly authorized to test.
```

```console
keyreach KEY                      # detect → validate → enumerate → score → terminal report
keyreach KEY --report md -o out.md
keyreach KEY --json               # machine-readable, schema-validated
keyreach -f keys.txt              # batch from a file, one key per line
cat keys.txt | keyreach -f -      # batch from stdin (keeps keys out of shell history)
keyreach KEY --provider google    # force provider, skip detection
keyreach KEY --no-enumerate       # validity + identity only
keyreach KEY --aggressive         # opt-in noisy enumeration; off by default, warned
keyreach KEY --delay 500ms        # pace probes
keyreach KEY --unmask             # show full key (off by default)
keyreach KEY --fail-on high       # exit 2 if band >= high (CI gating)
keyreach KEY --quiet              # no banner, no warnings
```

**Some credentials are two halves, and keyreach takes them colon-joined.** AWS,
Twilio and Razorpay all authenticate with a pair, so paste the pair:

```console
keyreach 'AKIA...:<secret access key>'                  # AWS
keyreach 'ASIA...:<secret>:<session token>'             # AWS, temporary
keyreach 'AC<32 hex>:<auth token>'                      # Twilio
keyreach 'rzp_live_...:<key secret>'                    # Razorpay
keyreach 'CLIENT_ID:CLIENT_SECRET' --provider paypal    # PayPal
keyreach 'ACCOUNT_ID:CLIENT_ID:CLIENT_SECRET' --provider zoom   # Zoom
```

Half a credential is still recognised and still reported — keyreach tells you
which half is missing rather than calling a live credential dead, and it makes
no request it cannot authenticate.

**stdout is the report; stderr is everything else.** The banner, warnings and
errors go to stderr, so `keyreach KEY --json | jq` works and
`keyreach KEY --report md > finding.md` writes a file containing nothing but the
finding.

**Exit codes** — fixed, documented, and safe to gate CI on:

| Code | Meaning |
| --- | --- |
| `0` | Ran cleanly; nothing reached the `--fail-on` threshold |
| `2` | A finding at or above `--fail-on` |
| `1` | Something went wrong — bad flag, unreadable file, unknown provider |

`2` means a finding and nothing else. A malformed command line exits `1`, so a
typo in a CI config can never be mistaken for a Critical key.

HTML output (`--report html`) arrives in
[R2.9](ROADMAP.md#phase-2--breadth--depth).

## What the output looks like

Abridged `--report md` for a GitHub token — the full report also carries a
reproduction command and a documentation link for **every** capability, plus
remediation steps. This one is generated from a committed test fixture, so
nothing below came from a real account.

````markdown
# Exposed github API key reaches GitHub Repositories and 4 other services

**Severity: CRITICAL** — Anyone holding this key can change data or move money.
Treat this as an active compromise: rotate now, then audit for use.

| Field | Value |
| --- | --- |
| Provider | `github` (devtools) |
| Key | `ghp_*********************************AAA` |
| Status | valid |
| Account | northwind-ops |
| scopes | read:org, repo, user |

## Why this severity

- Write or admin access to a service holding private data or able to spend:
  GitHub Repositories (write) — Can list the account's private repositories,
  which is the source code the account was relying on nobody being able to
  read. The token holds repo, which GitHub documents as granting more than read
  over this resource. No write was attempted.
- Reaches 5 distinct services, so the exposure is the project rather than a
  single API.

## Capabilities

| Service | Access | Data | Cost |
| --- | --- | --- | --- |
| GitHub Account | write | no | no |
| GitHub Email Addresses | write | yes | no |
| GitHub Gists | read | yes | no |
| GitHub Organizations | read | no | no |
| GitHub Repositories | write | yes | no |

## Evidence

### GitHub Repositories — write

```text
GET https://api.github.com/user/repos?per_page=1&visibility=private
  -> 200, private repositories: 1 listed
```

Reproduce (read-only):

```console
curl -s -H 'Authorization: Bearer <key>' \
  'https://api.github.com/user/repos?per_page=1&visibility=private'
```
````

Three things in there are the product rather than the formatting. The **severity
is derived**, not assigned by provider name — `write` on private repositories
plus private data is what produced Critical, and the rationale says so in terms
a triager can check. The **evidence counts, never quotes**: it proves the key
listed a private repository without putting the repository's name in a bug
bounty report. And the **`write` was never performed** — it comes from the
`X-OAuth-Scopes` header GitHub documents, which is why the same token's
organization capability stays a read.

## Provider coverage

Prioritized by *leak frequency × blast radius*, across cloud/infra, AI/LLM,
payment, communications, email/marketing, dev platforms, databases/data infra,
monitoring, auth/identity, and a generic bearer/JWT inspector. The full target
list is [`plan.md`](plan.md) §8; the shipping order is
[`ROADMAP.md`](ROADMAP.md).

**27 providers across 7 categories.** v0.1 shipped 10 — the target was ≥10
across ≥4, including cloud, AI, payment and comms — R2.1 and R2.2 added two
each, R2.3 opened the email category with five, R2.4 took dev platforms to five,
and R2.5 opened databases with four. The count is asserted by a test rather than
counted by hand (`tests/test_provider_contract.py`), so a deleted provider or a
typo'd category fails the build.

| Provider | Category | Credential | What a live key is shown to reach |
| --- | --- | --- | --- |
| `google` | cloud | `AIza…` | Maps, Places, Geocoding, Roads; Gemini *reachability* |
| `aws` | cloud | `AKIA…:secret`, `ASIA…:secret:token` | caller identity, account/root detection, IAM and read-only service probes |
| `openai` | ai | `sk-…`, `sk-proj-…`, `sk-svcacct-…`, `sk-admin-…` | models, files, vector stores, fine-tunes; org projects, members and spend for admin keys |
| `anthropic` | ai | `sk-ant-…`, `sk-ant-admin…` | models, files; organization, members, API keys and cost for admin keys |
| `stripe` | payment | `sk_live_…`, `sk_test_…`, `rk_…` | account, balance, charges, customers, payment intents, payouts, subscriptions |
| `razorpay` | payment | `rzp_live_…:secret` | payments, orders, customers, settlements |
| `paystack` | payment | `sk_live_…`, `sk_test_…` | balance, customers, settlements, subaccounts, transactions |
| `paypal` | payment | `client_id:client_secret` *(needs `--provider paypal`)* | disputes, invoices, products, subscription plans — with write read from the granted OAuth scopes |
| `slack` | comms | `xoxb-…`, `xoxp-…` | workspace, members, channels, files |
| `twilio` | comms | `AC…:auth token` | account and tier, balance, message log, call log, phone numbers |
| `telegram` | comms | `<bot id>:<secret>` | bot identity, webhook target, commands; group-message reach when privacy mode is off |
| `discord` | comms | bot token *(needs `--provider discord`)* | application, bot identity, servers; message-content and member reach from the privileged-intent flags |
| `zoom` | comms | `account_id:client_id:client_secret` *(needs `--provider zoom`)* | users, cloud recordings, meetings, groups — with write read from the granted scopes |
| `sendgrid` | email | `SG.…` | account, profile, templates, suppressions, API keys — with write and send read from the scopes SendGrid publishes for the key |
| `mailgun` | email | account API key *(needs `--provider mailgun`)* | domains, mailing lists, inbound routes, API keys |
| `postmark` | email | server **or** account token *(needs `--provider postmark`)* | server config and bounces for a server token; every server, domain and sender signature for an account token |
| `resend` | email | `re_…` | API keys, audiences, broadcasts, domains — or, for a sending-only key, the send capability alone |
| `mailchimp` | email | `<hex>-<dc>` | account, audiences, campaigns, reports, automations — with access read from the role Mailchimp returns |
| `github` | devtools | `ghp_…`, `gho_…`, `github_pat_…` | account, private repositories, organizations, email addresses, gists |
| `gitlab` | devtools | `glpat-…` | account, private projects, groups — with write and admin read from the token's own scopes |
| `bitbucket` | devtools | `<email>:<api token>` *(needs `--provider bitbucket`)* | account, email addresses, workspaces |
| `npm` | devtools | access token *(needs `--provider npm`)* | every token on the account, staged package versions |
| `dockerhub` | devtools | `<identifier>:dckr_pat_…` / `dckr_oat_…` | repositories including private ones; org members, settings and tokens for an organization token |
| `mongodb` | database | `<client id>:<client secret>` *(needs `--provider mongodb`)* | Atlas organizations and projects — the list of every cluster the credential could reach |
| `supabase` | database | `<ref>:sb_secret_…` / `sb_publishable_…`, or a legacy JWT | auth settings, storage buckets, the exposed table schema, and the end-user list for a key that bypasses Row Level Security |
| `redis` | database | `<account key>:<secret key>` *(needs `--provider redis`)* | Redis Cloud subscriptions and the cloud accounts they deploy into |
| `pinecone` | database | `pcsk_…` | indexes, collections, backups and assistants — the shape of what the account has embedded |

**Severity is computed, and the differences are the point.** A `sk_live_` Stripe
key rates Critical and a `sk_test_` one does not, because Stripe documents
sandbox payments as not processed. A GitHub token holding `repo` is reported as
**write** access to private source code — read out of the `X-OAuth-Scopes`
header GitHub documents, not from a push keyreach made — while the same token's
organization capability stays a read, because `repo` grants nothing there.

**What keyreach declines to claim is as deliberate as what it reports.** It
never calls a model, so it cannot confirm that an AI key can run inference or
spend, and does not pretend to. It never sends an SMS, so a Twilio credential is
reported for the message log it can read rather than the toll fraud it could
probably commit. Where a vendor *documents* an access model — Stripe's
"unrestricted permissions on all Stripe APIs" for `sk_`, AWS's root user,
Anthropic's unscoped Console admin keys — keyreach reports the stronger verdict
and cites the sentence. Everywhere else it under-reports and says so. See
[`plan.md`](plan.md) §1.

**Two things about detection are worth knowing.**

*Some credentials cannot be detected at all.* PayPal, Discord and Zoom all
authenticate with credentials that are opaque strings — no published prefix,
length or charset. keyreach will not ship a rule guessed from that, because a
pattern matching "long opaque string, colon, long opaque string" would claim a
large share of every base64 blob a scanner emits, and Discord's community
three-segment pattern would claim every JWT. So name it yourself, and the report
records that you did rather than pretending a rule recognised it:

```console
keyreach 'CLIENT_ID:CLIENT_SECRET' --provider paypal
keyreach 'BOT_TOKEN' --provider discord
keyreach 'ACCOUNT_ID:CLIENT_ID:CLIENT_SECRET' --provider zoom
keyreach 'API_KEY' --provider mailgun
keyreach 'SERVER_OR_ACCOUNT_TOKEN' --provider postmark
keyreach 'EMAIL:API_TOKEN' --provider bitbucket
keyreach 'ACCESS_TOKEN' --provider npm
keyreach 'CLIENT_ID:CLIENT_SECRET' --provider mongodb
keyreach 'ACCOUNT_KEY:SECRET_KEY' --provider redis
```

*Supabase legacy keys name their own project.* An `anon` or `service_role` key
is a JWT carrying the project reference, so `--provider supabase` is enough. A
current `sb_secret_…` key is opaque and needs `<project ref>:<key>`.

*Mailgun and npm are providers keyreach could once detect and no longer can.*
Both shipped a rule from R0.5, and both vendors have since stopped documenting
any credential format — Mailgun's authentication page and npm's access-token
page each describe how to send a token and never what one looks like. A rule
nobody can re-verify is worse than no rule, so both were withdrawn; see
[`ROADMAP.md`](ROADMAP.md) R2.3 and R2.4. A withdrawn rule is not silence: the
entropy fallback still reports the value as a secret of unknown provenance.

*Firebase is deliberately absent.* Google documents that a Firebase API key
"only identifies your Firebase project and app" and that "none of the
Firebase-related APIs use an API key as authorization". A string that authorises
nothing has no capability map, and the same `AIza…` format *does* authorise
Google Cloud APIs — which the `google` provider already probes.

*PyPI is recognised and deliberately not probed.* Its token format is documented
and the rule is sound, but PyPI publishes exactly one endpoint that accepts an
API token — a package upload. keyreach will not perform a write to establish a
capability, so it reports the vendor, the severity and the rotation guide, and
stops there.

*Postmark's two token types look identical*, so keyreach does not ask you which
you have. It tries both headers, and Postmark's own refusal names the one it
wanted — a server token reaches one server's mail, an account token reaches
every server on the account and can create more.

*Some prefixes belong to two vendors.* Stripe and Paystack both document
`sk_live_` and `sk_test_`. keyreach probes both and reports whichever one
authenticates, rather than ranking a guess — so a `sk_live_` key costs one
wasted request against the vendor it does not belong to. `--provider` settles it
for free if you already know.

Enumeration is quiet by default. The wider AWS cross-service sweep is behind
`--aggressive`, because a sweep looks like reconnaissance to whoever is watching
the account.

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
