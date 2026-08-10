# Security policy

This document has two distinct parts:

1. **[Responsible use](#part-1--responsible-use)** — the rules for using
   keyreach, and the safety properties it guarantees.
2. **[Coordinated vulnerability disclosure](#part-2--coordinated-vulnerability-disclosure)** —
   how to report a security vulnerability **in keyreach itself**.

---

## Part 1 — Responsible use

keyreach is a security tool. It takes an API key and determines what that key can
reach, by making real authenticated requests to the key's own provider. Please
read this before using it.

### Authorized use only

**Use keyreach only against keys you own or are explicitly authorized to test.**
In practice that means one of:

- **Your own** credentials, on your own infrastructure.
- A key found **within the scope of a bug bounty program** that permits
  validating exposed credentials. Check the program's policy — some explicitly
  forbid using a discovered credential at all, and scope rules always win over
  what a tool makes technically possible.
- A key covered by a **documented penetration test or red-team engagement**, with
  written authorization from the asset owner.

Everything else is out of bounds. In particular, **do not** run keyreach against
keys found in public code, paste sites, breach dumps, or logs when you have no
authorization from the owner. That the key was carelessly exposed is not
authorization.

### Understand what validation does

Validating a key is not a passive act:

- It generates **authenticated API traffic** to a live production service.
- It creates **log entries and audit trail records** on the target account, often
  including your source IP.
- It may **trigger security alerting** on the receiving side.
- It may consume **quota** on the target account.

Testing credentials without authorization may be illegal in your jurisdiction —
regardless of how the key was exposed. Laws such as the US Computer Fraud and
Abuse Act, the UK Computer Misuse Act, and equivalents elsewhere can apply to
merely *using* a credential you weren't given permission to use. **You are
responsible for ensuring your use is lawful and authorized.** The authors and
contributors accept no liability for misuse.

### What keyreach guarantees

These are design constraints, enforced in code and CI — not aspirations
([`plan.md`](plan.md) §1 and §11):

- **Read-only by default.** Every probe is non-destructive. keyreach does not
  write, delete, modify, or spend. The shared HTTP layer **default-denies**
  non-idempotent methods (POST/PUT/PATCH/DELETE); the rare read endpoint that
  requires POST must be explicitly annotated and reviewed.
- **No exploitation features.** No privilege escalation, no lateral movement, no
  destructive actions. keyreach is a scoping-and-reporting tool, and that is a
  permanent scope decision ([`plan.md`](plan.md) §4) — not a missing feature.
  Pull requests adding exploitation capability will be rejected.
- **Your key never leaves your machine, except to its own provider.** Because
  there are **zero AI/LLM calls** and no telemetry anywhere in keyreach, the only
  outbound traffic is the direct, read-only probes to the key's own provider
  API. Nothing is sent to us, and nothing is sent to a third party.
- **Keys are masked by default** — in terminal output, reports, logs, evidence
  strings, and recorded test fixtures. The full secret appears only if you
  explicitly pass `--unmask`.
- **Minimal probing.** keyreach probes the fewest endpoints that prove a
  capability, supports `--delay` for rate limiting, and never hammers a provider.
- **Deterministic and auditable.** Every verdict traces to a concrete rule and a
  concrete API response, so anything keyreach claims can be independently
  verified — by you, and by whoever receives your report.

### Handling reports and evidence

A keyreach report contains evidence that a credential was live and what it could
reach. Treat the report itself as sensitive:

- Keep the key **masked** — the default. Only use `--unmask` when you have a
  specific reason, and never paste an unmasked key into a bug bounty submission,
  a ticket, or a chat.
- Report evidence may include fragments of account or organisation data returned
  by the provider. Redact anything beyond what is needed to prove impact.
- Disclose to the **affected party**, through the appropriate channel (the bounty
  program, the vendor's security contact, or your engagement's reporting path).
  Publishing a live-credential finding publicly before it is rotated harms the
  people whose data is behind that key.
- **Recommend rotation first.** A keyreach report includes provider-specific
  rotation and restriction guidance — lead with that.

### If you are here because your key leaked

Rotate it now, before anything else. Then check the provider's audit logs for
use you don't recognise, and apply restrictions (referrer/IP/app restrictions,
scoped permissions, spend limits) to the replacement.

---

## Part 2 — Coordinated vulnerability disclosure

This section is about vulnerabilities **in keyreach itself** — not about keys you
have found with it.

### How to report

**Please do not open a public GitHub issue for a security vulnerability.**

Report privately to: **<SECURITY_CONTACT_EMAIL>**

If GitHub Private Vulnerability Reporting is enabled on the repository, you may
also use the **Security → Report a vulnerability** tab at
`https://github.com/Phantom-IN/keyreach/security/advisories/new`.

Include as much of the following as you can:

- The type of issue and the component affected (detection, engine/HTTP layer,
  scoring, reporting, CI, packaging).
- The affected version, commit SHA, or branch.
- Step-by-step reproduction instructions, and a proof of concept if you have one.
- The impact — what an attacker gains, and under what preconditions.
- Any suggested fix or mitigation.

**Never include a real API key in your report.** Use a synthetic or already-
rotated credential to demonstrate the issue. If a real key is genuinely
unavoidable, say so first and we will arrange a secure channel — do not send it
unprompted.

### What we consider a vulnerability

Given what keyreach does, these are the categories we care about most:

- **Secret leakage** — a key appearing unmasked anywhere it shouldn't: terminal
  output, report files, logs, error messages, stack traces, recorded cassettes,
  or CI output, without `--unmask`.
- **Unintended outbound traffic** — a key or response data reaching any host
  other than the key's own provider. This includes any AI/LLM endpoint,
  telemetry, or analytics. **There should be none, ever.**
- **Read-only guard bypass** — any path that lets a probe perform a write,
  delete, or spend operation, or that circumvents the non-idempotent-method
  default-deny.
- **Code execution or injection** — via a crafted key, a provider response, a
  YAML probe definition, a pattern file, or a report template (including
  template injection through Jinja2, or HTML/XSS injection into a rendered HTML
  report).
- **Path traversal or unsafe file writes** — via `-o` output paths, fixture
  loading, or provider/pattern discovery.
- **Supply-chain issues** — a compromised, typosquatted, or unexpectedly
  AI/LLM-linked dependency; a weakness in the release or publish workflow.
- **Determinism or integrity breaks that could falsify a report** — anything that
  makes keyreach assert a capability it did not actually confirm, since reports
  are used as evidence in disclosures.

### What is not a vulnerability

- **keyreach validating a key that you were not authorized to test.** That is the
  user's responsibility (see Part 1), not a flaw in the tool.
- **A provider's API behaving insecurely.** Report that to the provider; we will
  happily help you frame it.
- Findings from an automated scanner with no demonstrated impact.
- Missing hardening that has no exploitation path, absent a concrete scenario.
- Denial of service against the user's own machine via absurd inputs, unless it
  is triggerable by a provider response.

### Our commitments

- **Acknowledgement within 3 business days** of your report.
- **An initial assessment within 7 days**, including whether we accept the issue
  and a rough remediation timeline.
- **Regular updates** — at least every 14 days while the issue is open.
- **A fix released as fast as severity warrants.** Target: 30 days for high and
  critical severity, 90 days for lower severity.
- **Credit** in the advisory and [`CHANGELOG.md`](CHANGELOG.md) for the reporter,
  unless you prefer to stay anonymous.
- **We will not take legal action** against you for good-faith security research
  that follows this policy: research only against your own installation, no
  access to or exfiltration of other people's data, no service disruption, and
  no public disclosure before a fix is available.

### What we ask of you

- **Give us a chance to fix it first.** Please do not disclose publicly until a
  fix is released, or until 90 days have passed, whichever comes first. If you
  believe the issue is being actively exploited, tell us — we will move faster
  and can coordinate an earlier disclosure.
- Test only against your own installation. Do not access other people's data,
  degrade any service, or use social engineering.
- Report promptly once you find something.

### Supported versions

keyreach is pre-release; there is no published version yet. Until v0.1.0 ships
(roadmap item **R1.6**), only the `main` branch is supported and fixes land
there. After the first release, this section will list supported version ranges.

| Version | Supported |
| --- | --- |
| `main` (pre-release) | ✅ |

---

*Questions about this policy: **<SECURITY_CONTACT_EMAIL>**.*
