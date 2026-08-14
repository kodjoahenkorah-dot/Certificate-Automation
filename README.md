# Certificate Renewal Automation

**Opt-in automated SSL/TLS certificate renewal for a multi-tenant cloud posture management platform.**

[![CI](https://github.com/kodjoahenkorah-dot/Certificate-Automation/actions/workflows/ci.yml/badge.svg)](https://github.com/kodjoahenkorah-dot/Certificate-Automation/actions/workflows/ci.yml)
![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4)
![Next.js 14](https://img.shields.io/badge/Next.js-14-000000)
![Tests](https://img.shields.io/badge/tests-85%20passing-3fb950)

A production-oriented feature package that lets a cloud management platform **renew expiring
certificates automatically** — safely, one explicitly opted-in certificate at a time, across many
tenants, with a complete audit trail and a manual fallback for certificates that cannot be
automated.

Built as a standalone, integration-ready package against a documented interface boundary, then
adopted into the host product's certificate management module.

---

## The problem

The platform already scanned customers' Azure estates and raised **Critical** findings such as
*"SSL/TLS certificate has expired — certificate 'ci-grc-pfx' expired 333 days ago."* It could
identify the problem, but not fix it. Every renewal was manual work, and expired certificates
break HTTPS for real production services.

The hard part isn't calling a renewal API. It's doing it **safely** in a multi-tenant system:
never touching a certificate nobody asked you to touch, never letting one tenant's job reach
another tenant's cloud resources, and never silently failing on the certificates that can't be
automated at all.

## The solution

| Certificate type | How it renews |
|---|---|
| Azure Key Vault (with issuer policy) | New version issued via `Azure.Security.KeyVault.Certificates` |
| Azure Key Vault (imported) | Not re-issuable by Azure → owner-assigned Work Item |
| App Service **managed** certificate | Re-issued via `Azure.ResourceManager.AppService` |
| App Service **uploaded** certificate | Not re-issuable by Azure → owner-assigned Work Item |
| External, ACME CA (Let's Encrypt / ZeroSSL) | ACME (RFC 8555) with DNS-01 / HTTP-01 validation |
| External, commercial CA (GlobalSign, Sectigo, GoDaddy…) | Work Item with issuer-specific renewal instructions |

## Safety model

This is the part that mattered most, and where most of the design effort went.

- **Opt-in is enforced in the engine, not the UI.** Renewal requires a policy record with an
  explicit `AutoRenewEnabled` flag *and* a recorded actor and timestamp. The gate runs on every
  path — scheduled sweep, REST trigger, even `force: true`. A UI bug cannot cause a renewal.
- **Dry-run is the default**, resolved across three levels (global → tenant → certificate). Any
  level requesting dry-run wins. Dry-run executes the full pipeline and writes audit records
  describing exactly what a live run *would* do, while performing zero mutations.
- **Tenant isolation is structural.** Every query is tenant-filtered, the engine re-verifies the
  certificate's tenant before each attempt, and cloud credentials are resolved from the
  certificate's own tenant — never a shared credential.
- **Trust-but-verify.** After a live success, the provider re-reads the resource from Azure and
  confirms the expiry actually moved before the attempt is recorded as successful.
- **Bounded retries with escalation.** Three attempts with a cooldown, then an owner-assigned
  Work Item — no infinite retry loops against a cloud API.
- **Idempotent per expiry cycle.** Work Items and approvals are deduplicated on
  `(tenant, certificate, current expiry date)` in application logic *and* by a database unique
  constraint, so repeated sweeps can never create duplicates.
- **Optional human-in-the-loop mode**, where each renewal waits for a recorded approval — a
  deliberate stepping stone between dry-run and full automation.

## Architecture

```
              Certificate detail panel (Next.js 14)
                 CertificateRenewalPanel.tsx
                            │ REST
                            ▼
              CertRenewal.Api  (minimal APIs, thin)
                            │
   host scheduler ──▶ RenewalSweepJob  (per-tenant sweep)
                            │
                            ▼
              CertRenewal.Core ── RenewalEngine
   ┌────────────────────────┼─────────────────────────────┐
   │  PolicyGuard           │                             │
   │   opt-in gate          ▼                             ▼
   │   window math      providers                 integration ports
   │   retry budget      ├─ CertRenewal.Azure      INotifier
   │   dry-run rules     ├─ CertRenewal.Acme       IWorkItemSink
   │   approval gate     └─ ManualFallbackProvider ITenantCredentialResolver
   └────────────────────────┼─────────────────────────────┘
                            ▼
              CertRenewal.EntityFramework  (EF Core)
```

Renewal pipeline, per certificate:

```
load (tenant-filtered) → tenant-scope check → OPT-IN GATE → approval gate
  → renewal window → retry budget → method selection → dry-run resolution
  → provider.RenewAsync → provider.VerifyAsync → audit record
  → certificate write-back → Work Item escalation → owner notification
```

The core engine depends on nothing but `Microsoft.Extensions.Logging.Abstractions`. Azure SDKs,
ACME, EF Core, and ASP.NET Core all live in adapter projects behind interfaces, so the business
rules are testable in milliseconds and the host application's framework choices stay unconstrained.

## Tech stack

**Backend** — .NET 8 · ASP.NET Core minimal APIs · EF Core 8 · xUnit
**Cloud** — Azure Key Vault SDK · Azure Resource Manager (App Service, DNS) · Azure Identity
**Protocols** — ACME / RFC 8555 (Certes) with DNS-01 and HTTP-01 challenge support
**Frontend** — Next.js 14 · React · TypeScript (strict), zero UI dependencies

## Repository layout

```
dotnet/
  CertRenewal.sln
  src/
    CertRenewal.Core/              engine, policy gates, domain models, integration ports
    CertRenewal.Azure/             Key Vault + App Service renewal providers
    CertRenewal.Acme/              ACME provider, challenge-solver / installer ports,
                                   Azure DNS DNS-01 solver
    CertRenewal.EntityFramework/   EF Core entities, DbContext, repositories
    CertRenewal.Api/               REST endpoints, auth port, sweep background service
  tests/
    CertRenewal.Core.Tests/               81 engine tests
    CertRenewal.EntityFramework.Tests/     4 persistence tests (SQLite)
  migrations/                      plain-SQL alternative to EF migrations
frontend/
  CertificateRenewalPanel.tsx      opt-in panel: toggle, window, mode, attempt history
  renewalApi.ts                    typed API client
README_INTEGRATION.md              integration guide for the host application
DELIVERY_REPORT.md                 delivery summary
```

## Running it

```bash
cd dotnet
dotnet build CertRenewal.sln
dotnet test                 # 85 tests
```

No cloud credentials or database are required to run the test suite — the engine tests use
in-memory repositories and fake providers, and the persistence tests run against in-memory SQLite.

## Testing approach

85 xUnit tests, organised around the guarantees rather than the classes:

- opt-in fails closed, and `force` cannot bypass it
- renewal-window arithmetic, including already-expired certificates
- dry-run resolution across all three configuration levels
- retry cooldown, budget exhaustion, and Work Item escalation
- cross-tenant renewal rejected; credentials resolved from the certificate's own tenant
- commercial-CA fallback: Work Item severity, assignee, and instruction content
- approval create / approve / reject / no-duplicate-per-cycle
- verification failure downgrades a reported success to a failure
- EF Core repositories against a real database: entity round-trips, tenant filtering,
  failure-streak and dedup queries, unique-constraint enforcement

The persistence tests exist because EF mapping defects only surface when a real database
materialises the model — and they immediately caught a provider-portability bug that unit tests
alone would have missed.

## Design notes

<details>
<summary><b>Why every integration point is an interface</b></summary>

The package was written without access to the host codebase. Every place it touches the existing
product — certificates table, cloud credentials, work items, notifications, authentication,
scheduling — is a small interface with a documented default implementation, so integration is
additive rather than invasive.
</details>

<details>
<summary><b>Why dry-run instead of shipping the feature disabled</b></summary>

A disabled feature proves nothing. Dry-run exercises the entire pipeline in the real environment
and produces audit records as evidence that live behaviour will be correct — which makes the
rollout decision data-driven instead of hopeful.
</details>

<details>
<summary><b>Why the expiry date is the idempotency key</b></summary>

It is stable for an entire renewal cycle and changes exactly when the problem is solved. That
gives deduplication of work items and approvals without timers, tombstones, or state machines.
</details>

<details>
<summary><b>Why verify after a reported success</b></summary>

Cloud APIs can report success while the visible resource lags or an operation only partially
applies. One extra read prevents recording — and acting on — a renewal that did not stick.
</details>

## Status

Delivered as a standalone package and integrated into the host platform's certificate management
module. The engine, policy, and persistence layers are covered by the test suite; the cloud
provider calls are written against current SDK surfaces and are designed to be validated through
the documented dry-run-first rollout (dry-run → single pilot tenant → staged expansion) before
running live against production certificates.
