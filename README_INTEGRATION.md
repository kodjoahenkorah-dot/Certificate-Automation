# CertRenewal — Opt-in Automated Certificate Renewal for Clear Ops

A standalone **.NET 8** solution + **Next.js (React/TSX)** component that adds
strictly opt-in automated SSL/TLS certificate renewal to Clear Ops. It is
designed to be integrated into the existing multi-tenant backend with minimal
coupling: the core engine (`CertRenewal.Core`) has no cloud, EF, or ASP.NET
dependencies, and every touchpoint with the existing product is an explicit,
documented interface.

## Safety properties (read this first)

1. **Auto-renew is OFF by default, everywhere.** A certificate with no policy
   row, or a disabled policy, is never renewed. The gate lives in
   `PolicyGuard.AssertOptedIn` and is enforced inside the engine on **every**
   attempt — scheduler sweeps, API triggers, and `force: true` all pass
   through it. Enabling requires a non-empty actor identity; the policy
   records `EnabledBy` + `EnabledAt` (and `DisabledBy`/`DisabledAt`).
2. **Dry-run is ON by default** (`CERT_RENEWAL_DRY_RUN=true` unless explicitly
   set to `false`). Dry-run attempts execute the full pipeline and write audit
   rows marked `DryRun = true`, but providers make **no mutating calls** (no
   Key Vault writes, no ACME orders, no DNS records, no Work Items). Dry-run
   wins if *any* level requests it: global options, per-tenant list
   (`CERT_RENEWAL_DRY_RUN_TENANTS`), or per-certificate policy override.
3. **Tenant isolation is structural.** Every repository method filters by
   `tenantId`; the engine cross-checks `cert.TenantId` against the job's
   tenant before every attempt (`TenantScopeException` otherwise) and resolves
   Azure credentials from the *certificate's* tenant, never a shared one.
4. **Everything is audited.** Every attempt — dry-run, failed, skipped-to-
   manual — is a `cert_renewal_attempts` row with status, timestamps, new
   expiry/thumbprint on success, error text on failure, and the Work Item id
   when one was created.
5. **Optional human-in-the-loop mode.** A policy can be set to
   `RenewalMode.ApprovalRequired`: the sweep then creates one
   `RenewalApproval` per expiry window and pauses; renewal runs only after a
   user approves it (approve/reject endpoints record who and when).
   `force` cannot bypass this gate.
6. **Idempotent per expiry window.** Approvals and fallback Work Items are
   deduplicated on (tenant, certificate, current-expiry-date), so repeated
   sweeps can never create duplicates within one renewal cycle. A successful
   renewal changes the expiry and naturally opens a new window.
7. **Trust-but-verify.** After a live renewal reports success, the engine
   calls the provider's `VerifyAsync` hook, which re-reads the resource from
   Azure and confirms the new expiry actually took; a failed verification is
   recorded as a Failed attempt and the certificates table is not updated.

## Architecture

```
              Certificates page (Next.js)
              frontend/CertificateRenewalPanel.tsx
                        │ REST
                        ▼
          CertRenewal.Api (minimal-API endpoints, thin)
                        │
   Scans scheduler ──▶ RenewalSweepJob (per-tenant sweep)
   (or RenewalSweepHostedService, hourly BackgroundService)
                        │
                        ▼
                 CertRenewal.Core ── RenewalEngine
   ┌────────────────────┼────────────────────────────────┐
   │ PolicyGuard        │                                │
   │  opt-in gate       ▼                                ▼
   │  window math   providers                     integration ports
   │  retry budget   ├─ CertRenewal.Azure ─ KeyVaultRenewalProvider
   │  dry-run calc   │                     └ AppServiceRenewalProvider
   │  approval gate  ├─ CertRenewal.Acme ─ AcmeRenewalProvider
   └─────────────────│      (+ IChallengeSolver / ICertificateInstaller,
                     │       AzureDnsChallengeSolver included)
                     └─ ManualFallbackProvider ─ IWorkItemSink
                        │                                │
                        ▼                                ▼
        repository interfaces (Core)             INotifier
        CertRenewal.EntityFramework (EF impl)    IWorkItemSink
                                                 ITenantCredentialResolver
```

Renewal flow per certificate:

```
load cert (tenant-filtered) → tenant-scope check → OPT-IN GATE
  → approval gate (ApprovalRequired mode) → renewal-window check
  → retry budget/cooldown → method selection → dry-run resolution
  → provider.RenewAsync → provider.VerifyAsync (live successes)
  → audit row → cert-table write-back (verified live success only)
  → Work Item escalation (retries exhausted) → owner notification
```

Method selection (`RenewalEngine.SelectMethod`):

| Cert source  | Issuer                                    | Method |
|--------------|-------------------------------------------|--------|
| `KeyVault`   | any (imported certs fall back at runtime) | Key Vault re-issue via `Azure.Security.KeyVault.Certificates` |
| `AppService` | any (uploaded certs fall back at runtime) | Managed-cert re-issue via `Azure.ResourceManager.AppService` |
| `External`   | Let's Encrypt / ZeroSSL / Buypass         | ACME (DNS-01 / HTTP-01) via Certes |
| `External`   | GlobalSign, Sectigo, GoDaddy, AlphaSSL, SSL2BUY, unknown, … | Manual → Work Item assigned to cert owner |

## Solution layout

```
dotnet/
  CertRenewal.sln
  src/CertRenewal.Core/             engine, PolicyGuard, models, ports,
                                    in-memory repos, sweep job
                                    (only dep: Logging.Abstractions)
  src/CertRenewal.Azure/            Key Vault + App Service providers,
                                    env credential resolver (dev)
  src/CertRenewal.Acme/             ACME provider (Certes), solver/installer
                                    ports, Azure DNS DNS-01 solver
  src/CertRenewal.EntityFramework/  EF Core entities + DbContext + repos
  src/CertRenewal.Api/              minimal-API endpoints, IActorResolver,
                                    optional sweep BackgroundService,
                                    appsettings.example.json
  tests/CertRenewal.Core.Tests/     81 xUnit tests (no cloud deps)
  tests/CertRenewal.EntityFramework.Tests/  4 EF smoke tests (SQLite)
  migrations/                       plain-SQL alternative to EF migrations
frontend/
  CertificateRenewalPanel.tsx       Next.js "use client" component
  renewalApi.ts                     typed client for the API endpoints
```

Build & test: `cd dotnet && dotnet build CertRenewal.sln && dotnet test`.

## Integration points (in the order you'll wire them)

### 1. Certificates table → `ICertificateRepository`

Implement over the existing certificates table (the one behind the
Certificates page), mapping each row to `CertRenewal.Core.Models.Certificate`:

- `Source`: your Azure/External column split by resource type —
  `Microsoft.KeyVault/vaults` certs → `KeyVault`,
  `Microsoft.Web/certificates` → `AppService`, everything else → `External`.
- Per-source fields the providers need: `KeyVaultUrl` + `KeyVaultCertName`,
  or `AzureSubscriptionId` + `AzureResourceGroup` + `AppServiceCertName`,
  or `Domains` for ACME.
- `UpdateAfterRenewalAsync` writes the new expiry/thumbprint back so the UI
  and the "expiring ≤ 30 days" counters update before the next full scan.

### 2. New tables → EF Core (`CertRenewal.EntityFramework`)

Three new tables; the existing certificates table is NOT duplicated:

- `cert_renewal_policies` — unique on (TenantId, CertificateId)
- `cert_renewal_attempts` — append-mostly audit log
- `cert_renewal_approvals` — unique on (TenantId, CertificateId,
  ExpirationWindowKey); only needed if you expose approval mode

Either merge the entity configurations from `CertRenewalDbContext` into your
existing DbContext, or run the context side-by-side on the same database and
generate a migration
(`dotnet ef migrations add CertRenewal --context CertRenewalDbContext`), or
apply `dotnet/migrations/001_cert_renewal_tables.sql` directly (PostgreSQL
syntax; adapt types for SQL Server).
The `Ef*Repository` classes take `IDbContextFactory<CertRenewalDbContext>`
so they are safe to inject into singletons. If you'd rather use your own
data layer, implement the four small interfaces in
`CertRenewal.Core/Repositories.cs` directly.

### 3. Per-tenant Azure credentials → `ITenantCredentialResolver`

Clear Ops already holds per-tenant credentials for scan jobs. Implement
`GetAzureCredentialAsync(tenantId)` on top of that store, returning an
`Azure.Core.TokenCredential`. The engine calls it per attempt with the
certificate's own tenant id. `EnvTenantCredentialResolver` (in
CertRenewal.Azure) is for local testing only.

### 4. Work Items → `IWorkItemSink`

Implement `CreateAsync(request)` against your Work Items feature and return
the created item's id. Requests carry tenant, title, description
(issuer-specific renewal instructions), severity (`critical` for expired /
`high` for expiring — matching your severity pills), assignee email (cert
owner; null = Unassigned), certificate id, an idempotency key
(`certId:expiryDate` — upsert on it for a second layer of dedup), and a
`certificate-renewal` label. This closes the "0 open renewal tasks" counter
loop on the Certificates page.

### 5. Notifications → `INotifier`

Implement the three hooks (`RenewalSucceededAsync`, `RenewalFailedAsync`,
`ManualActionRequiredAsync`) against your notification system. Each receives
the `Certificate` (with owner name/email) and the full `RenewalAttempt`.
Route owner-less certs to a tenant default channel. Keep `LoggingNotifier`
until you're out of dry-run.

### 6. Scheduler

Call `RenewalSweepJob.RunTenantAsync(tenantId)` from your existing scan
scheduler — ideally right after a tenant's scan completes (freshest cert
data). Alternatively register `RenewalSweepHostedService` (hourly
BackgroundService; implement `ITenantSource` over your tenant registry).
Over-calling is harmless: opt-in, window, retry cooldown, approvals, and
dry-run are all enforced inside the engine. The returned `SweepSummary`
(attempted / succeeded / failed / manual / dry-run counts) slots into your
scan-history UI. Tenants are processed sequentially with per-tenant error
isolation; if you parallelize, parallelize across tenants, never within one.

### 7. API

Register services and map the endpoints:

```csharp
builder.Services.AddSingleton(RenewalOptions.FromEnvironment());
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<ICertificateRepository, YourCertRepository>();
builder.Services.AddDbContextFactory<CertRenewalDbContext>(o => o.UseNpgsql(...));
builder.Services.AddSingleton<IPolicyRepository, EfPolicyRepository>();
builder.Services.AddSingleton<IAttemptRepository, EfAttemptRepository>();
builder.Services.AddSingleton<IApprovalRepository, EfApprovalRepository>();
builder.Services.AddSingleton<ITenantCredentialResolver, YourCredentialResolver>();
builder.Services.AddSingleton<INotifier, YourNotifier>();          // LoggingNotifier first
builder.Services.AddSingleton<IWorkItemSink, YourWorkItemSink>();  // LoggingWorkItemSink first
builder.Services.AddSingleton<IActorResolver, YourActorResolver>(); // NOT HeaderActorResolver in prod
builder.Services.AddSingleton<IReadOnlyDictionary<RenewalMethod, IRenewalProvider>>(sp =>
    new Dictionary<RenewalMethod, IRenewalProvider>
    {
        [RenewalMethod.KeyVault] = new KeyVaultRenewalProvider(),
        [RenewalMethod.AppService] = new AppServiceRenewalProvider(),
        [RenewalMethod.Acme] = new AcmeRenewalProvider(/* solver, installer */),
        [RenewalMethod.Manual] = new ManualFallbackProvider(sp.GetRequiredService<IWorkItemSink>()),
    });
builder.Services.AddSingleton<RenewalEngine>();
builder.Services.AddSingleton<RenewalSweepJob>();

app.MapCertRenewalEndpoints("/api/v1");
```

`IActorResolver` is the auth integration point: return the acting user's
identity (email/UPN) for the audit trail and enforce tenant RBAC in
`AuthorizeTenant`. The bundled `HeaderActorResolver` (X-User-Email header) is
dev-only. Routes:

```
GET    /api/v1/tenants/{t}/certificates/{c}/renewal            policy + last 10 attempts
PUT    /api/v1/tenants/{t}/certificates/{c}/renewal/enable     {renewalWindowDays?, renewalMode?}
PUT    /api/v1/tenants/{t}/certificates/{c}/renewal/disable
PATCH  /api/v1/tenants/{t}/certificates/{c}/renewal            window/mode/dry-run/max-attempts
GET    /api/v1/tenants/{t}/certificates/{c}/renewal/attempts
POST   /api/v1/tenants/{t}/certificates/{c}/renewal/trigger    manual run (202 when awaiting approval)
GET    /api/v1/tenants/{t}/renewal-approvals                   pending approvals queue
POST   /api/v1/tenants/{t}/renewal-approvals/{id}/approve      approve + renew immediately
POST   /api/v1/tenants/{t}/renewal-approvals/{id}/reject       reject for this expiry window
```

### 8. Frontend (Next.js 14)

`frontend/CertificateRenewalPanel.tsx` is a fully typed, self-contained
`"use client"` component (no UI library) for the certificate row expansion /
detail drawer, and `frontend/renewalApi.ts` is a typed fetch client for the
routes above (set `NEXT_PUBLIC_CLEAR_OPS_API_BASE_URL`, and replace its
default headers together with `IActorResolver` when wiring real auth). Pass
the certificate, the GET response as `renewalState`, and callbacks built on
the client (`onEnable`, `onDisable`, `onUpdateWindow`, optional
`onUpdateMode`, `onTriggerNow`); refetch `renewalState` after each resolves —
the wiring example is at the top of `renewalApi.ts`. It shows the enable toggle, opt-in
provenance ("Enabled by … on …"), a dry-run badge, the renewal method, the
window input, an Automatic / Require-approval mode selector, an urgency
banner for expired/≤30-day certs, and the attempt history with the product's
pill-badge styling.

### 9. ACME specifics (external Let's Encrypt/ZeroSSL certs only)

`AcmeRenewalProvider` needs two deployment-specific pieces, both ports:

- **`IChallengeSolver`** — proves domain control. `AzureDnsChallengeSolver`
  (DNS-01 via Azure DNS) is included; configure it with a domain-suffix →
  (subscription, resource group, zone) map. Wildcards require DNS-01.
- **`ICertificateInstaller`** — installs the issued PEM where traffic
  terminates (e.g. import into Key Vault). There is no default; without one
  the provider reports ManualRequired rather than issuing a cert it can't
  install.

If either is missing, external ACME certs safely fall back to Work Items.

## Required Azure permissions (per-tenant service principal)

| Provider     | Permission |
|--------------|------------|
| Key Vault    | Key Vault RBAC: **Key Vault Certificates Officer** on the vault(s) (or access policy: certificates *get, create*). Issuance via an integrated CA also needs the issuer configured in the vault. |
| App Service  | ARM: `Microsoft.Web/certificates/read` + `Microsoft.Web/certificates/write` on the resource group (**Website Contributor** covers it). |
| ACME DNS-01  | **DNS Zone Contributor** on the DNS zone(s) used for `_acme-challenge` records. |

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `CERT_RENEWAL_DRY_RUN` | `true` | Global dry-run switch. Keep `true` until validated. |
| `CERT_RENEWAL_DRY_RUN_TENANTS` | *(empty)* | Comma-separated tenant ids forced into dry-run even when the global switch is off. |
| `CERT_RENEWAL_WINDOW_DAYS` | `30` | Default renewal window for new policies. |
| `CERT_RENEWAL_MAX_ATTEMPTS` | `3` | Attempts per failure cycle before escalating to a Work Item. |
| `CERT_RENEWAL_RETRY_INTERVAL_MINUTES` | `360` | Cooldown between attempts in a cycle. |
| `CERT_RENEWAL_MAX_PER_SWEEP` | `0` (unlimited) | Blast-radius cap per tenant sweep for early rollouts. |
| `CERT_RENEWAL_ACME_DIRECTORY` | Let's Encrypt v2 | ACME directory URL (use the LE *staging* URL while testing). |
| `CERT_RENEWAL_ACME_CONTACT` | *(unset)* | Contact email for the ACME account. |
| `CERT_RENEWAL_TENANT_<ID>_*` | *(unset)* | Dev-only credentials for `EnvTenantCredentialResolver`. |

`RenewalOptions` can also be bound from `IConfiguration` (section
`CertRenewal`) instead of environment variables — see
`src/CertRenewal.Api/appsettings.example.json`.

## Recommended rollout (dry-run first)

1. Deploy with everything at defaults (`CERT_RENEWAL_DRY_RUN=true`),
   `LoggingNotifier` and `LoggingWorkItemSink` in place. Nothing can mutate.
2. Opt in a handful of certs via the UI/API; let the scheduler sweep. Read
   the `cert_renewal_attempts` rows and logs — dry-run details state exactly
   what a live run would have done, per provider.
3. Wire the real `IWorkItemSink` and `INotifier`; confirm manual-fallback Work
   Items and notifications look right (note dry-run also suppresses Work Item
   creation, so validate those with step 5's pilot).
4. Optionally use `RenewalMode.ApprovalRequired` as a stepping stone between
   dry-run and fully automatic: renewals run live, but each one waits for a
   human click in the approvals queue first.
5. Go live for one pilot tenant: set `CERT_RENEWAL_DRY_RUN=false` and put
   **every other tenant** in `CERT_RENEWAL_DRY_RUN_TENANTS`. Set
   `CERT_RENEWAL_MAX_PER_SWEEP=3`. Start with a Key Vault "Self"-issued or
   staging cert.
6. For ACME, point `CERT_RENEWAL_ACME_DIRECTORY` at Let's Encrypt staging
   first; switch to production only after a staging issuance succeeds
   end-to-end (including installation).
7. Widen tenant by tenant by shrinking `CERT_RENEWAL_DRY_RUN_TENANTS`; raise
   or remove the per-sweep cap once confident.

## Adapting away from the defaults

- **Different data layer**: skip `CertRenewal.EntityFramework`; implement the
  four interfaces in `CertRenewal.Core/Repositories.cs` (~12 methods total).
  The engine only sees domain models.
- **Controllers instead of minimal APIs**: the endpoint bodies in
  `CertRenewalEndpoints.cs` are thin translations to `PolicyGuard` calls,
  repository reads, and `RenewalEngine` methods — port them 1:1 into MVC
  controllers if that matches the codebase style.
- **Different job runner**: `RenewalSweepJob.RunTenantAsync` is a plain async
  call; wrap it in Hangfire/Quartz/your scan workers as you prefer.
