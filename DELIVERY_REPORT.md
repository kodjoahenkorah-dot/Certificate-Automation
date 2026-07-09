# Delivery Report — Automated Certificate Renewal (Opt-in) for Clear Ops

**Deliverable:** standalone, integration-ready feature package
**Backend:** .NET 8 (C#) — 5 projects + test project, builds clean, 81/81 tests passing
**Frontend:** Next.js 14 client component (TypeScript/React, strict-mode typechecked)
**Reference:** a Python implementation with identical semantics is included (75/75 tests passing) for behavior cross-checking
**Status:** ready for integration; ships with dry-run enabled by default so it cannot touch real certificates until explicitly switched on

---

## 1. What this adds to the product

Clear Ops already detects expired/expiring certificates and raises Critical
findings ("SSL/TLS certificate has expired… az keyvault certificate renew…").
This package closes the loop: instead of only telling the customer to renew,
the platform can now renew for them — **but only for certificates a user has
explicitly opted in**, with a full audit trail, owner notifications, and a
manual Work Item fallback for certificates that cannot be renewed
automatically (paid CAs such as GlobalSign, Sectigo, GoDaddy, AlphaSSL,
SSL2BUY).

Per certificate, based on its Source and Issuer:

| Certificate type | Renewal path |
|---|---|
| Azure Key Vault cert with an issuer policy | New version created via `Azure.Security.KeyVault.Certificates` (SDK equivalent of `az keyvault certificate renew`) |
| Azure Key Vault cert that was *imported* | Cannot be re-issued by Key Vault → Work Item with manual steps |
| App Service **managed** certificate | Re-issued via `Azure.ResourceManager.AppService` |
| App Service **uploaded** certificate | Cannot be re-issued by Azure → Work Item |
| External cert issued by an ACME CA (Let's Encrypt, ZeroSSL, Buypass) | Re-issued via ACME (Certes) with DNS-01/HTTP-01; Azure DNS DNS-01 solver included |
| External cert from a paid CA, or unknown issuer | Work Item assigned to the certificate owner with issuer-specific renewal instructions |

## 2. Safety model (the important part)

1. **Opt-in only, enforced at the engine, not the UI.** Renewal requires a
   policy row with `AutoRenewEnabled = true` *and* a recorded actor +
   timestamp (`EnabledBy`/`EnabledAt`). No policy row = never renewed. The
   gate runs inside the engine on every code path — background sweep, API
   trigger, even `force` — so a UI bug or a hand-crafted API call cannot
   renew a cert nobody opted in.
2. **Dry-run is the default.** Until `CERT_RENEWAL_DRY_RUN=false`, every
   attempt runs the full pipeline and writes an audit row describing exactly
   what a live run would do, but no Azure/ACME/DNS/Work-Item mutation happens.
   Dry-run can also be forced per tenant and per certificate; if any level
   says dry-run, dry-run wins.
3. **Multi-tenant isolation is structural.** Every repository query is
   tenant-filtered; the engine re-checks the certificate's tenant before every
   attempt and resolves Azure credentials from the certificate's own tenant
   via your credential store. Cross-tenant renewal is a covered test case.
4. **Everything is audited.** One `cert_renewal_attempts` row per attempt
   (including dry runs) with status
   (`pending → in_progress → succeeded | failed | manual_required`),
   timestamps, new expiry + thumbprint on success, error text on failure, and
   Work Item id when one was created.
5. **Optional human approval mode.** A policy can require approval: the sweep
   creates one approval request per expiry window; renewal only runs after a
   user approves it (recorded who/when). Rejection blocks the cycle. This is
   a useful rollout stage between dry-run and fully automatic.
6. **Retry with escalation.** Failures retry up to `MaxAttempts` (default 3)
   with a cooldown (default 6h). When the budget is exhausted, the engine
   creates an owner-assigned Work Item and stops hammering Azure.
7. **Idempotent per expiry window.** Work Items and approvals are
   deduplicated on (tenant, certificate, current expiry date), so hourly
   sweeps can never spam duplicates. A successful renewal changes the expiry,
   which naturally opens the next window.
8. **Trust-but-verify.** After a live "success", the engine has the provider
   re-read the resource from Azure and confirm the new expiry actually took
   before recording success or updating the certificates table.
9. **Blast-radius controls for rollout:** per-tenant dry-run list and a
   `MaxRenewalsPerSweep` cap.

## 3. What's in the package

```
dotnet/CertRenewal.sln
  CertRenewal.Core              engine + policy gates + models + ports
                                (dependency: Logging.Abstractions only)
  CertRenewal.Azure             Key Vault + App Service providers
  CertRenewal.Acme              ACME provider (Certes) + Azure DNS solver
  CertRenewal.EntityFramework   EF Core entities/DbContext/repositories
                                (3 new tables; your certificates table is untouched)
  CertRenewal.Api               minimal-API endpoints + optional hourly
                                BackgroundService for the sweep
  CertRenewal.Core.Tests        81 xUnit tests
frontend/CertificateRenewalPanel.tsx    Next.js "use client" component
README_INTEGRATION.md                   full integration guide
cert_renewal/ + tests/                  Python reference implementation
```

The core engine has **no** dependency on EF, ASP.NET, or Azure SDKs — those
live in adapter projects. If any adapter doesn't fit your codebase, the
interfaces it implements are small and documented.

## 4. What you need to wire (7 integration points)

Each is a small interface, fully documented in README_INTEGRATION.md:

1. `ICertificateRepository` — map your existing certificates table to the
   engine's `Certificate` model (read + one write-back method).
2. EF migration for 3 new tables (policies, attempts, approvals) — or
   implement the repository interfaces on your own data layer.
3. `ITenantCredentialResolver` — return an `Azure.Core.TokenCredential` per
   tenant from the credential store your scan jobs already use.
4. `IWorkItemSink` — create a Work Item in your existing Work Items feature
   (this also feeds the "open renewal tasks" counter on the Certificates page).
5. `INotifier` — 3 hooks (success / failure / manual-required) into your
   notification system.
6. Scheduler — call `RenewalSweepJob.RunTenantAsync(tenantId)` after each
   tenant scan (recommended), or register the included hourly
   `RenewalSweepHostedService`.
7. `IActorResolver` — plug in your authentication (user identity for the
   audit trail) and tenant RBAC. The bundled header-based resolver is
   dev-only.

Frontend: drop `CertificateRenewalPanel.tsx` into the certificate detail
drawer/row expansion and wire its five callbacks to the API routes.

## 5. API surface

```
GET    /api/v1/tenants/{t}/certificates/{c}/renewal            policy + recent attempts
PUT    /api/v1/tenants/{t}/certificates/{c}/renewal/enable     opt in (records actor)
PUT    /api/v1/tenants/{t}/certificates/{c}/renewal/disable    opt out
PATCH  /api/v1/tenants/{t}/certificates/{c}/renewal            window / mode / dry-run / retries
GET    /api/v1/tenants/{t}/certificates/{c}/renewal/attempts   audit history
POST   /api/v1/tenants/{t}/certificates/{c}/renewal/trigger    run now (202 if awaiting approval)
GET    /api/v1/tenants/{t}/renewal-approvals                   pending approvals
POST   /api/v1/tenants/{t}/renewal-approvals/{id}/approve      approve + renew
POST   /api/v1/tenants/{t}/renewal-approvals/{id}/reject       reject this cycle
```

## 6. Verification status — honest accounting

**Verified in this package:**
- Solution builds clean on .NET 8; all 81 xUnit tests pass. Tests cover:
  opt-in fails closed (and `force` can't bypass it), renewal-window math
  including already-expired certs, dry-run at all three levels, retry
  cooldown + Work Item escalation, cross-tenant rejection, credential
  resolution from the cert's tenant, paid-CA → Work Item fallback with
  severity/assignee rules, approval create/approve/reject/dedup, Work Item
  window dedup, and verify-failure handling.
- The TSX component passes strict-mode TypeScript checking.
- The Python reference implementation (identical semantics) passes its own
  75 tests — useful for cross-checking behavior questions.

**Not verified here (needs your environment):**
- The three cloud providers compile against current SDK surfaces
  (`Azure.Security.KeyVault.Certificates` 4.7, `Azure.ResourceManager.AppService`
  1.2, `Certes` 3.0) but have not been run against live Azure resources or a
  real ACME directory from this environment. The rollout plan below is
  designed so the first live contact happens under dry-run, then against
  staging/self-signed certs, one pilot tenant at a time.

## 7. Recommended rollout

1. Deploy with defaults (dry-run ON, logging notifier/sink). Nothing mutates.
2. Opt in a few certs, let sweeps run, read the audit rows — dry-run details
   say exactly what a live run would have done.
3. Wire the real Work Items sink and notifier.
4. Optionally require approval per renewal as a live-but-gated stage.
5. Go live for one pilot tenant only (`CERT_RENEWAL_DRY_RUN=false`, all other
   tenants in `CERT_RENEWAL_DRY_RUN_TENANTS`, `CERT_RENEWAL_MAX_PER_SWEEP=3`),
   starting with a Key Vault self-signed/staging cert.
6. ACME against Let's Encrypt *staging* first; production directory only after
   an end-to-end staging issuance (including installation) succeeds.
7. Widen tenant by tenant.

## 8. Azure permissions required (per-tenant service principal)

- **Key Vault:** Key Vault Certificates Officer on the target vaults (or
  access-policy equivalent: certificates get/create). Integrated-CA issuance
  additionally requires the issuer configured in the vault.
- **App Service:** `Microsoft.Web/certificates/read|write` on the resource
  group (Website Contributor covers it).
- **ACME DNS-01:** DNS Zone Contributor on the zones used for
  `_acme-challenge` TXT records.

## 9. Known limitations / decisions for the team

- ACME issuance is only half the job; installing the issued cert where
  traffic terminates is deployment-specific, so it's a port
  (`ICertificateInstaller`). Until one is configured, ACME-eligible certs
  fall back to Work Items rather than issuing certificates that go nowhere.
- Key Vault renewal covers certs with an issuer policy; imported certs are
  correctly routed to manual (this matches Azure's own capabilities).
- The engine is intentionally synchronous-per-tenant. Parallelize across
  tenants if needed; don't parallelize within a tenant without adding
  per-certificate locking.
- `HeaderActorResolver` (X-User-Email) is a development placeholder — wire
  `IActorResolver` to real auth before exposing the endpoints.
