# cert_renewal — Opt-in Automated Certificate Renewal for Clear Ops

A standalone Python package + React component that adds **strictly opt-in**
automated SSL/TLS certificate renewal to Clear Ops. It is designed to be
integrated into the existing multi-tenant backend with minimal coupling:
the core engine is pure Python (no FastAPI/SQLAlchemy/Azure imports), and
every touchpoint with the existing product is an explicit, documented
interface.

## Safety properties (read this first)

1. **Auto-renew is OFF by default, everywhere.** A certificate with no
   policy row, or a disabled policy, is never renewed. The gate lives in
   `policy.assert_opted_in()` and is enforced inside the engine on **every**
   attempt — scheduler sweeps, API triggers, and `force=True` all pass
   through it. Enabling requires a non-empty actor identity; the policy
   records `enabled_by` + `enabled_at` (and `disabled_by`/`disabled_at`).
2. **Dry-run is ON by default** (`CERT_RENEWAL_DRY_RUN=true` unless
   explicitly set to `false`). Dry-run attempts execute the full pipeline
   and write audit rows marked `dry_run=true`, but providers make **no
   mutating calls** (no Key Vault writes, no ACME orders, no DNS records,
   no Work Items). Dry-run wins if *any* level requests it: global config,
   per-tenant list (`CERT_RENEWAL_DRY_RUN_TENANTS`), or per-certificate
   policy override.
3. **Tenant isolation is structural.** Every repository method filters by
   `tenant_id`; the engine cross-checks `cert.tenant_id` against the job's
   tenant before every attempt (`TenantScopeError` otherwise) and resolves
   Azure credentials from the *certificate's* tenant, never a shared one.
4. **Everything is audited.** Every attempt — dry-run, failed, skipped-to-
   manual — is a `cert_renewal_attempts` row with status, timestamps, new
   expiry/thumbprint on success, error text on failure, and the Work Item
   id when one was created.
5. **Optional human-in-the-loop mode.** A policy can be set to
   `renewal_mode = approval_required`: the sweep then creates one
   `RenewalApproval` per expiry window and pauses; renewal runs only after a
   user approves it (approve/reject endpoints record who and when). `force`
   cannot bypass this gate.
6. **Idempotent per expiry window.** Approvals and fallback Work Items are
   deduplicated on (tenant, certificate, current-expiry-date), so repeated
   sweeps can never create duplicates within one renewal cycle. A successful
   renewal changes the expiry and naturally opens a new window.
7. **Trust-but-verify.** After a live renewal reports success, the engine
   calls the provider's `verify()` hook, which re-reads the resource from
   Azure and confirms the new expiry actually took; a failed verification is
   recorded as a FAILED attempt and the certificates table is not updated.

## Architecture

```
                 Certificates page (React)
                 CertificateRenewalPanel.jsx
                          │ REST
                          ▼
                    api.py (FastAPI router, thin)
                          │
     Scans scheduler ──▶ scheduler.py (RenewalJob, per-tenant sweep)
                          │
                          ▼
                     engine.py (RenewalEngine)
   ┌──────────────────────┼───────────────────────────────┐
   │ policy.py            │                               │
   │  opt-in gate         ▼                               ▼
   │  window math   providers/                    integration ports
   │  retry budget   ├─ key_vault.py  ─ azure-keyvault-certificates
   │  dry-run calc   ├─ app_service.py ─ azure-mgmt-web   │
   └─────────────────├─ acme.py ─ ACME + solver/installer ports
                     └─ manual.py ─ WorkItemSink          │
                          │                               │
                          ▼                               ▼
              repository.py (ports)              notifications.Notifier
              models/orm.py (SQLAlchemy impl)    work_items.WorkItemSink
                                                 credentials.TenantCredentialResolver
```

Renewal flow per certificate:

```
load cert (tenant-filtered) → tenant-scope check → OPT-IN GATE
  → renewal-window check → retry budget/cooldown → method selection
  → dry-run resolution → provider.renew() → audit row
  → cert-table write-back (live success only)
  → Work Item escalation (retries exhausted) → owner notification
```

Method selection (`engine.select_method`):

| Cert source   | Issuer                                   | Method       |
|---------------|------------------------------------------|--------------|
| `key_vault`   | any (imported certs fall back at runtime)| Key Vault re-issue via SDK |
| `app_service` | any (uploaded certs fall back at runtime)| Managed-cert re-issue via mgmt API |
| `external`    | Let's Encrypt / ZeroSSL / Buypass        | ACME (DNS-01 / HTTP-01) |
| `external`    | GlobalSign, Sectigo, GoDaddy, AlphaSSL, SSL2BUY, unknown, … | Manual → Work Item assigned to cert owner |

`manual_required` outcomes are terminal for the current cycle (they respect
the retry cooldown), so the sweep does not spam duplicate Work Items.

## Package layout

```
cert_renewal/
  config.py            RenewalConfig (env-driven; dry-run ON, window 30d)
  models/domain.py     Certificate, RenewalPolicy, RenewalAttempt, enums
  models/orm.py        SQLAlchemy tables + repositories        [optional]
  repository.py        Cert/Policy/Attempt ports + in-memory impls
  policy.py            opt-in gate, window math, retry budget, dry-run calc
  engine.py            RenewalEngine orchestration
  credentials.py       TenantCredentialResolver port (+ env impl for dev)
  providers/           key_vault, app_service, acme, manual (+ base)
  scheduler.py         RenewalJob per-tenant sweep
  notifications.py     Notifier port (+ logging impl)
  work_items.py        WorkItemSink port (+ logging impl), instruction builder
  api.py               FastAPI router                          [optional]
frontend/
  CertificateRenewalPanel.jsx
tests/                 75 unit tests (pure Python, no cloud deps)
```

Install: `pip install .` gives the dependency-free core. Extras:
`.[sqlalchemy]`, `.[api]`, `.[azure]`, `.[acme]`, `.[all]`, `.[dev]`.

Run tests: `pip install -e .[dev] && pytest`.

## Integration points (in the order you'll wire them)

### 1. Certificates table → `CertRepository`

Implement `repository.CertRepository` over your existing certificates table
(the one behind the Certificates page). Map each row to
`models.domain.Certificate`:

- `source`: your Azure/External column, split by resource type —
  `Microsoft.KeyVault/vaults` certs → `key_vault`,
  `Microsoft.Web/certificates` → `app_service`, everything else →
  `external`.
- Per-source fields the providers need: `key_vault_url` +
  `key_vault_cert_name`, or `azure_subscription_id` +
  `azure_resource_group` + `app_service_cert_name`, or `domains` for ACME.
- `update_after_renewal()` writes the new expiry/thumbprint back so the UI
  and the "expiring ≤ 30 days" counters update before the next full scan.

### 2. New tables → `PolicyRepository` / `AttemptRepository` / `ApprovalRepository`

Use the provided SQLAlchemy implementation (`models/orm.py`:
`cert_renewal_policies`, `cert_renewal_attempts`, `cert_renewal_approvals`;
`Base.metadata.create_all(engine)` or generate an Alembic migration), or
implement the ports over your own ORM. `cert_renewal_policies` is unique on
(tenant_id, certificate_id); `cert_renewal_attempts` is append-mostly
(status transitions update the same row id); `cert_renewal_approvals` is
unique on (tenant_id, certificate_id, expiration_window_key). The approvals
table/repository is only needed if you expose `approval_required` mode —
the engine defaults to an in-memory store otherwise.

### 3. Per-tenant Azure credentials → `TenantCredentialResolver`

Clear Ops already holds per-tenant credentials for scan jobs. Implement
`credentials.TenantCredentialResolver.azure_credential(tenant_id)` on top
of that store, returning an `azure.core` TokenCredential. The engine calls
it per attempt with the certificate's own tenant id.
`EnvTenantCredentialResolver` is for local testing only.

### 4. Work Items → `WorkItemSink`

Implement `work_items.WorkItemSink.create(request)` against your Work Items
feature and return the created item's id. Requests carry tenant, title,
description (issuer-specific renewal instructions), severity
(`critical` for expired / `high` for expiring — matching your severity
pills), assignee email (cert owner; `None` = Unassigned), certificate id,
and a `certificate-renewal` label. This closes the "0 open renewal tasks"
counter loop on the Certificates page.

### 5. Notifications → `Notifier`

Implement the three hooks in `notifications.Notifier`
(`renewal_succeeded`, `renewal_failed`, `manual_action_required`) against
your notification system. Each receives the `Certificate` (with owner
name/email) and the full `RenewalAttempt`. Route owner-less certs to a
tenant default channel. Keep `LoggingNotifier` until you're out of dry-run.

### 6. Scheduler

Call `RenewalJob.run_tenant(tenant_id)` from your existing scan scheduler —
ideally right after a tenant's scan completes (freshest cert data), or
hourly via `run_all(tenant_ids)`. Over-calling is harmless: opt-in, window,
retry cooldown, and dry-run are all enforced inside the engine. The
returned `SweepSummary` (attempted/succeeded/failed/manual/dry-run counts)
slots into your scan-history UI. Tenants are processed sequentially with
per-tenant error isolation; if you parallelize, parallelize across tenants,
never within one.

### 7. API

Mount the router and wire the two dependencies:

```python
from cert_renewal.api import router, get_services, Services

app.include_router(router, prefix="/api/v1")
app.dependency_overrides[get_services] = lambda: Services(
    certs=..., policies=..., attempts=..., engine=..., config=...,
)
```

Replace `api.get_actor` (currently an `X-User-Email` placeholder header)
with your real auth dependency, and fill in `api.authorize_tenant` with
your RBAC check. Routes:

```
GET    /tenants/{t}/certificates/{c}/renewal            policy + last 10 attempts
PUT    /tenants/{t}/certificates/{c}/renewal/enable     {renewal_window_days?, renewal_mode?}
PUT    /tenants/{t}/certificates/{c}/renewal/disable
PATCH  /tenants/{t}/certificates/{c}/renewal            window/mode/dry-run/max-attempts
GET    /tenants/{t}/certificates/{c}/renewal/attempts
POST   /tenants/{t}/certificates/{c}/renewal/trigger    manual run (opt-in + approval still enforced;
                                                        202 when awaiting approval)
GET    /tenants/{t}/renewal-approvals                   pending approvals queue
POST   /tenants/{t}/renewal-approvals/{id}/approve      approve + renew immediately
POST   /tenants/{t}/renewal-approvals/{id}/reject       reject for this expiry window
```

### 8. Frontend

`frontend/CertificateRenewalPanel.jsx` is a self-contained component (no UI
library) for the certificate row expansion / detail drawer. Pass the
certificate, the GET response as `renewalState`, and four callbacks that
hit the routes above (`onEnable`, `onDisable`, `onUpdateWindow`,
`onTriggerNow`, plus optional `onUpdateMode`); refetch `renewalState` after
each resolves. It shows the enable toggle, opt-in provenance ("Enabled by …
on …"), a dry-run badge, the renewal method, the window input, an
Automatic / Require-approval mode selector, an urgency banner for
expired/≤30-day certs, and the attempt history with your pill-badge styling.

### 9. ACME specifics (external Let's Encrypt/ZeroSSL certs only)

`AcmeRenewalProvider` needs two deployment-specific pieces, both ports:

- **ChallengeSolver** — proves domain control. `AzureDnsChallengeSolver`
  (DNS-01 via Azure DNS) is included; configure it with a domain-suffix →
  (subscription, resource group, zone) map. Wildcards require DNS-01.
- **CertificateInstaller** — installs the issued PEM where traffic
  terminates (e.g. import into Key Vault). There is no default; without
  one the provider reports `manual_required` rather than issuing a cert
  it can't install.

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

## Recommended rollout (dry-run first)

1. Deploy with everything at defaults (`CERT_RENEWAL_DRY_RUN=true`),
   `LoggingNotifier` and `LoggingWorkItemSink` in place. Nothing can mutate.
2. Opt in a handful of certs via the UI/API; let the scheduler sweep. Read
   the `cert_renewal_attempts` rows and logs — dry-run details state exactly
   what a live run would have done, per provider.
3. Wire the real `WorkItemSink` and `Notifier`; confirm manual-fallback
   Work Items and notifications look right (still dry-run for providers —
   note dry-run also suppresses Work Item creation, so validate those with
   step 4's pilot).
4. Optionally use `renewal_mode = approval_required` as a stepping stone
   between dry-run and fully automatic: renewals run live, but each one
   waits for a human click in the approvals queue first.
5. Go live for one pilot tenant: set `CERT_RENEWAL_DRY_RUN=false` and put
   **every other tenant** in `CERT_RENEWAL_DRY_RUN_TENANTS`. Set
   `CERT_RENEWAL_MAX_PER_SWEEP=3`. Start with a Key Vault "Self"-issued or
   staging cert.
6. For ACME, point `CERT_RENEWAL_ACME_DIRECTORY` at Let's Encrypt staging
   first; switch to production only after a staging issuance succeeds
   end-to-end (including installation).
7. Widen tenant by tenant by shrinking `CERT_RENEWAL_DRY_RUN_TENANTS`;
   raise or remove the per-sweep cap once confident.

## Adapting away from the defaults

- **Different ORM**: skip `models/orm.py`; implement the three ports in
  `repository.py` (~6 methods total). The engine only sees domain
  dataclasses.
- **Different web framework**: skip `api.py`; its handlers are thin
  translations to `policy.enable_auto_renewal` / `disable_auto_renewal`,
  repository reads, and `engine.renew_certificate` — port them 1:1.
- **Different job runner**: `RenewalJob.run_tenant` is a plain synchronous
  call; wrap it in Celery/APS/your scan workers as you prefer.
- **Async backend**: the engine is synchronous by design (renewals are rare,
  slow, external-IO operations). Run sweeps in a worker thread/task
  (`anyio.to_thread.run_sync`) rather than converting the package to async.
