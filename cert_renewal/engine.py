"""RenewalEngine — orchestrates a single certificate renewal.

Pipeline for every attempt (manual API trigger and scheduler alike):

    load cert (tenant-filtered) ─▶ tenant-scope check ─▶ opt-in gate
      ─▶ retry budget ─▶ method selection ─▶ dry-run resolution
      ─▶ provider.renew() ─▶ audit record ─▶ cert table write-back
      ─▶ Work Item on exhaustion ─▶ notification

Every attempt — including rejected and dry-run ones — leaves a
RenewalAttempt audit row. The engine is synchronous and safe to call from
any job runner; wrap it in a thread/task per tenant if you need parallelism
(never parallelize within a tenant without external locking per cert).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Mapping, Optional

from cert_renewal import policy as policy_mod
from cert_renewal.config import RenewalConfig
from cert_renewal.credentials import (
    CredentialNotConfiguredError,
    TenantCredentialResolver,
)
from cert_renewal.models.domain import (
    ACME_AUTOMATABLE_ISSUERS,
    AttemptStatus,
    Certificate,
    CertSource,
    RenewalAttempt,
    RenewalMethod,
    RenewalPolicy,
    RenewalResult,
    utcnow,
)
from cert_renewal.notifications import Notifier
from cert_renewal.providers.base import ProviderContext, RenewalProvider
from cert_renewal.repository import (
    AttemptRepository,
    CertRepository,
    PolicyRepository,
)
from cert_renewal.work_items import (
    WorkItemRequest,
    WorkItemSink,
    build_manual_renewal_instructions,
)

log = logging.getLogger("cert_renewal.engine")


class RenewalSkipped(Exception):
    """The attempt did not run (retry budget, cooldown). Not an error."""


def select_method(cert: Certificate) -> RenewalMethod:
    """Choose the renewal method from the cert's source and issuer.

    KEY_VAULT and APP_SERVICE certs go to their Azure providers (the
    provider itself falls back to MANUAL_REQUIRED when the cert turns out
    to be non-renewable, e.g. an imported Key Vault cert with no issuer
    policy). EXTERNAL certs are ACME-renewable only when issued by an ACME
    CA; paid CAs (GlobalSign, Sectigo, GoDaddy, AlphaSSL, SSL2BUY, ...)
    become manual Work Items.
    """
    if cert.source == CertSource.KEY_VAULT:
        return RenewalMethod.KEY_VAULT
    if cert.source == CertSource.APP_SERVICE:
        return RenewalMethod.APP_SERVICE
    issuer = (cert.issuer or "").lower()
    if any(marker in issuer for marker in ACME_AUTOMATABLE_ISSUERS):
        return RenewalMethod.ACME
    return RenewalMethod.MANUAL


class RenewalEngine:
    def __init__(
        self,
        *,
        certs: CertRepository,
        policies: PolicyRepository,
        attempts: AttemptRepository,
        providers: Mapping[RenewalMethod, RenewalProvider],
        credentials: TenantCredentialResolver,
        notifier: Notifier,
        work_items: WorkItemSink,
        config: Optional[RenewalConfig] = None,
        clock=utcnow,
    ):
        self._certs = certs
        self._policies = policies
        self._attempts = attempts
        self._providers = providers
        self._credentials = credentials
        self._notifier = notifier
        self._work_items = work_items
        self._config = config or RenewalConfig()
        self._clock = clock

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def renew_certificate(
        self,
        tenant_id: str,
        certificate_id: str,
        *,
        triggered_by: str = "scheduler",
        force: bool = False,
    ) -> RenewalAttempt:
        """Run one renewal attempt. Raises OptInRequiredError /
        TenantScopeError / RenewalSkipped; any provider exception is caught
        and recorded as a failed attempt.

        ``force=True`` (manual API trigger) bypasses the renewal-window and
        retry-cooldown checks but NEVER the opt-in or tenant-scope gates.
        """
        now = self._clock()
        cert = self._certs.get(tenant_id, certificate_id)
        if cert is None:
            raise policy_mod.TenantScopeError(
                f"Certificate {certificate_id!r} not found in tenant {tenant_id!r}."
            )
        policy_mod.assert_tenant_scope(cert, tenant_id)

        pol = self._policies.get(tenant_id, certificate_id)
        pol = policy_mod.assert_opted_in(pol)  # raises OptInRequiredError

        if not force and not policy_mod.in_renewal_window(cert, pol, now):
            raise RenewalSkipped(
                f"Certificate {cert.name} is outside its {pol.renewal_window_days}-day "
                "renewal window."
            )

        max_attempts = pol.max_attempts or self._config.max_attempts
        retry_interval = timedelta(
            minutes=pol.retry_interval_minutes or self._config.retry_interval_minutes
        )
        streak = self._attempts.attempts_since_last_success(tenant_id, certificate_id)
        allowed, attempt_number = policy_mod.retry_allowed(
            streak, max_attempts=max_attempts, retry_interval=retry_interval, now=now
        )
        if not allowed and not force:
            raise RenewalSkipped(
                f"Retry budget/cooldown: {len(streak)} of {max_attempts} attempts used."
            )
        if force:
            attempt_number = len(streak) + 1

        dry_run = policy_mod.effective_dry_run(self._config, pol, tenant_id)
        method = select_method(cert)

        attempt = RenewalAttempt(
            tenant_id=tenant_id,
            certificate_id=certificate_id,
            status=AttemptStatus.PENDING,
            method=method,
            dry_run=dry_run,
            attempt_number=attempt_number,
            triggered_by=triggered_by,
            started_at=now,
        )
        self._attempts.save(attempt)

        attempt.status = AttemptStatus.IN_PROGRESS
        self._attempts.save(attempt)

        result = self._execute(cert, method, dry_run)
        self._finalize(cert, pol, attempt, result, max_attempts)
        return attempt

    def run_due_renewals(self, tenant_id: str) -> list[RenewalAttempt]:
        """One scheduler sweep for one tenant: attempt every opted-in cert
        that is inside its renewal window and has retry budget. Never raises
        per-cert errors; each outcome is in the returned audit records."""
        now = self._clock()
        results: list[RenewalAttempt] = []
        budget = self._config.max_renewals_per_sweep
        for pol in self._policies.list_enabled_for_tenant(tenant_id):
            cert = self._certs.get(tenant_id, pol.certificate_id)
            if cert is None:
                continue
            if not policy_mod.should_renew(cert, pol, now):
                continue
            if budget and len(results) >= budget:
                log.info(
                    "[tenant=%s] Sweep budget (%d) reached; remaining certs "
                    "will be picked up next sweep.", tenant_id, budget,
                )
                break
            try:
                results.append(
                    self.renew_certificate(
                        tenant_id, cert.id, triggered_by="scheduler"
                    )
                )
            except RenewalSkipped as exc:
                log.debug("[tenant=%s] %s: %s", tenant_id, cert.name, exc)
            except policy_mod.OptInRequiredError:
                # Race: policy disabled between listing and attempting.
                log.info("[tenant=%s] %s no longer opted in; skipped.",
                         tenant_id, cert.name)
        return results

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _execute(
        self, cert: Certificate, method: RenewalMethod, dry_run: bool
    ) -> RenewalResult:
        provider = self._providers.get(method)
        if provider is None:
            return RenewalResult(
                status=AttemptStatus.FAILED,
                error=f"No provider registered for method {method.value!r}.",
            )
        try:
            ctx = self._build_context(cert, method, dry_run)
        except CredentialNotConfiguredError as exc:
            return RenewalResult(status=AttemptStatus.FAILED, error=str(exc))
        try:
            return provider.renew(cert, ctx)
        except Exception as exc:  # provider bugs/timeouts become failed attempts
            log.exception(
                "[tenant=%s] Provider %s raised for cert %s",
                cert.tenant_id, method.value, cert.id,
            )
            return RenewalResult(
                status=AttemptStatus.FAILED, error=f"{type(exc).__name__}: {exc}"
            )

    def _build_context(
        self, cert: Certificate, method: RenewalMethod, dry_run: bool
    ) -> ProviderContext:
        ctx = ProviderContext(
            tenant_id=cert.tenant_id, dry_run=dry_run, config=self._config
        )
        if method in (RenewalMethod.KEY_VAULT, RenewalMethod.APP_SERVICE):
            # Credentials resolved from the CERT's tenant — combined with
            # assert_tenant_scope this makes cross-tenant renewal impossible.
            ctx.azure_credential = self._credentials.azure_credential(cert.tenant_id)
            ctx.azure_subscription_id = (
                cert.azure_subscription_id
                or self._credentials.azure_subscription_id(cert.tenant_id)
            )
        elif method == RenewalMethod.ACME:
            ctx.acme_account_key_pem = self._credentials.acme_account_key_pem(
                cert.tenant_id
            )
        return ctx

    def _finalize(
        self,
        cert: Certificate,
        pol: RenewalPolicy,
        attempt: RenewalAttempt,
        result: RenewalResult,
        max_attempts: int,
    ) -> None:
        attempt.status = result.status
        attempt.finished_at = self._clock()
        attempt.new_expires_at = result.new_expires_at
        attempt.new_thumbprint = result.new_thumbprint
        attempt.error = result.error
        attempt.detail = result.detail
        attempt.work_item_id = result.work_item_id

        if result.status == AttemptStatus.SUCCEEDED and not attempt.dry_run:
            self._certs.update_after_renewal(
                cert.tenant_id,
                cert.id,
                new_expires_at=result.new_expires_at,
                new_thumbprint=result.new_thumbprint,
            )

        # Exhausted retries with no Work Item yet -> escalate to manual.
        if (
            result.status == AttemptStatus.FAILED
            and attempt.attempt_number >= max_attempts
            and not attempt.dry_run
            and attempt.work_item_id is None
        ):
            attempt.work_item_id = self._create_fallback_work_item(
                cert,
                reason=(
                    f"Automated renewal failed {attempt.attempt_number} time(s); "
                    f"last error: {result.error}"
                ),
            )
            attempt.status = AttemptStatus.MANUAL_REQUIRED
            attempt.detail = (
                (attempt.detail + "\n") if attempt.detail else ""
            ) + "Retry budget exhausted; escalated to a Work Item."

        self._attempts.save(attempt)
        self._notify(cert, attempt)

    def _create_fallback_work_item(self, cert: Certificate, *, reason: str) -> str:
        return self._work_items.create(
            WorkItemRequest(
                tenant_id=cert.tenant_id,
                title=f"Renew certificate {cert.name}",
                description=reason + "\n\n" + build_manual_renewal_instructions(cert),
                severity="critical" if cert.is_expired(self._clock()) else "high",
                assignee_email=cert.owner_email,
                certificate_id=cert.id,
            )
        )

    def _notify(self, cert: Certificate, attempt: RenewalAttempt) -> None:
        try:
            if attempt.status == AttemptStatus.SUCCEEDED:
                self._notifier.renewal_succeeded(cert, attempt)
            elif attempt.status == AttemptStatus.MANUAL_REQUIRED:
                self._notifier.manual_action_required(cert, attempt)
            elif attempt.status == AttemptStatus.FAILED:
                self._notifier.renewal_failed(cert, attempt)
        except Exception:
            # A broken notification channel must not fail the renewal itself.
            log.exception(
                "[tenant=%s] Notifier raised for cert %s", cert.tenant_id, cert.id
            )
