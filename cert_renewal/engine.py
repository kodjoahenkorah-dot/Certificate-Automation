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
    ApprovalStatus,
    AttemptStatus,
    Certificate,
    CertSource,
    RenewalApproval,
    RenewalAttempt,
    RenewalMethod,
    RenewalMode,
    RenewalPolicy,
    RenewalResult,
    expiration_window_key,
    utcnow,
)
from cert_renewal.notifications import Notifier
from cert_renewal.providers.base import ProviderContext, RenewalProvider
from cert_renewal.repository import (
    ApprovalRepository,
    AttemptRepository,
    CertRepository,
    InMemoryApprovalRepository,
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


class ApprovalPending(Exception):
    """The policy requires human approval and none has been granted for the
    current expiry window. Not an error; the approval (newly created or
    already open) is attached."""

    def __init__(self, message: str, approval: Optional[RenewalApproval] = None):
        super().__init__(message)
        self.approval = approval


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
        approvals: Optional[ApprovalRepository] = None,
        config: Optional[RenewalConfig] = None,
        clock=utcnow,
    ):
        self._certs = certs
        self._policies = policies
        self._attempts = attempts
        # Approvals only matter for APPROVAL_REQUIRED policies; default to an
        # in-memory store so purely-automatic deployments need no extra table.
        self._approvals = approvals or InMemoryApprovalRepository()
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
        retry-cooldown checks but NEVER the opt-in, tenant-scope, or
        approval gates.
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

        if pol.renewal_mode == RenewalMode.APPROVAL_REQUIRED:
            self._require_approval(cert, triggered_by, now)

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
        window_key = expiration_window_key(cert)

        attempt = RenewalAttempt(
            tenant_id=tenant_id,
            certificate_id=certificate_id,
            status=AttemptStatus.PENDING,
            method=method,
            dry_run=dry_run,
            attempt_number=attempt_number,
            expiration_window_key=window_key,
            triggered_by=triggered_by,
            started_at=now,
        )
        self._attempts.save(attempt)

        # Idempotency: if a Work Item already exists for this expiry window,
        # the manual path has nothing left to do — reference it and stop
        # instead of creating a duplicate on every sweep.
        if method == RenewalMethod.MANUAL and not dry_run:
            existing = self._attempts.find_work_item_for_window(
                tenant_id, certificate_id, window_key
            )
            if existing:
                attempt.status = AttemptStatus.MANUAL_REQUIRED
                attempt.finished_at = self._clock()
                attempt.work_item_id = existing
                attempt.detail = (
                    f"Work Item {existing} already open for this expiry window; "
                    "no duplicate created."
                )
                self._attempts.save(attempt)
                return attempt

        attempt.status = AttemptStatus.IN_PROGRESS
        self._attempts.save(attempt)

        result = self._execute(cert, method, dry_run)
        self._finalize(cert, pol, attempt, result, max_attempts)
        return attempt

    def approve_renewal(
        self, tenant_id: str, approval_id: str, *, actor: str,
        notes: Optional[str] = None,
    ) -> RenewalAttempt:
        """Approve a pending APPROVAL_REQUIRED renewal and run it immediately.
        The approval covers only the certificate's current expiry window."""
        if not actor or not actor.strip():
            raise ValueError("actor is required to approve a renewal")
        approval = self._approvals.get(tenant_id, approval_id)
        if approval is None:
            raise policy_mod.TenantScopeError(
                f"Approval {approval_id!r} not found in tenant {tenant_id!r}."
            )
        if approval.status != ApprovalStatus.PENDING:
            raise RenewalSkipped(
                f"Approval {approval_id} is already {approval.status.value}."
            )
        approval.status = ApprovalStatus.APPROVED
        approval.approved_by = actor.strip()
        approval.approved_at = self._clock()
        approval.notes = notes or approval.notes
        self._approvals.save(approval)
        return self.renew_certificate(
            tenant_id, approval.certificate_id, triggered_by=f"approval:{actor}"
        )

    def reject_renewal(
        self, tenant_id: str, approval_id: str, *, actor: str,
        notes: Optional[str] = None,
    ) -> RenewalApproval:
        """Reject a pending approval. The cert will not be renewed this
        expiry window unless a user re-triggers and re-approves."""
        if not actor or not actor.strip():
            raise ValueError("actor is required to reject a renewal")
        approval = self._approvals.get(tenant_id, approval_id)
        if approval is None:
            raise policy_mod.TenantScopeError(
                f"Approval {approval_id!r} not found in tenant {tenant_id!r}."
            )
        if approval.status != ApprovalStatus.PENDING:
            raise RenewalSkipped(
                f"Approval {approval_id} is already {approval.status.value}."
            )
        approval.status = ApprovalStatus.REJECTED
        approval.rejected_by = actor.strip()
        approval.rejected_at = self._clock()
        approval.notes = notes or approval.notes
        self._approvals.save(approval)
        return approval

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
            except ApprovalPending as exc:
                log.info("[tenant=%s] %s: %s", tenant_id, cert.name, exc)
            except policy_mod.OptInRequiredError:
                # Race: policy disabled between listing and attempting.
                log.info("[tenant=%s] %s no longer opted in; skipped.",
                         tenant_id, cert.name)
        return results

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _require_approval(
        self, cert: Certificate, triggered_by: str, now
    ) -> None:
        """Gate for APPROVAL_REQUIRED mode. Proceeds only when an APPROVED
        approval exists for the cert's current expiry window; otherwise
        ensures exactly one PENDING approval exists (idempotent per window)
        and raises ApprovalPending."""
        window_key = expiration_window_key(cert)
        approval = self._approvals.find_for_window(
            cert.tenant_id, cert.id, window_key
        )
        if approval is not None and approval.status == ApprovalStatus.APPROVED:
            return
        if approval is not None and approval.status == ApprovalStatus.PENDING:
            raise ApprovalPending(
                f"Renewal of {cert.name} awaits approval "
                f"(approval {approval.id}, window {window_key}).",
                approval,
            )
        if approval is not None and approval.status == ApprovalStatus.REJECTED:
            raise ApprovalPending(
                f"Renewal of {cert.name} was rejected by "
                f"{approval.rejected_by} for window {window_key}; not retrying.",
                approval,
            )
        approval = RenewalApproval(
            tenant_id=cert.tenant_id,
            certificate_id=cert.id,
            expiration_window_key=window_key,
            requested_by=triggered_by,
            requested_at=now,
        )
        self._approvals.save(approval)
        raise ApprovalPending(
            f"Renewal of {cert.name} requires approval; created approval "
            f"{approval.id} for window {window_key}.",
            approval,
        )

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
            result = provider.renew(cert, ctx)
            # Trust-but-verify: a live success must survive the provider's
            # own re-read of the renewed resource before we record it.
            if result.status == AttemptStatus.SUCCEEDED and not dry_run:
                verify_error = provider.verify(cert, result, ctx)
                if verify_error:
                    return RenewalResult(
                        status=AttemptStatus.FAILED,
                        error=f"Renewal reported success but verification "
                              f"failed: {verify_error}",
                        detail=result.detail,
                    )
            return result
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
        window_key = expiration_window_key(cert)
        existing = self._attempts.find_work_item_for_window(
            cert.tenant_id, cert.id, window_key
        )
        if existing:
            return existing
        return self._work_items.create(
            WorkItemRequest(
                tenant_id=cert.tenant_id,
                title=f"Renew certificate {cert.name}",
                description=reason + "\n\n" + build_manual_renewal_instructions(cert),
                severity="critical" if cert.is_expired(self._clock()) else "high",
                assignee_email=cert.owner_email,
                certificate_id=cert.id,
                idempotency_key=f"{cert.id}:{window_key}",
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
