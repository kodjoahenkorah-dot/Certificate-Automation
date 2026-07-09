"""APPROVAL_REQUIRED mode, expiry-window idempotency, and verify()."""

import pytest

from cert_renewal import policy
from cert_renewal.engine import ApprovalPending, RenewalSkipped
from cert_renewal.models.domain import (
    ApprovalStatus,
    AttemptStatus,
    CertSource,
    RenewalMode,
    RenewalResult,
    expiration_window_key,
)
from tests.conftest import NOW, make_cert
from tests.test_engine import opt_in


def opt_in_approval(policies, cert, actor="alice@anadata.com"):
    return opt_in(
        policies, cert, actor=actor, renewal_mode=RenewalMode.APPROVAL_REQUIRED
    )


class TestApprovalRequiredMode:
    def test_sweep_creates_pending_approval_and_does_not_renew(
        self, engine, certs, policies, approvals, fake_kv_provider
    ):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        assert engine.run_due_renewals("tenant-a") == []
        assert fake_kv_provider.calls == []
        pending = approvals.list_pending_for_tenant("tenant-a")
        assert len(pending) == 1
        assert pending[0].certificate_id == "cert-1"
        assert pending[0].expiration_window_key == expiration_window_key(cert)

    def test_repeated_sweeps_do_not_duplicate_approvals(
        self, engine, certs, policies, approvals
    ):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        engine.run_due_renewals("tenant-a")
        engine.run_due_renewals("tenant-a")
        engine.run_due_renewals("tenant-a")
        assert len(approvals.list_pending_for_tenant("tenant-a")) == 1

    def test_approve_runs_renewal(
        self, engine, certs, policies, approvals, fake_kv_provider
    ):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        engine.run_due_renewals("tenant-a")
        approval = approvals.list_pending_for_tenant("tenant-a")[0]
        attempt = engine.approve_renewal(
            "tenant-a", approval.id, actor="boss@anadata.com"
        )
        assert attempt.status == AttemptStatus.SUCCEEDED
        assert attempt.triggered_by == "approval:boss@anadata.com"
        stored = approvals.get("tenant-a", approval.id)
        assert stored.status == ApprovalStatus.APPROVED
        assert stored.approved_by == "boss@anadata.com"
        assert len(fake_kv_provider.calls) == 1

    def test_reject_blocks_renewal_for_the_window(
        self, engine, certs, policies, approvals, fake_kv_provider
    ):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        engine.run_due_renewals("tenant-a")
        approval = approvals.list_pending_for_tenant("tenant-a")[0]
        rejected = engine.reject_renewal(
            "tenant-a", approval.id, actor="boss@anadata.com", notes="not now"
        )
        assert rejected.status == ApprovalStatus.REJECTED
        # subsequent sweeps neither renew nor recreate the approval
        assert engine.run_due_renewals("tenant-a") == []
        assert fake_kv_provider.calls == []
        assert approvals.list_pending_for_tenant("tenant-a") == []

    def test_direct_renewal_raises_approval_pending(
        self, engine, certs, policies
    ):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        with pytest.raises(ApprovalPending):
            engine.renew_certificate("tenant-a", "cert-1")

    def test_force_does_not_bypass_approval(self, engine, certs, policies):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        with pytest.raises(ApprovalPending):
            engine.renew_certificate("tenant-a", "cert-1", force=True)

    def test_approval_is_tenant_scoped(self, engine, certs, policies, approvals):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        engine.run_due_renewals("tenant-a")
        approval = approvals.list_pending_for_tenant("tenant-a")[0]
        with pytest.raises(policy.TenantScopeError):
            engine.approve_renewal("tenant-b", approval.id, actor="evil@b.com")

    def test_double_approve_is_rejected(self, engine, certs, policies, approvals):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in_approval(policies, cert)
        engine.run_due_renewals("tenant-a")
        approval = approvals.list_pending_for_tenant("tenant-a")[0]
        engine.approve_renewal("tenant-a", approval.id, actor="boss@anadata.com")
        with pytest.raises(RenewalSkipped):
            engine.approve_renewal("tenant-a", approval.id, actor="boss@anadata.com")


class TestWorkItemIdempotency:
    def _external_cert(self, **kwargs):
        return make_cert(
            source=CertSource.EXTERNAL, issuer="GlobalSign GCC R3", **kwargs
        )

    def test_same_window_reuses_work_item(
        self, engine, certs, policies, work_items, clock
    ):
        cert = self._external_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        first = engine.renew_certificate("tenant-a", "cert-1")
        clock.advance(minutes=61 * 24)  # well past any cooldown
        second = engine.renew_certificate("tenant-a", "cert-1", force=True)
        assert first.work_item_id is not None
        assert second.work_item_id == first.work_item_id
        assert len(work_items.created) == 1
        assert "already open" in second.detail

    def test_work_item_request_carries_idempotency_key(
        self, engine, certs, policies, work_items
    ):
        cert = self._external_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        expected = f"cert-1:{expiration_window_key(cert)}"
        assert work_items.created[0].idempotency_key == expected

    def test_retry_exhaustion_reuses_existing_work_item(
        self, engine, certs, policies, work_items, fake_kv_provider, clock, attempts
    ):
        """If a Work Item already exists for this window (e.g. from an earlier
        manual fallback), exhausting retries must not create a second one."""
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        # Seed an attempt that already produced a Work Item in this window.
        from cert_renewal.models.domain import RenewalAttempt

        attempts.save(
            RenewalAttempt(
                tenant_id="tenant-a",
                certificate_id="cert-1",
                status=AttemptStatus.MANUAL_REQUIRED,
                dry_run=False,
                expiration_window_key=expiration_window_key(cert),
                work_item_id="wi-existing",
                started_at=NOW,
                finished_at=NOW,
            )
        )
        fake_kv_provider.result = RenewalResult(
            status=AttemptStatus.FAILED, error="boom"
        )
        last = None
        for _ in range(3):
            clock.advance(minutes=61)
            last = engine.renew_certificate("tenant-a", "cert-1", force=True)
        assert last.status == AttemptStatus.MANUAL_REQUIRED
        assert last.work_item_id == "wi-existing"
        assert work_items.created == []


class TestVerify:
    def test_verify_failure_turns_success_into_failed(
        self, engine, certs, policies, fake_kv_provider, notifier, attempts
    ):
        fake_kv_provider.verify_error = "vault still reports old expiry"
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.FAILED
        assert "verification failed" in attempt.error
        assert notifier.succeeded == []
        assert len(notifier.failed) == 1
        # cert table must NOT be updated with the unverified expiry
        assert certs.get("tenant-a", "cert-1").expires_at == cert.expires_at

    def test_verify_pass_records_success(
        self, engine, certs, policies, fake_kv_provider
    ):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.SUCCEEDED
        assert fake_kv_provider.verify_calls == 1

    def test_dry_run_skips_verify(
        self, engine, certs, policies, fake_kv_provider, config
    ):
        config.dry_run = True
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        assert fake_kv_provider.verify_calls == 0
