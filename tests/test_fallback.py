"""Manual fallback: paid-CA external certs become owner-assigned Work Items."""

from cert_renewal.models.domain import AttemptStatus, CertSource
from tests.conftest import make_cert
from tests.test_engine import opt_in


class TestManualFallback:
    def _external_cert(self, **kwargs):
        return make_cert(
            source=CertSource.EXTERNAL,
            issuer="GlobalSign GCC R3 DV TLS CA 2020",
            **kwargs,
        )

    def test_paid_ca_creates_work_item(
        self, engine, certs, policies, work_items, notifier
    ):
        cert = self._external_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.MANUAL_REQUIRED
        assert attempt.work_item_id is not None
        assert len(work_items.created) == 1
        wi = work_items.created[0]
        assert wi.tenant_id == "tenant-a"
        assert wi.assignee_email == "owner@anadata.com"
        assert "GlobalSign" in wi.description
        assert cert.name in wi.title
        assert len(notifier.manual) == 1

    def test_expired_cert_work_item_is_critical(
        self, engine, certs, policies, work_items
    ):
        cert = self._external_cert(days_to_expiry=-40)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        assert work_items.created[0].severity == "critical"

    def test_expiring_cert_work_item_is_high(
        self, engine, certs, policies, work_items
    ):
        cert = self._external_cert(days_to_expiry=10)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        assert work_items.created[0].severity == "high"

    def test_unassigned_owner_creates_unassigned_work_item(
        self, engine, certs, policies, work_items
    ):
        cert = self._external_cert(days_to_expiry=5, owner_email=None)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.MANUAL_REQUIRED
        assert work_items.created[0].assignee_email is None

    def test_dry_run_describes_work_item_without_creating(
        self, engine, certs, policies, work_items, config
    ):
        config.dry_run = True
        cert = self._external_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.MANUAL_REQUIRED
        assert attempt.work_item_id is None
        assert work_items.created == []
        assert "DRY RUN" in attempt.detail

    def test_manual_required_is_not_retried_as_failure(
        self, engine, certs, policies, work_items, clock
    ):
        """MANUAL_REQUIRED counts against the failure streak, so the sweep
        does not re-create Work Items every hour."""
        cert = self._external_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        clock.advance(minutes=30)
        assert engine.run_due_renewals("tenant-a") == []  # cooldown holds
