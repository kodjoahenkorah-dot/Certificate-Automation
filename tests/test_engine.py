"""Engine behavior: opt-in gate, dry-run, retries, audit, notifications."""

from datetime import timedelta

import pytest

from cert_renewal import policy
from cert_renewal.engine import RenewalSkipped, select_method
from cert_renewal.models.domain import (
    AttemptStatus,
    CertSource,
    RenewalMethod,
    RenewalResult,
)
from tests.conftest import NOW, make_cert


def opt_in(policies, cert, actor="alice@anadata.com", **kwargs):
    pol = policy.enable_auto_renewal(
        None, certificate=cert, actor=actor, now=NOW, **kwargs
    )
    policies.save(pol)
    return pol


class TestOptInEnforcement:
    def test_renewal_without_opt_in_is_rejected(self, engine, certs, fake_kv_provider):
        certs.add(make_cert(days_to_expiry=5))
        with pytest.raises(policy.OptInRequiredError):
            engine.renew_certificate("tenant-a", "cert-1")
        assert fake_kv_provider.calls == []

    def test_force_does_not_bypass_opt_in(self, engine, certs, fake_kv_provider):
        certs.add(make_cert(days_to_expiry=5))
        with pytest.raises(policy.OptInRequiredError):
            engine.renew_certificate("tenant-a", "cert-1", force=True)
        assert fake_kv_provider.calls == []

    def test_opted_in_cert_renews(self, engine, certs, policies, fake_kv_provider):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.SUCCEEDED
        assert len(fake_kv_provider.calls) == 1

    def test_sweep_skips_non_opted_in(self, engine, certs, policies, fake_kv_provider):
        opted = make_cert(cert_id="opted", days_to_expiry=5)
        not_opted = make_cert(cert_id="not-opted", days_to_expiry=5)
        certs.add(opted)
        certs.add(not_opted)
        opt_in(policies, opted)
        results = engine.run_due_renewals("tenant-a")
        assert [a.certificate_id for a in results] == ["opted"]


class TestRenewalWindowAndSweep:
    def test_outside_window_is_skipped(self, engine, certs, policies):
        cert = make_cert(days_to_expiry=183)
        certs.add(cert)
        opt_in(policies, cert)
        with pytest.raises(RenewalSkipped):
            engine.renew_certificate("tenant-a", "cert-1")
        assert engine.run_due_renewals("tenant-a") == []

    def test_expired_cert_is_renewed(self, engine, certs, policies):
        cert = make_cert(days_to_expiry=-333)
        certs.add(cert)
        opt_in(policies, cert)
        results = engine.run_due_renewals("tenant-a")
        assert len(results) == 1
        assert results[0].status == AttemptStatus.SUCCEEDED

    def test_force_bypasses_window_only(self, engine, certs, policies):
        cert = make_cert(days_to_expiry=183)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1", force=True)
        assert attempt.status == AttemptStatus.SUCCEEDED

    def test_sweep_budget(self, engine, certs, policies, config):
        config.max_renewals_per_sweep = 1
        for i in range(3):
            cert = make_cert(cert_id=f"c{i}", days_to_expiry=5)
            certs.add(cert)
            opt_in(policies, cert)
        assert len(engine.run_due_renewals("tenant-a")) == 1


class TestDryRun:
    def test_dry_run_records_attempt_without_touching_cert_table(
        self, engine, certs, policies, config, attempts
    ):
        config.dry_run = True
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.dry_run is True
        # audit row exists, but the cert table was not updated
        assert attempts.list_for_certificate("tenant-a", "cert-1")
        assert certs.get("tenant-a", "cert-1").expires_at == cert.expires_at

    def test_dry_run_flag_reaches_provider(
        self, engine, certs, policies, config, fake_kv_provider
    ):
        config.dry_run = True
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        _, ctx = fake_kv_provider.calls[0]
        assert ctx.dry_run is True

    def test_live_run_updates_cert_table(self, engine, certs, policies):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.dry_run is False
        updated = certs.get("tenant-a", "cert-1")
        assert updated.expires_at == attempt.new_expires_at
        assert updated.thumbprint == "AA11BB22CC33"

    def test_policy_dry_run_override(self, engine, certs, policies, fake_kv_provider):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        pol = opt_in(policies, cert)
        pol.dry_run_override = True
        policies.save(pol)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.dry_run is True

    def test_dry_run_failures_never_create_work_items(
        self, engine, certs, policies, config, fake_kv_provider, work_items
    ):
        config.dry_run = True
        config.max_attempts = 1
        fake_kv_provider.result = RenewalResult(
            status=AttemptStatus.FAILED, error="boom"
        )
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.FAILED
        assert work_items.created == []


class TestRetriesAndFailure:
    def test_provider_exception_becomes_failed_attempt(
        self, engine, certs, policies, fake_kv_provider, notifier
    ):
        fake_kv_provider.raise_exc = RuntimeError("azure timeout")
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.FAILED
        assert "azure timeout" in attempt.error
        assert len(notifier.failed) == 1

    def test_cooldown_blocks_immediate_retry(
        self, engine, certs, policies, fake_kv_provider, clock
    ):
        fake_kv_provider.result = RenewalResult(
            status=AttemptStatus.FAILED, error="boom"
        )
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        with pytest.raises(RenewalSkipped):
            engine.renew_certificate("tenant-a", "cert-1")
        clock.advance(minutes=61)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.attempt_number == 2

    def test_exhausted_retries_escalate_to_work_item(
        self, engine, certs, policies, fake_kv_provider, work_items, notifier, clock
    ):
        fake_kv_provider.result = RenewalResult(
            status=AttemptStatus.FAILED, error="persistent failure"
        )
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        last = None
        for _ in range(3):  # config.max_attempts == 3
            last = engine.renew_certificate("tenant-a", "cert-1")
            clock.advance(minutes=61)
        assert last.status == AttemptStatus.MANUAL_REQUIRED
        assert last.work_item_id is not None
        assert len(work_items.created) == 1
        assert work_items.created[0].assignee_email == "owner@anadata.com"
        assert len(notifier.manual) == 1
        # budget now exhausted
        with pytest.raises(RenewalSkipped):
            engine.renew_certificate("tenant-a", "cert-1")

    def test_success_resets_failure_streak(
        self, engine, certs, policies, fake_kv_provider, clock, attempts
    ):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        fake_kv_provider.result = RenewalResult(
            status=AttemptStatus.FAILED, error="boom"
        )
        engine.renew_certificate("tenant-a", "cert-1")
        clock.advance(minutes=61)
        fake_kv_provider.result = RenewalResult(
            status=AttemptStatus.SUCCEEDED,
            new_expires_at=NOW + timedelta(days=365),
        )
        engine.renew_certificate("tenant-a", "cert-1")
        assert attempts.attempts_since_last_success("tenant-a", "cert-1") == []


class TestNotifications:
    def test_success_notifies_owner(self, engine, certs, policies, notifier):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        assert len(notifier.succeeded) == 1
        notified_cert, attempt = notifier.succeeded[0]
        assert notified_cert.owner_email == "owner@anadata.com"
        assert attempt.status == AttemptStatus.SUCCEEDED

    def test_notifier_crash_does_not_break_renewal(
        self, engine, certs, policies, notifier, attempts
    ):
        def boom(cert, attempt):
            raise RuntimeError("smtp down")

        notifier.renewal_succeeded = boom
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        attempt = engine.renew_certificate("tenant-a", "cert-1")
        assert attempt.status == AttemptStatus.SUCCEEDED
        saved = attempts.list_for_certificate("tenant-a", "cert-1")[0]
        assert saved.status == AttemptStatus.SUCCEEDED


class TestAudit:
    def test_every_attempt_is_recorded(self, engine, certs, policies, attempts):
        cert = make_cert(days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate(
            "tenant-a", "cert-1", triggered_by="api:alice@anadata.com"
        )
        rows = attempts.list_for_certificate("tenant-a", "cert-1")
        assert len(rows) == 1
        row = rows[0]
        assert row.triggered_by == "api:alice@anadata.com"
        assert row.method == RenewalMethod.KEY_VAULT
        assert row.started_at == NOW
        assert row.finished_at == NOW
        assert row.new_thumbprint == "AA11BB22CC33"


class TestMethodSelection:
    def test_key_vault(self):
        assert select_method(make_cert()) == RenewalMethod.KEY_VAULT

    def test_app_service(self):
        cert = make_cert(source=CertSource.APP_SERVICE)
        assert select_method(cert) == RenewalMethod.APP_SERVICE

    def test_external_acme_issuer(self):
        cert = make_cert(source=CertSource.EXTERNAL, issuer="Let's Encrypt R11")
        assert select_method(cert) == RenewalMethod.ACME
        cert = make_cert(source=CertSource.EXTERNAL, issuer="ZeroSSL RSA CA")
        assert select_method(cert) == RenewalMethod.ACME

    def test_external_paid_ca_goes_manual(self):
        for issuer in ("GlobalSign GCC R3", "Sectigo Public Server",
                       "Go Daddy Secure CA", "AlphaSSL CA - SHA256",
                       "SSL2BUY EMEA", None):
            cert = make_cert(source=CertSource.EXTERNAL, issuer=issuer)
            assert select_method(cert) == RenewalMethod.MANUAL, issuer
