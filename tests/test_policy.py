"""Opt-in enforcement and renewal-window math."""

from datetime import timedelta

import pytest

from cert_renewal import policy
from cert_renewal.config import RenewalConfig
from cert_renewal.models.domain import RenewalAttempt, RenewalPolicy, AttemptStatus
from tests.conftest import NOW, make_cert


class TestOptIn:
    def test_no_policy_fails_closed(self):
        with pytest.raises(policy.OptInRequiredError):
            policy.assert_opted_in(None)

    def test_disabled_policy_fails(self):
        pol = RenewalPolicy(certificate_id="c", tenant_id="t")
        assert pol.auto_renew_enabled is False  # the default is OFF
        with pytest.raises(policy.OptInRequiredError):
            policy.assert_opted_in(pol)

    def test_enabled_without_actor_fails(self):
        # A policy flipped on without going through enable_auto_renewal()
        # (no recorded actor) is rejected.
        pol = RenewalPolicy(
            certificate_id="c", tenant_id="t", auto_renew_enabled=True
        )
        with pytest.raises(policy.OptInRequiredError):
            policy.assert_opted_in(pol)

    def test_enable_records_actor_and_timestamp(self):
        cert = make_cert()
        pol = policy.enable_auto_renewal(
            None, certificate=cert, actor="alice@anadata.com", now=NOW
        )
        assert pol.auto_renew_enabled is True
        assert pol.enabled_by == "alice@anadata.com"
        assert pol.enabled_at == NOW
        policy.assert_opted_in(pol)  # passes the gate

    def test_enable_requires_actor(self):
        with pytest.raises(ValueError):
            policy.enable_auto_renewal(None, certificate=make_cert(), actor="  ")

    def test_disable_records_actor(self):
        cert = make_cert()
        pol = policy.enable_auto_renewal(
            None, certificate=cert, actor="alice@anadata.com", now=NOW
        )
        pol = policy.disable_auto_renewal(pol, actor="bob@anadata.com", now=NOW)
        assert pol.auto_renew_enabled is False
        assert pol.disabled_by == "bob@anadata.com"
        with pytest.raises(policy.OptInRequiredError):
            policy.assert_opted_in(pol)

    def test_enable_window_bounds(self):
        with pytest.raises(ValueError):
            policy.enable_auto_renewal(
                None, certificate=make_cert(), actor="a@b.c",
                renewal_window_days=0,
            )
        with pytest.raises(ValueError):
            policy.enable_auto_renewal(
                None, certificate=make_cert(), actor="a@b.c",
                renewal_window_days=400,
            )


class TestRenewalWindow:
    def _policy(self, cert, window=30):
        return policy.enable_auto_renewal(
            None, certificate=cert, actor="a@b.c",
            renewal_window_days=window, now=NOW,
        )

    def test_inside_window(self):
        cert = make_cert(days_to_expiry=10)
        assert policy.in_renewal_window(cert, self._policy(cert), NOW)

    def test_outside_window(self):
        cert = make_cert(days_to_expiry=183)
        assert not policy.in_renewal_window(cert, self._policy(cert), NOW)

    def test_expired_is_inside_window(self):
        cert = make_cert(days_to_expiry=-333)
        assert policy.in_renewal_window(cert, self._policy(cert), NOW)

    def test_boundary_exactly_window_days(self):
        cert = make_cert(days_to_expiry=30)
        assert policy.in_renewal_window(cert, self._policy(cert, window=30), NOW)

    def test_custom_window(self):
        cert = make_cert(days_to_expiry=50)
        assert not policy.in_renewal_window(cert, self._policy(cert, window=30), NOW)
        assert policy.in_renewal_window(cert, self._policy(cert, window=60), NOW)

    def test_naive_datetime_rejected(self):
        cert = make_cert()
        cert.expires_at = cert.expires_at.replace(tzinfo=None)
        with pytest.raises(ValueError):
            policy.in_renewal_window(cert, self._policy(make_cert()), NOW)

    def test_should_renew_requires_opt_in_and_window(self):
        cert = make_cert(days_to_expiry=10)
        assert policy.should_renew(cert, None, NOW) is False
        pol = self._policy(cert)
        assert policy.should_renew(cert, pol, NOW) is True
        far = make_cert(cert_id="cert-far", days_to_expiry=200)
        pol_far = self._policy(far)
        assert policy.should_renew(far, pol_far, NOW) is False

    def test_should_renew_rejects_mismatched_policy(self):
        cert = make_cert(days_to_expiry=5)
        other = make_cert(cert_id="other-cert", days_to_expiry=5)
        pol = self._policy(other)
        assert policy.should_renew(cert, pol, NOW) is False


class TestEffectiveDryRun:
    def test_global_default_is_dry_run(self):
        assert RenewalConfig().dry_run is True
        assert policy.effective_dry_run(RenewalConfig(), None, "t") is True

    def test_global_dry_run_wins_over_policy_override(self):
        pol = RenewalPolicy(
            certificate_id="c", tenant_id="t", dry_run_override=False
        )
        assert policy.effective_dry_run(RenewalConfig(dry_run=True), pol, "t") is True

    def test_tenant_dry_run_wins(self):
        cfg = RenewalConfig(dry_run=False, dry_run_tenants=frozenset({"t"}))
        pol = RenewalPolicy(
            certificate_id="c", tenant_id="t", dry_run_override=False
        )
        assert policy.effective_dry_run(cfg, pol, "t") is True
        assert policy.effective_dry_run(cfg, pol, "other") is False

    def test_policy_override_keeps_dry_run_on(self):
        cfg = RenewalConfig(dry_run=False)
        pol = RenewalPolicy(certificate_id="c", tenant_id="t", dry_run_override=True)
        assert policy.effective_dry_run(cfg, pol, "t") is True

    def test_live_when_all_levels_allow(self):
        cfg = RenewalConfig(dry_run=False)
        assert policy.effective_dry_run(cfg, None, "t") is False


class TestRetryBudget:
    def _failed(self, minutes_ago: int, n: int) -> RenewalAttempt:
        started = NOW - timedelta(minutes=minutes_ago)
        return RenewalAttempt(
            tenant_id="t", certificate_id="c",
            status=AttemptStatus.FAILED, dry_run=False,
            attempt_number=n, started_at=started, finished_at=started,
        )

    def test_first_attempt_allowed(self):
        allowed, n = policy.retry_allowed(
            [], max_attempts=3, retry_interval=timedelta(hours=1), now=NOW
        )
        assert (allowed, n) == (True, 1)

    def test_cooldown_blocks(self):
        allowed, n = policy.retry_allowed(
            [self._failed(10, 1)], max_attempts=3,
            retry_interval=timedelta(hours=1), now=NOW,
        )
        assert (allowed, n) == (False, 2)

    def test_after_cooldown_allowed(self):
        allowed, n = policy.retry_allowed(
            [self._failed(90, 1)], max_attempts=3,
            retry_interval=timedelta(hours=1), now=NOW,
        )
        assert (allowed, n) == (True, 2)

    def test_max_attempts_exhausted(self):
        streak = [self._failed(300, 1), self._failed(200, 2), self._failed(100, 3)]
        allowed, _ = policy.retry_allowed(
            streak, max_attempts=3, retry_interval=timedelta(hours=1), now=NOW
        )
        assert allowed is False
