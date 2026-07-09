"""Opt-in enforcement and renewal-window math.

This module is the single place where "is this certificate allowed to be
renewed automatically?" is decided. The engine calls ``assert_opted_in``
before every attempt, so the guarantee holds even for attempts triggered
manually through the API or by a misbehaving scheduler.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from cert_renewal.config import RenewalConfig
from cert_renewal.models.domain import (
    Certificate,
    RenewalAttempt,
    RenewalMode,
    RenewalPolicy,
    utcnow,
)


class OptInRequiredError(Exception):
    """Raised when a renewal is attempted for a cert that was never opted in."""


class TenantScopeError(Exception):
    """Raised when an operation crosses tenant boundaries."""


def _require_aware(dt: datetime, what: str) -> None:
    if dt.tzinfo is None:
        raise ValueError(f"{what} must be timezone-aware (UTC); got naive datetime")


def assert_opted_in(policy: Optional[RenewalPolicy]) -> RenewalPolicy:
    """Gatekeeper: a cert is renewable only with an explicit, attributed opt-in.

    No policy row, a disabled policy, or an enabled policy with no recorded
    actor/timestamp (which should never exist if enable_auto_renewal() was
    used) all fail closed.
    """
    if policy is None or not policy.auto_renew_enabled:
        raise OptInRequiredError(
            "Automated renewal is disabled for this certificate. "
            "A user must explicitly enable it first."
        )
    if not policy.enabled_by or policy.enabled_at is None:
        raise OptInRequiredError(
            "Renewal policy is enabled but has no recorded actor/timestamp; "
            "refusing to renew. Re-enable via enable_auto_renewal()."
        )
    return policy


def assert_tenant_scope(cert: Certificate, tenant_id: str) -> None:
    if cert.tenant_id != tenant_id:
        raise TenantScopeError(
            f"Certificate {cert.id} belongs to tenant {cert.tenant_id!r}, "
            f"but the operation is scoped to tenant {tenant_id!r}."
        )


def enable_auto_renewal(
    policy: Optional[RenewalPolicy],
    *,
    certificate: Certificate,
    actor: str,
    renewal_window_days: Optional[int] = None,
    renewal_mode: Optional[RenewalMode] = None,
    config: Optional[RenewalConfig] = None,
    now: Optional[datetime] = None,
) -> RenewalPolicy:
    """Turn auto-renew ON for one certificate, recording who and when.

    ``actor`` is required and must be non-empty — anonymous opt-ins are
    rejected so the audit trail is always complete.
    """
    if not actor or not actor.strip():
        raise ValueError("actor is required to enable auto-renewal")
    now = now or utcnow()
    _require_aware(now, "now")
    config = config or RenewalConfig()

    window = (
        renewal_window_days
        if renewal_window_days is not None
        else (policy.renewal_window_days if policy else config.default_renewal_window_days)
    )
    if window < 1 or window > 365:
        raise ValueError("renewal_window_days must be between 1 and 365")

    if policy is None:
        policy = RenewalPolicy(
            certificate_id=certificate.id, tenant_id=certificate.tenant_id
        )
    if policy.certificate_id != certificate.id:
        raise ValueError("policy does not belong to this certificate")
    assert_tenant_scope(certificate, policy.tenant_id)

    policy.auto_renew_enabled = True
    policy.enabled_by = actor.strip()
    policy.enabled_at = now
    policy.renewal_window_days = window
    if renewal_mode is not None:
        policy.renewal_mode = renewal_mode
    policy.updated_at = now
    return policy


def disable_auto_renewal(
    policy: RenewalPolicy, *, actor: str, now: Optional[datetime] = None
) -> RenewalPolicy:
    if not actor or not actor.strip():
        raise ValueError("actor is required to disable auto-renewal")
    now = now or utcnow()
    policy.auto_renew_enabled = False
    policy.disabled_by = actor.strip()
    policy.disabled_at = now
    policy.updated_at = now
    return policy


def in_renewal_window(
    cert: Certificate, policy: RenewalPolicy, now: Optional[datetime] = None
) -> bool:
    """True when the cert is expired or expires within the policy window.

    Expired certs are deliberately included: the product surfaces them as
    Critical findings and they are the most urgent renewal case.
    """
    now = now or utcnow()
    _require_aware(now, "now")
    _require_aware(cert.expires_at, "certificate.expires_at")
    return cert.expires_at <= now + timedelta(days=policy.renewal_window_days)


def should_renew(
    cert: Certificate,
    policy: Optional[RenewalPolicy],
    now: Optional[datetime] = None,
) -> bool:
    """Scheduler predicate: opted in AND inside the renewal window.

    Unlike assert_opted_in this doesn't raise — the sweep silently skips
    non-opted-in certs.
    """
    if policy is None or not policy.auto_renew_enabled:
        return False
    if not policy.enabled_by or policy.enabled_at is None:
        return False
    if cert.tenant_id != policy.tenant_id or cert.id != policy.certificate_id:
        return False
    return in_renewal_window(cert, policy, now)


def effective_dry_run(
    config: RenewalConfig, policy: Optional[RenewalPolicy], tenant_id: str
) -> bool:
    """Dry-run wins if ANY level asks for it: global config, per-tenant list,
    or the per-certificate policy override. A policy override of False can
    only take effect once global and tenant levels allow live runs."""
    if config.dry_run:
        return True
    if tenant_id in config.dry_run_tenants:
        return True
    if policy is not None and policy.dry_run_override is not None:
        return policy.dry_run_override
    return False


def retry_allowed(
    attempts_this_cycle: list[RenewalAttempt],
    *,
    max_attempts: int,
    retry_interval: timedelta,
    now: Optional[datetime] = None,
) -> tuple[bool, int]:
    """Decide whether another attempt may run and what its number would be.

    ``attempts_this_cycle`` = attempts for this cert since it last entered the
    renewal window with no success in between (the repository provides this
    via attempts_since_last_success()).

    Returns (allowed, next_attempt_number).
    """
    now = now or utcnow()
    if not attempts_this_cycle:
        return True, 1
    last = max(attempts_this_cycle, key=lambda a: a.started_at)
    n = len(attempts_this_cycle)
    if n >= max_attempts:
        return False, n + 1
    anchor = last.finished_at or last.started_at
    if now - anchor < retry_interval:
        return False, n + 1
    return True, n + 1
