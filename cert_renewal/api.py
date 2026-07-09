"""FastAPI router (optional — requires `pip install .[api]`).

Framework coupling is deliberately thin: this module only translates HTTP
to calls on policy/engine/repositories; all rules live below it. If the
product uses Flask/Django, port these ~6 handlers 1:1.

INTEGRATION POINTS (see README_INTEGRATION.md):
  * get_actor: replace the X-User-Email header with your real auth. The
    actor string is stored on the policy (enabled_by) and audit rows.
  * authorize_tenant: enforce that the caller may act on {tenant_id}. The
    engine still enforces data-level tenant scoping, but authorization is
    the host app's job.
  * Dependency wiring: override `get_services` (fastapi dependency) to
    provide your repositories/engine.

Routes (mount under your API prefix):
  GET    /tenants/{tenant_id}/certificates/{cert_id}/renewal            policy + recent attempts
  PUT    /tenants/{tenant_id}/certificates/{cert_id}/renewal/enable     opt in (records actor)
  PUT    /tenants/{tenant_id}/certificates/{cert_id}/renewal/disable    opt out
  PATCH  /tenants/{tenant_id}/certificates/{cert_id}/renewal            update window / dry-run override
  GET    /tenants/{tenant_id}/certificates/{cert_id}/renewal/attempts   full audit history
  POST   /tenants/{tenant_id}/certificates/{cert_id}/renewal/trigger    manual run (still opt-in gated)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from cert_renewal import policy as policy_mod
from cert_renewal.config import RenewalConfig
from cert_renewal.engine import (
    ApprovalPending,
    RenewalEngine,
    RenewalSkipped,
    select_method,
)
from cert_renewal.models.domain import (
    RenewalApproval,
    RenewalAttempt,
    RenewalMode,
    RenewalPolicy,
)
from cert_renewal.repository import (
    ApprovalRepository,
    AttemptRepository,
    CertRepository,
    PolicyRepository,
)


@dataclass
class Services:
    certs: CertRepository
    policies: PolicyRepository
    attempts: AttemptRepository
    engine: RenewalEngine
    config: RenewalConfig
    approvals: Optional[ApprovalRepository] = None  # for APPROVAL_REQUIRED mode


def get_services() -> Services:  # pragma: no cover - wired by host app
    raise HTTPException(
        status_code=500,
        detail="cert_renewal services not wired: override the get_services "
               "dependency (app.dependency_overrides[get_services] = ...).",
    )


def get_actor(x_user_email: Optional[str] = Header(default=None)) -> str:
    """INTEGRATION POINT: replace with your real authentication dependency.
    Must return a stable user identity (email/UPN) for the audit trail."""
    if not x_user_email:
        raise HTTPException(
            status_code=401,
            detail="Missing user identity (X-User-Email placeholder header). "
                   "Wire get_actor to your auth system.",
        )
    return x_user_email


def authorize_tenant(tenant_id: str, actor: str) -> None:
    """INTEGRATION POINT: enforce your RBAC (may this user act on this
    tenant?). Default allows everything — replace before production."""


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------


class EnableRequest(BaseModel):
    renewal_window_days: Optional[int] = Field(default=None, ge=1, le=365)
    # "automatic" or "approval_required"; default automatic
    renewal_mode: Optional[RenewalMode] = None


class PatchRequest(BaseModel):
    renewal_window_days: Optional[int] = Field(default=None, ge=1, le=365)
    renewal_mode: Optional[RenewalMode] = None
    dry_run_override: Optional[bool] = None
    max_attempts: Optional[int] = Field(default=None, ge=1, le=10)
    retry_interval_minutes: Optional[int] = Field(default=None, ge=5)


class ApprovalDecision(BaseModel):
    notes: Optional[str] = Field(default=None, max_length=2000)


class ApprovalOut(BaseModel):
    id: str
    certificate_id: str
    expiration_window_key: str
    status: str
    requested_by: str
    requested_at: datetime
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    rejected_by: Optional[str]
    rejected_at: Optional[datetime]
    notes: Optional[str]

    @classmethod
    def build(cls, a: RenewalApproval) -> "ApprovalOut":
        return cls(
            id=a.id,
            certificate_id=a.certificate_id,
            expiration_window_key=a.expiration_window_key,
            status=a.status.value,
            requested_by=a.requested_by,
            requested_at=a.requested_at,
            approved_by=a.approved_by,
            approved_at=a.approved_at,
            rejected_by=a.rejected_by,
            rejected_at=a.rejected_at,
            notes=a.notes,
        )


class PolicyOut(BaseModel):
    certificate_id: str
    tenant_id: str
    auto_renew_enabled: bool
    renewal_mode: str
    enabled_by: Optional[str]
    enabled_at: Optional[datetime]
    disabled_by: Optional[str]
    disabled_at: Optional[datetime]
    renewal_window_days: int
    dry_run_override: Optional[bool]
    effective_dry_run: bool
    renewal_method: Optional[str] = None

    @classmethod
    def build(cls, pol: RenewalPolicy, config: RenewalConfig, method: Optional[str]):
        return cls(
            certificate_id=pol.certificate_id,
            tenant_id=pol.tenant_id,
            auto_renew_enabled=pol.auto_renew_enabled,
            renewal_mode=pol.renewal_mode.value,
            enabled_by=pol.enabled_by,
            enabled_at=pol.enabled_at,
            disabled_by=pol.disabled_by,
            disabled_at=pol.disabled_at,
            renewal_window_days=pol.renewal_window_days,
            dry_run_override=pol.dry_run_override,
            effective_dry_run=policy_mod.effective_dry_run(
                config, pol, pol.tenant_id
            ),
            renewal_method=method,
        )


class AttemptOut(BaseModel):
    id: str
    status: str
    method: Optional[str]
    dry_run: bool
    attempt_number: int
    triggered_by: str
    started_at: datetime
    finished_at: Optional[datetime]
    new_expires_at: Optional[datetime]
    new_thumbprint: Optional[str]
    error: Optional[str]
    work_item_id: Optional[str]
    detail: Optional[str]

    @classmethod
    def build(cls, a: RenewalAttempt) -> "AttemptOut":
        return cls(
            id=a.id,
            status=a.status.value,
            method=a.method.value if a.method else None,
            dry_run=a.dry_run,
            attempt_number=a.attempt_number,
            triggered_by=a.triggered_by,
            started_at=a.started_at,
            finished_at=a.finished_at,
            new_expires_at=a.new_expires_at,
            new_thumbprint=a.new_thumbprint,
            error=a.error,
            work_item_id=a.work_item_id,
            detail=a.detail,
        )


class RenewalStateOut(BaseModel):
    policy: PolicyOut
    recent_attempts: list[AttemptOut]


# --------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------

router = APIRouter(tags=["certificate-renewal"])
_BASE = "/tenants/{tenant_id}/certificates/{cert_id}/renewal"


def _load_cert(svc: Services, tenant_id: str, cert_id: str):
    cert = svc.certs.get(tenant_id, cert_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert


def _policy_or_default(svc: Services, tenant_id: str, cert_id: str) -> RenewalPolicy:
    return svc.policies.get(tenant_id, cert_id) or RenewalPolicy(
        certificate_id=cert_id,
        tenant_id=tenant_id,
        renewal_window_days=svc.config.default_renewal_window_days,
    )


@router.get(_BASE, response_model=RenewalStateOut)
def get_renewal_state(
    tenant_id: str, cert_id: str,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    authorize_tenant(tenant_id, actor)
    cert = _load_cert(svc, tenant_id, cert_id)
    pol = _policy_or_default(svc, tenant_id, cert_id)
    return RenewalStateOut(
        policy=PolicyOut.build(pol, svc.config, select_method(cert).value),
        recent_attempts=[
            AttemptOut.build(a)
            for a in svc.attempts.list_for_certificate(tenant_id, cert_id, limit=10)
        ],
    )


@router.put(_BASE + "/enable", response_model=PolicyOut)
def enable_renewal(
    tenant_id: str, cert_id: str, body: EnableRequest,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    authorize_tenant(tenant_id, actor)
    cert = _load_cert(svc, tenant_id, cert_id)
    pol = policy_mod.enable_auto_renewal(
        svc.policies.get(tenant_id, cert_id),
        certificate=cert,
        actor=actor,
        renewal_window_days=body.renewal_window_days,
        renewal_mode=body.renewal_mode,
        config=svc.config,
    )
    svc.policies.save(pol)
    return PolicyOut.build(pol, svc.config, select_method(cert).value)


@router.put(_BASE + "/disable", response_model=PolicyOut)
def disable_renewal(
    tenant_id: str, cert_id: str,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    authorize_tenant(tenant_id, actor)
    cert = _load_cert(svc, tenant_id, cert_id)
    pol = svc.policies.get(tenant_id, cert_id)
    if pol is None:
        raise HTTPException(status_code=404, detail="No renewal policy exists")
    pol = policy_mod.disable_auto_renewal(pol, actor=actor)
    svc.policies.save(pol)
    return PolicyOut.build(pol, svc.config, select_method(cert).value)


@router.patch(_BASE, response_model=PolicyOut)
def patch_policy(
    tenant_id: str, cert_id: str, body: PatchRequest,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    authorize_tenant(tenant_id, actor)
    cert = _load_cert(svc, tenant_id, cert_id)
    pol = svc.policies.get(tenant_id, cert_id)
    if pol is None:
        raise HTTPException(status_code=404, detail="No renewal policy exists")
    if body.renewal_window_days is not None:
        pol.renewal_window_days = body.renewal_window_days
    if body.renewal_mode is not None:
        pol.renewal_mode = body.renewal_mode
    if body.dry_run_override is not None:
        pol.dry_run_override = body.dry_run_override
    if body.max_attempts is not None:
        pol.max_attempts = body.max_attempts
    if body.retry_interval_minutes is not None:
        pol.retry_interval_minutes = body.retry_interval_minutes
    pol.updated_at = policy_mod.utcnow()
    svc.policies.save(pol)
    return PolicyOut.build(pol, svc.config, select_method(cert).value)


@router.get(_BASE + "/attempts", response_model=list[AttemptOut])
def list_attempts(
    tenant_id: str, cert_id: str, limit: int = 50,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    authorize_tenant(tenant_id, actor)
    _load_cert(svc, tenant_id, cert_id)
    return [
        AttemptOut.build(a)
        for a in svc.attempts.list_for_certificate(
            tenant_id, cert_id, limit=min(limit, 200)
        )
    ]


@router.post(_BASE + "/trigger", response_model=AttemptOut)
def trigger_renewal(
    tenant_id: str, cert_id: str,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    """Run one renewal attempt now. force bypasses window/cooldown but the
    engine still hard-enforces opt-in and tenant scope."""
    authorize_tenant(tenant_id, actor)
    try:
        attempt = svc.engine.renew_certificate(
            tenant_id, cert_id, triggered_by=f"api:{actor}", force=True
        )
    except policy_mod.OptInRequiredError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except policy_mod.TenantScopeError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RenewalSkipped as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    except ApprovalPending as exc:
        # Not an error: the renewal now awaits a human decision.
        raise HTTPException(status_code=202, detail=str(exc))
    return AttemptOut.build(attempt)


# ------------------------------------------------------------------
# Approvals (APPROVAL_REQUIRED mode)
# ------------------------------------------------------------------


def _approvals_or_501(svc: Services) -> ApprovalRepository:
    if svc.approvals is None:
        raise HTTPException(
            status_code=501,
            detail="Approvals are not wired: provide Services.approvals "
                   "(e.g. SqlApprovalRepository) to use approval_required mode.",
        )
    return svc.approvals


@router.get("/tenants/{tenant_id}/renewal-approvals", response_model=list[ApprovalOut])
def list_pending_approvals(
    tenant_id: str,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    authorize_tenant(tenant_id, actor)
    repo = _approvals_or_501(svc)
    return [ApprovalOut.build(a) for a in repo.list_pending_for_tenant(tenant_id)]


@router.post(
    "/tenants/{tenant_id}/renewal-approvals/{approval_id}/approve",
    response_model=AttemptOut,
)
def approve_renewal(
    tenant_id: str, approval_id: str, body: ApprovalDecision,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    """Approve and immediately run the renewal (opt-in still enforced)."""
    authorize_tenant(tenant_id, actor)
    _approvals_or_501(svc)
    try:
        attempt = svc.engine.approve_renewal(
            tenant_id, approval_id, actor=actor, notes=body.notes
        )
    except policy_mod.TenantScopeError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except policy_mod.OptInRequiredError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except RenewalSkipped as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return AttemptOut.build(attempt)


@router.post(
    "/tenants/{tenant_id}/renewal-approvals/{approval_id}/reject",
    response_model=ApprovalOut,
)
def reject_renewal(
    tenant_id: str, approval_id: str, body: ApprovalDecision,
    svc: Services = Depends(get_services),
    actor: str = Depends(get_actor),
):
    authorize_tenant(tenant_id, actor)
    _approvals_or_501(svc)
    try:
        approval = svc.engine.reject_renewal(
            tenant_id, approval_id, actor=actor, notes=body.notes
        )
    except policy_mod.TenantScopeError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RenewalSkipped as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return ApprovalOut.build(approval)
