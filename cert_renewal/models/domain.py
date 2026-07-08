"""Framework-free domain models.

These dataclasses are the engine's only view of the world. The integrating
team maps their existing certificates table onto ``Certificate`` inside their
``CertRepository`` implementation (see repository.py); nothing in the engine
depends on SQLAlchemy, FastAPI, or Azure SDKs.

All datetimes are timezone-aware UTC. Naive datetimes are rejected by the
policy layer to avoid off-by-timezone renewal windows.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class CertSource(str, enum.Enum):
    """Where the certificate lives — mirrors the Source column in the
    Certificates page (Azure vs External), split by Azure resource type."""

    KEY_VAULT = "key_vault"        # Microsoft.KeyVault/vaults certificate
    APP_SERVICE = "app_service"    # Microsoft.Web/certificates
    EXTERNAL = "external"          # discovered/imported cert not managed in Azure


class RenewalMethod(str, enum.Enum):
    """How a renewal is executed. Selected from the cert's source + issuer."""

    KEY_VAULT = "key_vault"      # azure-keyvault-certificates begin_create_certificate
    APP_SERVICE = "app_service"  # Azure management API (App Service managed cert)
    ACME = "acme"                # Let's Encrypt / ZeroSSL with DNS-01 or HTTP-01
    MANUAL = "manual"            # Work Item assigned to the cert owner


class AttemptStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    MANUAL_REQUIRED = "manual_required"

    @property
    def is_terminal(self) -> bool:
        return self in (
            AttemptStatus.SUCCEEDED,
            AttemptStatus.FAILED,
            AttemptStatus.MANUAL_REQUIRED,
        )


# CAs whose certificates we can re-issue automatically via ACME. Anything
# else (GlobalSign, Sectigo, GoDaddy, AlphaSSL, SSL2BUY, ...) is a paid CA
# whose renewal is a purchase/CSR workflow -> manual Work Item fallback.
ACME_AUTOMATABLE_ISSUERS = ("let's encrypt", "lets encrypt", "zerossl", "buypass")


@dataclass
class Certificate:
    """Engine-side view of one certificate row.

    INTEGRATION POINT: populate this from your existing certificates table.
    Only ``id``, ``tenant_id``, ``source`` and ``expires_at`` are required for
    the policy logic; the per-source blocks are required for the matching
    provider (documented per field).
    """

    id: str
    tenant_id: str
    name: str                          # e.g. "ci-grc-pfx" or "*.cleardhan.ai"
    source: CertSource
    expires_at: datetime
    domains: list[str] = field(default_factory=list)
    thumbprint: Optional[str] = None
    issuer: Optional[str] = None       # e.g. "GlobalSign GCC ...", "Let's Encrypt"
    owner_name: Optional[str] = None   # None => "Unassigned" in the UI
    owner_email: Optional[str] = None

    # -- KEY_VAULT source --
    key_vault_url: Optional[str] = None       # https://<vault>.vault.azure.net
    key_vault_cert_name: Optional[str] = None

    # -- APP_SERVICE source --
    azure_subscription_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    app_service_cert_name: Optional[str] = None  # Microsoft.Web/certificates name

    # Free-form extras (resource ids, tags, ...). Never read by the engine;
    # passed through to notifications and Work Items for context.
    metadata: dict[str, Any] = field(default_factory=dict)

    def days_to_expiry(self, now: Optional[datetime] = None) -> float:
        now = now or utcnow()
        return (self.expires_at - now).total_seconds() / 86400.0

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return self.days_to_expiry(now) <= 0


@dataclass
class RenewalPolicy:
    """Per-certificate opt-in record. THE default is auto_renew_enabled=False.

    A certificate with no policy row at all is treated identically to one
    with an explicitly disabled policy: it is never renewed.
    """

    certificate_id: str
    tenant_id: str
    auto_renew_enabled: bool = False
    enabled_by: Optional[str] = None      # user identity who opted in
    enabled_at: Optional[datetime] = None
    disabled_by: Optional[str] = None
    disabled_at: Optional[datetime] = None
    renewal_window_days: int = 30         # renew when expiry is within this window
    # Per-cert dry-run override. None = inherit tenant/global setting.
    # The effective value is dry-run if ANY level (global, tenant, policy)
    # says dry-run — see policy.effective_dry_run().
    dry_run_override: Optional[bool] = None
    max_attempts: Optional[int] = None    # None = use RenewalConfig.max_attempts
    retry_interval_minutes: Optional[int] = None  # None = use config default
    updated_at: datetime = field(default_factory=utcnow)


@dataclass
class RenewalAttempt:
    """Audit-log row. One is written for every renewal attempt, including
    dry runs and attempts that were rejected before touching a provider."""

    tenant_id: str
    certificate_id: str
    id: str = field(default_factory=new_id)
    status: AttemptStatus = AttemptStatus.PENDING
    method: Optional[RenewalMethod] = None
    dry_run: bool = True
    attempt_number: int = 1               # 1..max_attempts within a renewal cycle
    triggered_by: str = "scheduler"       # "scheduler" or "api:<user identity>"
    started_at: datetime = field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    # Success outputs
    new_expires_at: Optional[datetime] = None
    new_thumbprint: Optional[str] = None
    # Failure / manual outputs
    error: Optional[str] = None
    work_item_id: Optional[str] = None    # set when a fallback Work Item was created
    detail: Optional[str] = None          # human-readable narrative (esp. dry runs)


@dataclass
class RenewalResult:
    """What a provider returns to the engine."""

    status: AttemptStatus
    new_expires_at: Optional[datetime] = None
    new_thumbprint: Optional[str] = None
    error: Optional[str] = None
    detail: Optional[str] = None
    work_item_id: Optional[str] = None
