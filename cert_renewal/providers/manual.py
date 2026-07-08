"""Manual fallback provider.

Handles every certificate that cannot be renewed automatically — paid-CA
external certs (GlobalSign, Sectigo, GoDaddy, AlphaSSL, SSL2BUY, ...) and
anything the other providers hand back as MANUAL_REQUIRED at the engine
level. It creates a Work Item assigned to the certificate owner with
issuer-specific renewal instructions and reports MANUAL_REQUIRED so the
attempt is not retried as if it were a transient failure.

Dry run: no Work Item is created; the result describes the one that would be.
"""

from __future__ import annotations

from cert_renewal.models.domain import (
    AttemptStatus,
    Certificate,
    RenewalResult,
)
from cert_renewal.providers.base import ProviderContext, RenewalProvider
from cert_renewal.work_items import (
    WorkItemRequest,
    WorkItemSink,
    build_manual_renewal_instructions,
)


class ManualFallbackProvider(RenewalProvider):
    def __init__(self, work_items: WorkItemSink):
        self._work_items = work_items

    def renew(self, cert: Certificate, ctx: ProviderContext) -> RenewalResult:
        instructions = build_manual_renewal_instructions(cert)
        title = f"Renew certificate {cert.name}"
        severity = "critical" if cert.is_expired() else "high"

        if ctx.dry_run:
            return RenewalResult(
                status=AttemptStatus.MANUAL_REQUIRED,
                detail=(
                    f"DRY RUN: would create a {severity} Work Item "
                    f"'{title}' assigned to "
                    f"{cert.owner_email or 'Unassigned'} with these "
                    f"instructions:\n{instructions}"
                ),
            )

        work_item_id = self._work_items.create(
            WorkItemRequest(
                tenant_id=cert.tenant_id,
                title=title,
                description=instructions,
                severity=severity,
                assignee_email=cert.owner_email,
                certificate_id=cert.id,
            )
        )
        return RenewalResult(
            status=AttemptStatus.MANUAL_REQUIRED,
            work_item_id=work_item_id,
            detail=(
                f"Automated renewal is not available for issuer "
                f"'{cert.issuer or 'unknown'}'. Work Item {work_item_id} created "
                f"for {cert.owner_email or 'Unassigned'}."
            ),
        )
