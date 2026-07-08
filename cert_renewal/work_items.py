"""Work Item port.

INTEGRATION POINT: implement WorkItemSink against the product's existing
Work Items feature. The manual-fallback provider calls create() when a
certificate cannot be renewed automatically (paid CA, missing DNS control,
retries exhausted). Return your Work Item's id so it can be stored on the
audit record and linked from the UI.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import Optional

from cert_renewal.models.domain import Certificate, new_id

log = logging.getLogger("cert_renewal.work_items")


@dataclass
class WorkItemRequest:
    tenant_id: str
    title: str
    description: str
    severity: str = "high"                 # matches product severity pills
    assignee_email: Optional[str] = None   # cert owner; None => Unassigned
    certificate_id: Optional[str] = None
    labels: list[str] = field(default_factory=lambda: ["certificate-renewal"])


class WorkItemSink(abc.ABC):
    @abc.abstractmethod
    def create(self, request: WorkItemRequest) -> str:
        """Create a Work Item, return its id."""


class LoggingWorkItemSink(WorkItemSink):
    """Default no-op sink: logs and returns a synthetic id. Replace before
    going live so manual-renewal tasks reach the real Work Items queue."""

    def __init__(self):
        self.created: list[WorkItemRequest] = []  # inspectable in tests/dev

    def create(self, request: WorkItemRequest) -> str:
        self.created.append(request)
        work_item_id = f"wi-{new_id()[:8]}"
        log.info(
            "[tenant=%s] Work Item %s: %s (assignee=%s)",
            request.tenant_id, work_item_id, request.title,
            request.assignee_email or "unassigned",
        )
        return work_item_id


def build_manual_renewal_instructions(cert: Certificate) -> str:
    """Issuer-aware renewal instructions used as the Work Item body — the
    same tone as the product's remediation texts on the Findings page."""
    days = cert.days_to_expiry()
    urgency = (
        f"This certificate EXPIRED {abs(int(days))} days ago."
        if days <= 0
        else f"This certificate expires in {int(days)} days."
    )
    lines = [
        f"Certificate: {cert.name}",
        f"Domains: {', '.join(cert.domains) or 'n/a'}",
        f"Thumbprint: {cert.thumbprint or 'n/a'}",
        f"Issuer: {cert.issuer or 'unknown'}",
        f"Expiry: {cert.expires_at.date().isoformat()} — {urgency}",
        "",
        "Automated renewal is not available for this certificate. Steps:",
    ]
    source = cert.source.value
    if source == "key_vault":
        lines += [
            f"1. Renew in Key Vault: az keyvault certificate create "
            f"--vault-name <vault> --name {cert.key_vault_cert_name or cert.name} "
            f"--policy @policy.json (or merge a CSR signed by the CA).",
        ]
    elif source == "app_service":
        lines += [
            "1. Azure portal > App Service > Custom domains > Certificates, "
            "renew or re-import the certificate.",
        ]
    else:
        lines += [
            f"1. Purchase/renew the certificate with {cert.issuer or 'the issuing CA'}.",
            "2. Generate a CSR for the listed domains and complete the CA's "
            "validation flow.",
            "3. Install the issued certificate on the serving endpoint(s) and "
            "update any Azure bindings.",
        ]
    lines += [
        "Finally: re-run a scan (Scans > Run Full Scan) so Clear Ops picks up "
        "the new expiry and closes the finding.",
    ]
    return "\n".join(lines)
