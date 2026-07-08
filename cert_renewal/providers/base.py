"""Provider contract.

A provider executes one renewal for one certificate and reports a
RenewalResult. Providers MUST honor ctx.dry_run: when it is True, no call
that mutates external state (Azure, ACME, DNS) may be made — describe what
would happen in RenewalResult.detail instead. The engine additionally
verifies opt-in and tenant scope before a provider is ever invoked, so
providers can assume both.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Optional

from cert_renewal.config import RenewalConfig
from cert_renewal.models.domain import Certificate, RenewalResult


@dataclass
class ProviderContext:
    tenant_id: str
    dry_run: bool
    config: RenewalConfig
    # azure.core TokenCredential for THIS tenant, resolved per attempt.
    azure_credential: Optional[Any] = None
    azure_subscription_id: Optional[str] = None
    acme_account_key_pem: Optional[bytes] = None


class RenewalProvider(abc.ABC):
    """Implementations must be stateless across calls (the engine may reuse
    one instance across tenants); all tenant-specific state comes in ctx."""

    @abc.abstractmethod
    def renew(self, cert: Certificate, ctx: ProviderContext) -> RenewalResult:
        ...
