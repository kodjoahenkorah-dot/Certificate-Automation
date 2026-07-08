"""Per-tenant credential resolution.

INTEGRATION POINT: Clear Ops already holds per-tenant Azure credentials for
its scan jobs — implement TenantCredentialResolver on top of that store and
pass it to the engine. The engine never caches credentials across tenants;
it asks the resolver per attempt, keyed by the certificate's own tenant_id
(which policy.assert_tenant_scope has already validated).

EnvTenantCredentialResolver is provided for local testing only: it reads
CERT_RENEWAL_TENANT_<TENANTID>_{TENANT,CLIENT_ID,CLIENT_SECRET} and builds a
ClientSecretCredential. Azure imports are deferred so the core package works
without the Azure SDK installed.
"""

from __future__ import annotations

import abc
import os
from typing import Any, Optional


class CredentialNotConfiguredError(Exception):
    pass


class TenantCredentialResolver(abc.ABC):
    @abc.abstractmethod
    def azure_credential(self, tenant_id: str) -> Any:
        """Return an azure.core TokenCredential scoped to this tenant.
        Raise CredentialNotConfiguredError if none exists."""

    @abc.abstractmethod
    def azure_subscription_id(self, tenant_id: str) -> Optional[str]:
        """Default Azure subscription for management-plane calls when the
        certificate row doesn't carry one."""

    def acme_account_key_pem(self, tenant_id: str) -> Optional[bytes]:
        """Optional per-tenant ACME account key (PEM). None => the ACME
        provider registers a fresh account (fine for Let's Encrypt)."""
        return None


class EnvTenantCredentialResolver(TenantCredentialResolver):
    """CERT_RENEWAL_TENANT_<ID>_TENANT / _CLIENT_ID / _CLIENT_SECRET, where
    <ID> is the tenant id uppercased with non-alphanumerics replaced by _."""

    @staticmethod
    def _key(tenant_id: str, suffix: str) -> str:
        safe = "".join(ch if ch.isalnum() else "_" for ch in tenant_id).upper()
        return f"CERT_RENEWAL_TENANT_{safe}_{suffix}"

    def azure_credential(self, tenant_id: str) -> Any:
        tenant = os.environ.get(self._key(tenant_id, "TENANT"))
        client_id = os.environ.get(self._key(tenant_id, "CLIENT_ID"))
        secret = os.environ.get(self._key(tenant_id, "CLIENT_SECRET"))
        if not (tenant and client_id and secret):
            raise CredentialNotConfiguredError(
                f"No Azure credential configured for tenant {tenant_id!r} "
                f"(set {self._key(tenant_id, 'TENANT')} / _CLIENT_ID / _CLIENT_SECRET)"
            )
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(
            tenant_id=tenant, client_id=client_id, client_secret=secret
        )

    def azure_subscription_id(self, tenant_id: str) -> Optional[str]:
        return os.environ.get(self._key(tenant_id, "SUBSCRIPTION_ID"))
