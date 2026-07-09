"""Azure Key Vault renewal provider.

Requires the [azure] extra (azure-identity + azure-keyvault-certificates).

How renewal works: for a Key Vault certificate that has an issuer policy
("Self" or an integrated CA like DigiCert/GlobalSign-via-KV),
``begin_create_certificate`` with the certificate's existing policy re-runs
issuance — this is the SDK equivalent of the portal's "New Version" /
`az keyvault certificate renew`. Certificates that were *imported* into Key
Vault (issuer "Unknown") have no issuance pipeline, so the provider reports
MANUAL_REQUIRED and lets the engine's fallback create a Work Item.

Dry run: reads the certificate and its policy (read-only) and reports what
would happen; begin_create_certificate is never called.
"""

from __future__ import annotations

import logging
from datetime import timezone

from cert_renewal.models.domain import (
    AttemptStatus,
    Certificate,
    RenewalResult,
)
from cert_renewal.providers.base import ProviderContext, RenewalProvider

log = logging.getLogger("cert_renewal.providers.key_vault")

# How long to wait for the CA to issue before reporting failure. Integrated
# CAs usually complete in seconds-to-minutes; "Self" is immediate.
ISSUANCE_TIMEOUT_SECONDS = 600


class KeyVaultRenewalProvider(RenewalProvider):
    def renew(self, cert: Certificate, ctx: ProviderContext) -> RenewalResult:
        if not cert.key_vault_url or not cert.key_vault_cert_name:
            return RenewalResult(
                status=AttemptStatus.FAILED,
                error="Certificate row is missing key_vault_url / "
                      "key_vault_cert_name; cannot target the vault.",
            )
        if ctx.azure_credential is None:
            return RenewalResult(
                status=AttemptStatus.FAILED,
                error="No Azure credential resolved for this tenant.",
            )

        from azure.keyvault.certificates import CertificateClient

        client = CertificateClient(
            vault_url=cert.key_vault_url, credential=ctx.azure_credential
        )
        name = cert.key_vault_cert_name

        current = client.get_certificate(name)
        cert_policy = client.get_certificate_policy(name)
        issuer = getattr(cert_policy, "issuer_name", None)

        if not issuer or issuer.lower() == "unknown":
            return RenewalResult(
                status=AttemptStatus.MANUAL_REQUIRED,
                detail=(
                    f"Key Vault certificate '{name}' was imported (issuer policy "
                    "'Unknown'); Key Vault cannot re-issue it. A Work Item with "
                    "manual renewal steps is required."
                ),
            )

        if ctx.dry_run:
            return RenewalResult(
                status=AttemptStatus.SUCCEEDED,
                detail=(
                    f"DRY RUN: would call begin_create_certificate('{name}') on "
                    f"{cert.key_vault_url} with its existing policy "
                    f"(issuer='{issuer}'), current version "
                    f"{getattr(current.properties, 'version', '?')}, current expiry "
                    f"{getattr(current.properties, 'expires_on', '?')}."
                ),
            )

        poller = client.begin_create_certificate(
            certificate_name=name, policy=cert_policy
        )
        renewed = poller.result(timeout=ISSUANCE_TIMEOUT_SECONDS)

        new_expiry = renewed.properties.expires_on
        if new_expiry and new_expiry.tzinfo is None:
            new_expiry = new_expiry.replace(tzinfo=timezone.utc)
        thumbprint = renewed.properties.x509_thumbprint
        if isinstance(thumbprint, (bytes, bytearray)):
            thumbprint = thumbprint.hex().upper()

        log.info(
            "[tenant=%s] Key Vault cert %s renewed; new expiry %s",
            ctx.tenant_id, name, new_expiry,
        )
        return RenewalResult(
            status=AttemptStatus.SUCCEEDED,
            new_expires_at=new_expiry,
            new_thumbprint=thumbprint,
            detail=f"New version created in {cert.key_vault_url} (issuer '{issuer}').",
        )

    def verify(self, cert: Certificate, result, ctx: ProviderContext):
        """Re-read the current certificate version and confirm the vault
        really serves the new expiry before the engine records success."""
        from azure.keyvault.certificates import CertificateClient

        client = CertificateClient(
            vault_url=cert.key_vault_url, credential=ctx.azure_credential
        )
        current = client.get_certificate(cert.key_vault_cert_name)
        expires_on = current.properties.expires_on
        if expires_on and expires_on.tzinfo is None:
            expires_on = expires_on.replace(tzinfo=timezone.utc)
        if not expires_on or expires_on <= cert.expires_at:
            return (
                f"Vault still reports expiry {expires_on} "
                f"(previous expiry {cert.expires_at})."
            )
        return None
