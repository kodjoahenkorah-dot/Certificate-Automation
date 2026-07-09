"""Azure App Service certificate renewal provider.

Requires the [azure] extra (azure-mgmt-web).

Covers App Service *managed* certificates (the free certs Azure issues for
custom domains, resource type Microsoft.Web/certificates with a canonical
name). Renewal = re-PUT the certificate resource with the same properties;
Azure re-issues against the current domain validation. Uploaded/BYO
certificates in Microsoft.Web/certificates cannot be re-issued by Azure, so
they report MANUAL_REQUIRED (portal: App Service > Custom domains >
Certificates, as the product's remediation text already says).

Dry run: reads the certificate resource only.
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

log = logging.getLogger("cert_renewal.providers.app_service")


class AppServiceRenewalProvider(RenewalProvider):
    def renew(self, cert: Certificate, ctx: ProviderContext) -> RenewalResult:
        missing = [
            f
            for f in ("azure_resource_group", "app_service_cert_name")
            if not getattr(cert, f)
        ]
        if not ctx.azure_subscription_id:
            missing.append("azure_subscription_id")
        if missing:
            return RenewalResult(
                status=AttemptStatus.FAILED,
                error=f"Certificate row is missing {', '.join(missing)}; "
                      "cannot target the App Service certificate resource.",
            )
        if ctx.azure_credential is None:
            return RenewalResult(
                status=AttemptStatus.FAILED,
                error="No Azure credential resolved for this tenant.",
            )

        from azure.mgmt.web import WebSiteManagementClient

        client = WebSiteManagementClient(
            credential=ctx.azure_credential,
            subscription_id=ctx.azure_subscription_id,
        )
        rg = cert.azure_resource_group
        name = cert.app_service_cert_name

        resource = client.certificates.get(rg, name)

        # Managed certs carry a canonical_name; uploaded PFX certs don't and
        # cannot be re-issued by Azure.
        canonical = getattr(resource, "canonical_name", None)
        if not canonical:
            return RenewalResult(
                status=AttemptStatus.MANUAL_REQUIRED,
                detail=(
                    f"App Service certificate '{name}' is an uploaded certificate, "
                    "not an App Service managed certificate; Azure cannot re-issue "
                    "it. Renew with the issuing CA and re-import via the portal "
                    "(App Service > Custom domains > Certificates)."
                ),
            )

        if ctx.dry_run:
            return RenewalResult(
                status=AttemptStatus.SUCCEEDED,
                detail=(
                    f"DRY RUN: would re-issue App Service managed certificate "
                    f"'{name}' (canonical name {canonical}) in resource group "
                    f"'{rg}' of subscription {ctx.azure_subscription_id} by "
                    f"re-submitting the certificate resource; current expiry "
                    f"{getattr(resource, 'expiration_date', '?')}."
                ),
            )

        renewed = client.certificates.create_or_update(rg, name, resource)

        new_expiry = getattr(renewed, "expiration_date", None)
        if new_expiry and new_expiry.tzinfo is None:
            new_expiry = new_expiry.replace(tzinfo=timezone.utc)
        thumbprint = getattr(renewed, "thumbprint", None)

        log.info(
            "[tenant=%s] App Service cert %s renewed; new expiry %s",
            ctx.tenant_id, name, new_expiry,
        )
        return RenewalResult(
            status=AttemptStatus.SUCCEEDED,
            new_expires_at=new_expiry,
            new_thumbprint=thumbprint,
            detail=f"Managed certificate re-issued for {canonical}.",
        )

    def verify(self, cert: Certificate, result, ctx: ProviderContext):
        """Re-read the certificate resource and confirm Azure reports the
        new expiry before the engine records success."""
        from azure.mgmt.web import WebSiteManagementClient

        client = WebSiteManagementClient(
            credential=ctx.azure_credential,
            subscription_id=ctx.azure_subscription_id,
        )
        resource = client.certificates.get(
            cert.azure_resource_group, cert.app_service_cert_name
        )
        expires_on = getattr(resource, "expiration_date", None)
        if expires_on and expires_on.tzinfo is None:
            expires_on = expires_on.replace(tzinfo=timezone.utc)
        if not expires_on or expires_on <= cert.expires_at:
            return (
                f"Azure still reports expiry {expires_on} "
                f"(previous expiry {cert.expires_at})."
            )
        return None
