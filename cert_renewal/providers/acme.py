"""ACME renewal provider (Let's Encrypt / ZeroSSL / any RFC 8555 CA).

Requires the [acme] extra (acme, josepy, cryptography).

The engine routes an EXTERNAL cert here only when its issuer is an ACME CA
(see models.domain.ACME_AUTOMATABLE_ISSUERS); paid-CA certs never reach this
provider. Even so, this provider needs a *challenge solver* to prove domain
control, and that is deployment-specific — so it is a port:

    ChallengeSolver.setup(domain, token, key_authorization) -> None
    ChallengeSolver.cleanup(domain, token) -> None

Provide a DNS-01 solver (create the _acme-challenge TXT record — e.g. via
Azure DNS, which the AzureDnsChallengeSolver below implements) or an HTTP-01
solver (serve the token at /.well-known/acme-challenge/<token>). If no
solver is configured, or the issued cert can't be installed anywhere
automatically, the provider reports MANUAL_REQUIRED instead of failing.

Dry run: no ACME order is placed, no DNS records are written. The provider
reports the exact plan (directory, domains, challenge type).

NOTE ON INSTALLATION: issuing a cert is only half the job — it must also be
installed where traffic terminates. That is deployment-specific too, so it's
the second port (CertificateInstaller). The default is None => the issued
material is reported via MANUAL_REQUIRED with the PEM stored nowhere; wire
an installer (e.g. import into Key Vault) before enabling live ACME runs.
"""

from __future__ import annotations

import abc
import logging
import time
from datetime import timezone
from typing import Optional

from cert_renewal.models.domain import (
    AttemptStatus,
    Certificate,
    RenewalResult,
)
from cert_renewal.providers.base import ProviderContext, RenewalProvider

log = logging.getLogger("cert_renewal.providers.acme")


class ChallengeSolver(abc.ABC):
    """Proves control of a domain for one ACME challenge."""

    challenge_type: str = "dns-01"  # or "http-01"

    @abc.abstractmethod
    def setup(self, domain: str, token: str, key_authorization: str) -> None:
        ...

    @abc.abstractmethod
    def cleanup(self, domain: str, token: str) -> None:
        ...

    def propagation_wait_seconds(self) -> int:
        return 30 if self.challenge_type == "dns-01" else 0


class CertificateInstaller(abc.ABC):
    """Installs issued PEM material where traffic terminates (e.g. imports
    into Key Vault, pushes to a CDN, updates an App Gateway listener)."""

    @abc.abstractmethod
    def install(
        self, cert: Certificate, fullchain_pem: bytes, private_key_pem: bytes
    ) -> None:
        ...


class AzureDnsChallengeSolver(ChallengeSolver):
    """DNS-01 via Azure DNS. Requires [azure] extra and DNS Zone Contributor
    on the zone. zone_map: domain suffix -> (subscription_id, resource_group,
    zone_name); credential: azure.core TokenCredential for the tenant."""

    challenge_type = "dns-01"

    def __init__(self, credential, zone_map: dict[str, tuple[str, str, str]]):
        self._credential = credential
        self._zone_map = zone_map

    def _zone_for(self, domain: str):
        best = None
        for suffix, target in self._zone_map.items():
            if domain == suffix or domain.endswith("." + suffix):
                if best is None or len(suffix) > len(best[0]):
                    best = (suffix, target)
        if best is None:
            raise LookupError(f"No Azure DNS zone configured for {domain!r}")
        return best

    def _record_name(self, domain: str, zone_suffix: str) -> str:
        bare = domain[2:] if domain.startswith("*.") else domain
        prefix = bare[: -len(zone_suffix)].rstrip(".")
        return f"_acme-challenge.{prefix}" if prefix else "_acme-challenge"

    def _client(self, subscription_id: str):
        from azure.mgmt.dns import DnsManagementClient

        return DnsManagementClient(self._credential, subscription_id)

    def setup(self, domain: str, token: str, key_authorization: str) -> None:
        import base64
        import hashlib

        digest = hashlib.sha256(key_authorization.encode()).digest()
        txt_value = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        suffix, (sub, rg, zone) = self._zone_for(domain)
        self._client(sub).record_sets.create_or_update(
            rg, zone, self._record_name(domain, suffix), "TXT",
            {"ttl": 60, "txt_records": [{"value": [txt_value]}]},
        )

    def cleanup(self, domain: str, token: str) -> None:
        suffix, (sub, rg, zone) = self._zone_for(domain)
        try:
            self._client(sub).record_sets.delete(
                rg, zone, self._record_name(domain, suffix), "TXT"
            )
        except Exception:
            log.warning("Failed to clean up TXT record for %s", domain, exc_info=True)


class AcmeRenewalProvider(RenewalProvider):
    def __init__(
        self,
        solver: Optional[ChallengeSolver] = None,
        installer: Optional[CertificateInstaller] = None,
    ):
        self._solver = solver
        self._installer = installer

    def renew(self, cert: Certificate, ctx: ProviderContext) -> RenewalResult:
        domains = cert.domains or ([cert.name] if "." in cert.name else [])
        if not domains:
            return RenewalResult(
                status=AttemptStatus.FAILED,
                error="Certificate row has no domains; cannot build an ACME order.",
            )
        if self._solver is None:
            return RenewalResult(
                status=AttemptStatus.MANUAL_REQUIRED,
                detail=(
                    "No ACME challenge solver is configured for this deployment, "
                    "so domain control cannot be proven automatically. Renew "
                    "manually or configure a DNS-01/HTTP-01 solver."
                ),
            )
        if self._installer is None:
            return RenewalResult(
                status=AttemptStatus.MANUAL_REQUIRED,
                detail=(
                    "No CertificateInstaller is configured; an ACME cert could be "
                    "issued but not installed anywhere. Configure an installer "
                    "(e.g. Key Vault import) before enabling live ACME renewals."
                ),
            )
        wildcard = [d for d in domains if d.startswith("*.")]
        if wildcard and self._solver.challenge_type != "dns-01":
            return RenewalResult(
                status=AttemptStatus.MANUAL_REQUIRED,
                detail=(
                    f"Wildcard domains ({', '.join(wildcard)}) require DNS-01, but "
                    f"the configured solver is {self._solver.challenge_type}."
                ),
            )

        if ctx.dry_run:
            return RenewalResult(
                status=AttemptStatus.SUCCEEDED,
                detail=(
                    f"DRY RUN: would order a certificate for "
                    f"{', '.join(domains)} from {ctx.config.acme_directory_url} "
                    f"using {self._solver.challenge_type}, then install via "
                    f"{type(self._installer).__name__}. No ACME order placed, "
                    "no DNS/HTTP changes made."
                ),
            )

        return self._issue(cert, domains, ctx)

    # -- live issuance ---------------------------------------------------

    def _issue(
        self, cert: Certificate, domains: list[str], ctx: ProviderContext
    ) -> RenewalResult:
        import josepy as jose
        from acme import challenges, client, crypto_util, messages
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Account key: per-tenant if provided, else ephemeral registration.
        if ctx.acme_account_key_pem:
            account_key = jose.JWKRSA(
                key=serialization.load_pem_private_key(
                    ctx.acme_account_key_pem, password=None
                )
            )
        else:
            account_key = jose.JWKRSA(
                key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
            )

        net = client.ClientNetwork(account_key, user_agent="cert-renewal/0.1")
        directory = client.ClientV2.get_directory(ctx.config.acme_directory_url, net)
        acme_client = client.ClientV2(directory, net=net)
        contact = (
            (f"mailto:{ctx.config.acme_contact_email}",)
            if ctx.config.acme_contact_email
            else ()
        )
        try:
            acme_client.new_account(
                messages.NewRegistration.from_data(
                    email=ctx.config.acme_contact_email,
                    terms_of_service_agreed=True,
                    contact=contact or None,
                )
            )
        except Exception as exc:  # account may already exist for this key
            if "already" not in str(exc).lower():
                raise

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        csr_pem = crypto_util.make_csr(key_pem, domains)
        order = acme_client.new_order(csr_pem)

        wanted = (
            challenges.DNS01
            if self._solver.challenge_type == "dns-01"
            else challenges.HTTP01
        )
        solved: list[tuple[str, str]] = []  # (domain, token) for cleanup
        try:
            for authz in order.authorizations:
                domain = authz.body.identifier.value
                challenge_body = next(
                    (c for c in authz.body.challenges if isinstance(c.chall, wanted)),
                    None,
                )
                if challenge_body is None:
                    return RenewalResult(
                        status=AttemptStatus.MANUAL_REQUIRED,
                        detail=f"CA offered no {self._solver.challenge_type} "
                               f"challenge for {domain}.",
                    )
                token = challenge_body.chall.encode("token")
                key_auth = challenge_body.chall.key_authorization(account_key)
                self._solver.setup(domain, token, key_auth)
                solved.append((domain, token))

            wait = self._solver.propagation_wait_seconds()
            if wait:
                time.sleep(wait)

            for authz in order.authorizations:
                challenge_body = next(
                    c for c in authz.body.challenges if isinstance(c.chall, wanted)
                )
                acme_client.answer_challenge(
                    challenge_body, challenge_body.response(account_key)
                )

            finalized = acme_client.poll_and_finalize(order)
        finally:
            for domain, token in solved:
                self._solver.cleanup(domain, token)

        fullchain = finalized.fullchain_pem.encode()
        leaf = x509.load_pem_x509_certificate(fullchain)
        self._installer.install(cert, fullchain, key_pem)

        expires = leaf.not_valid_after_utc if hasattr(
            leaf, "not_valid_after_utc"
        ) else leaf.not_valid_after.replace(tzinfo=timezone.utc)
        import hashlib

        thumbprint = hashlib.sha1(
            leaf.public_bytes(serialization.Encoding.DER)
        ).hexdigest().upper()

        log.info(
            "[tenant=%s] ACME renewal for %s succeeded; new expiry %s",
            ctx.tenant_id, ",".join(domains), expires,
        )
        return RenewalResult(
            status=AttemptStatus.SUCCEEDED,
            new_expires_at=expires,
            new_thumbprint=thumbprint,
            detail=f"Issued by {ctx.config.acme_directory_url} and installed via "
                   f"{type(self._installer).__name__}.",
        )
