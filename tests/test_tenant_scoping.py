"""Multi-tenant safety: one tenant's job can never touch another's certs."""

import pytest

from cert_renewal import policy
from cert_renewal.models.domain import AttemptStatus
from tests.conftest import NOW, make_cert
from tests.test_engine import opt_in


class TestTenantScoping:
    def test_cross_tenant_renewal_rejected(self, engine, certs, policies):
        cert_b = make_cert(cert_id="cert-b", tenant_id="tenant-b", days_to_expiry=5)
        certs.add(cert_b)
        opt_in(policies, cert_b)
        # tenant-a's job asks for tenant-b's cert id
        with pytest.raises(policy.TenantScopeError):
            engine.renew_certificate("tenant-a", "cert-b")

    def test_cross_tenant_force_rejected(self, engine, certs, policies):
        cert_b = make_cert(cert_id="cert-b", tenant_id="tenant-b", days_to_expiry=5)
        certs.add(cert_b)
        opt_in(policies, cert_b)
        with pytest.raises(policy.TenantScopeError):
            engine.renew_certificate("tenant-a", "cert-b", force=True)

    def test_sweep_only_touches_own_tenant(self, engine, certs, policies):
        cert_a = make_cert(cert_id="cert-a", tenant_id="tenant-a", days_to_expiry=5)
        cert_b = make_cert(cert_id="cert-b", tenant_id="tenant-b", days_to_expiry=5)
        certs.add(cert_a)
        certs.add(cert_b)
        opt_in(policies, cert_a)
        opt_in(policies, cert_b)
        results = engine.run_due_renewals("tenant-a")
        assert [a.certificate_id for a in results] == ["cert-a"]
        assert all(a.tenant_id == "tenant-a" for a in results)

    def test_credentials_resolved_from_certificate_tenant(
        self, engine, certs, policies, credentials
    ):
        cert = make_cert(tenant_id="tenant-a", days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        assert credentials.requested_tenants == ["tenant-a"]

    def test_provider_context_carries_correct_tenant(
        self, engine, certs, policies, fake_kv_provider
    ):
        cert = make_cert(tenant_id="tenant-a", days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        _, ctx = fake_kv_provider.calls[0]
        assert ctx.tenant_id == "tenant-a"
        assert ctx.azure_credential == "credential-for-tenant-a"

    def test_policy_cannot_be_attached_across_tenants(self, policies):
        cert = make_cert(tenant_id="tenant-a")
        from cert_renewal.models.domain import RenewalPolicy

        foreign = RenewalPolicy(certificate_id="cert-1", tenant_id="tenant-b")
        with pytest.raises(policy.TenantScopeError):
            policy.enable_auto_renewal(
                foreign, certificate=cert, actor="a@b.c", now=NOW
            )

    def test_attempt_history_is_tenant_filtered(
        self, engine, certs, policies, attempts
    ):
        cert = make_cert(tenant_id="tenant-a", days_to_expiry=5)
        certs.add(cert)
        opt_in(policies, cert)
        engine.renew_certificate("tenant-a", "cert-1")
        assert attempts.list_for_certificate("tenant-b", "cert-1") == []
