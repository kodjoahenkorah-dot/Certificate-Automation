"""Shared fixtures: in-memory repos, fake providers, frozen clock.

No Azure/ACME/FastAPI dependencies — the engine and policy layers are pure
Python, which is what these tests exercise.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cert_renewal.config import RenewalConfig
from cert_renewal.credentials import TenantCredentialResolver
from cert_renewal.engine import RenewalEngine
from cert_renewal.models.domain import (
    AttemptStatus,
    Certificate,
    CertSource,
    RenewalMethod,
    RenewalResult,
)
from cert_renewal.notifications import Notifier
from cert_renewal.providers.base import ProviderContext, RenewalProvider
from cert_renewal.providers.manual import ManualFallbackProvider
from cert_renewal.repository import (
    InMemoryAttemptRepository,
    InMemoryCertRepository,
    InMemoryPolicyRepository,
)
from cert_renewal.work_items import LoggingWorkItemSink

NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


class FrozenClock:
    def __init__(self, now: datetime = NOW):
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now += timedelta(**kwargs)


class FakeProvider(RenewalProvider):
    """Scripted provider that records every call it receives."""

    def __init__(self, result: RenewalResult | None = None):
        self.result = result or RenewalResult(
            status=AttemptStatus.SUCCEEDED,
            new_expires_at=NOW + timedelta(days=365),
            new_thumbprint="AA11BB22CC33",
        )
        self.calls: list[tuple[Certificate, ProviderContext]] = []
        self.raise_exc: Exception | None = None

    def renew(self, cert: Certificate, ctx: ProviderContext) -> RenewalResult:
        self.calls.append((cert, ctx))
        if self.raise_exc:
            raise self.raise_exc
        return self.result


class FakeCredentials(TenantCredentialResolver):
    def __init__(self):
        self.requested_tenants: list[str] = []

    def azure_credential(self, tenant_id: str):
        self.requested_tenants.append(tenant_id)
        return f"credential-for-{tenant_id}"

    def azure_subscription_id(self, tenant_id: str):
        return f"sub-{tenant_id}"


class RecordingNotifier(Notifier):
    def __init__(self):
        self.succeeded, self.failed, self.manual = [], [], []

    def renewal_succeeded(self, cert, attempt):
        self.succeeded.append((cert, attempt))

    def renewal_failed(self, cert, attempt):
        self.failed.append((cert, attempt))

    def manual_action_required(self, cert, attempt):
        self.manual.append((cert, attempt))


def make_cert(
    cert_id="cert-1",
    tenant_id="tenant-a",
    source=CertSource.KEY_VAULT,
    days_to_expiry=10,
    issuer="GlobalSign GCC R3",
    **kwargs,
) -> Certificate:
    defaults = dict(
        name=f"cert-{cert_id}",
        domains=["example.anadata.com"],
        thumbprint="00FFAA",
        owner_email="owner@anadata.com",
        key_vault_url="https://kv.vault.azure.net",
        key_vault_cert_name="kv-cert",
    )
    defaults.update(kwargs)
    return Certificate(
        id=cert_id,
        tenant_id=tenant_id,
        source=source,
        expires_at=NOW + timedelta(days=days_to_expiry),
        issuer=issuer,
        **defaults,
    )


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def certs():
    return InMemoryCertRepository()


@pytest.fixture
def policies():
    return InMemoryPolicyRepository()


@pytest.fixture
def attempts():
    return InMemoryAttemptRepository()


@pytest.fixture
def work_items():
    return LoggingWorkItemSink()


@pytest.fixture
def notifier():
    return RecordingNotifier()


@pytest.fixture
def credentials():
    return FakeCredentials()


@pytest.fixture
def fake_kv_provider():
    return FakeProvider()


@pytest.fixture
def config():
    # Live mode by default in tests so dry-run behavior is opted into
    # explicitly by the tests that cover it.
    return RenewalConfig(dry_run=False, retry_interval_minutes=60, max_attempts=3)


@pytest.fixture
def engine(certs, policies, attempts, work_items, notifier, credentials,
           fake_kv_provider, config, clock):
    return RenewalEngine(
        certs=certs,
        policies=policies,
        attempts=attempts,
        providers={
            RenewalMethod.KEY_VAULT: fake_kv_provider,
            RenewalMethod.APP_SERVICE: FakeProvider(),
            RenewalMethod.ACME: FakeProvider(),
            RenewalMethod.MANUAL: ManualFallbackProvider(work_items),
        },
        credentials=credentials,
        notifier=notifier,
        work_items=work_items,
        config=config,
        clock=clock,
    )
