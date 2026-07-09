"""Persistence ports.

INTEGRATION POINT: the engine talks to storage only through these three
abstract classes. To integrate with the existing Clear Ops database, implement
them against your ORM (a SQLAlchemy implementation is provided in
models/orm.py as a reference / default). The in-memory implementations below
are used by the test suite and are handy for local experimentation.

Every method takes tenant_id explicitly — implementations MUST filter by it.
"""

from __future__ import annotations

import abc
import threading
from dataclasses import replace
from typing import Optional

from cert_renewal.models.domain import (
    ApprovalStatus,
    Certificate,
    RenewalApproval,
    RenewalAttempt,
    RenewalPolicy,
)


class CertRepository(abc.ABC):
    """Read-only access to the product's existing certificates table."""

    @abc.abstractmethod
    def get(self, tenant_id: str, certificate_id: str) -> Optional[Certificate]:
        """Return the cert only if it belongs to tenant_id, else None."""

    @abc.abstractmethod
    def list_for_tenant(self, tenant_id: str) -> list[Certificate]:
        ...

    @abc.abstractmethod
    def update_after_renewal(
        self, tenant_id: str, certificate_id: str, *, new_expires_at, new_thumbprint
    ) -> None:
        """Write the renewed expiry/thumbprint back to the certificates table
        so the UI reflects the renewal before the next full scan."""


class PolicyRepository(abc.ABC):
    @abc.abstractmethod
    def get(self, tenant_id: str, certificate_id: str) -> Optional[RenewalPolicy]:
        ...

    @abc.abstractmethod
    def save(self, policy: RenewalPolicy) -> None:
        ...

    @abc.abstractmethod
    def list_enabled_for_tenant(self, tenant_id: str) -> list[RenewalPolicy]:
        ...


class AttemptRepository(abc.ABC):
    @abc.abstractmethod
    def save(self, attempt: RenewalAttempt) -> None:
        """Insert or update (matched on attempt.id)."""

    @abc.abstractmethod
    def list_for_certificate(
        self, tenant_id: str, certificate_id: str, limit: int = 20
    ) -> list[RenewalAttempt]:
        """Most recent first."""

    @abc.abstractmethod
    def attempts_since_last_success(
        self, tenant_id: str, certificate_id: str
    ) -> list[RenewalAttempt]:
        """Terminal, non-dry-run attempts after the latest SUCCEEDED one
        (i.e. the current failure streak). Used for retry budgeting."""

    @abc.abstractmethod
    def find_work_item_for_window(
        self, tenant_id: str, certificate_id: str, expiration_window_key: str
    ) -> Optional[str]:
        """Id of a Work Item already created for this cert in this expiry
        window, if any. Used to deduplicate manual-fallback Work Items."""


class ApprovalRepository(abc.ABC):
    """Persistence for APPROVAL_REQUIRED-mode sign-offs."""

    @abc.abstractmethod
    def get(self, tenant_id: str, approval_id: str) -> Optional[RenewalApproval]:
        ...

    @abc.abstractmethod
    def find_for_window(
        self, tenant_id: str, certificate_id: str, expiration_window_key: str
    ) -> Optional[RenewalApproval]:
        """Most recent approval for this cert + window, any status."""

    @abc.abstractmethod
    def save(self, approval: RenewalApproval) -> None:
        ...

    @abc.abstractmethod
    def list_pending_for_tenant(self, tenant_id: str) -> list[RenewalApproval]:
        ...


# ---------------------------------------------------------------------------
# In-memory implementations (tests / local experimentation)
# ---------------------------------------------------------------------------


class InMemoryCertRepository(CertRepository):
    def __init__(self, certs: Optional[list[Certificate]] = None):
        self._certs: dict[str, Certificate] = {c.id: c for c in (certs or [])}
        self._lock = threading.Lock()

    def add(self, cert: Certificate) -> None:
        with self._lock:
            self._certs[cert.id] = cert

    def get(self, tenant_id: str, certificate_id: str) -> Optional[Certificate]:
        cert = self._certs.get(certificate_id)
        if cert is None or cert.tenant_id != tenant_id:
            return None
        return cert

    def list_for_tenant(self, tenant_id: str) -> list[Certificate]:
        return [c for c in self._certs.values() if c.tenant_id == tenant_id]

    def update_after_renewal(
        self, tenant_id: str, certificate_id: str, *, new_expires_at, new_thumbprint
    ) -> None:
        with self._lock:
            cert = self.get(tenant_id, certificate_id)
            if cert is None:
                return
            self._certs[certificate_id] = replace(
                cert,
                expires_at=new_expires_at or cert.expires_at,
                thumbprint=new_thumbprint or cert.thumbprint,
            )


class InMemoryPolicyRepository(PolicyRepository):
    def __init__(self):
        self._policies: dict[tuple[str, str], RenewalPolicy] = {}
        self._lock = threading.Lock()

    def get(self, tenant_id: str, certificate_id: str) -> Optional[RenewalPolicy]:
        return self._policies.get((tenant_id, certificate_id))

    def save(self, policy: RenewalPolicy) -> None:
        with self._lock:
            self._policies[(policy.tenant_id, policy.certificate_id)] = policy

    def list_enabled_for_tenant(self, tenant_id: str) -> list[RenewalPolicy]:
        return [
            p
            for (tid, _), p in self._policies.items()
            if tid == tenant_id and p.auto_renew_enabled
        ]


class InMemoryAttemptRepository(AttemptRepository):
    def __init__(self):
        self._attempts: list[RenewalAttempt] = []
        self._lock = threading.Lock()

    def save(self, attempt: RenewalAttempt) -> None:
        with self._lock:
            for i, existing in enumerate(self._attempts):
                if existing.id == attempt.id:
                    self._attempts[i] = attempt
                    return
            self._attempts.append(attempt)

    def _for_cert(self, tenant_id: str, certificate_id: str) -> list[RenewalAttempt]:
        return [
            a
            for a in self._attempts
            if a.tenant_id == tenant_id and a.certificate_id == certificate_id
        ]

    def list_for_certificate(
        self, tenant_id: str, certificate_id: str, limit: int = 20
    ) -> list[RenewalAttempt]:
        rows = sorted(
            self._for_cert(tenant_id, certificate_id),
            key=lambda a: a.started_at,
            reverse=True,
        )
        return rows[:limit]

    def attempts_since_last_success(
        self, tenant_id: str, certificate_id: str
    ) -> list[RenewalAttempt]:
        from cert_renewal.models.domain import AttemptStatus

        rows = sorted(
            self._for_cert(tenant_id, certificate_id), key=lambda a: a.started_at
        )
        streak: list[RenewalAttempt] = []
        for a in rows:
            if a.dry_run or not a.status.is_terminal:
                continue
            if a.status == AttemptStatus.SUCCEEDED:
                streak = []
            else:
                streak.append(a)
        return streak

    def find_work_item_for_window(
        self, tenant_id: str, certificate_id: str, expiration_window_key: str
    ) -> Optional[str]:
        rows = sorted(
            self._for_cert(tenant_id, certificate_id),
            key=lambda a: a.started_at,
            reverse=True,
        )
        for a in rows:
            if (
                a.work_item_id
                and a.expiration_window_key == expiration_window_key
            ):
                return a.work_item_id
        return None


class InMemoryApprovalRepository(ApprovalRepository):
    def __init__(self):
        self._approvals: dict[str, RenewalApproval] = {}
        self._lock = threading.Lock()

    def get(self, tenant_id: str, approval_id: str) -> Optional[RenewalApproval]:
        approval = self._approvals.get(approval_id)
        if approval is None or approval.tenant_id != tenant_id:
            return None
        return approval

    def find_for_window(
        self, tenant_id: str, certificate_id: str, expiration_window_key: str
    ) -> Optional[RenewalApproval]:
        matches = [
            a
            for a in self._approvals.values()
            if a.tenant_id == tenant_id
            and a.certificate_id == certificate_id
            and a.expiration_window_key == expiration_window_key
        ]
        if not matches:
            return None
        return max(matches, key=lambda a: a.requested_at)

    def save(self, approval: RenewalApproval) -> None:
        with self._lock:
            self._approvals[approval.id] = approval

    def list_pending_for_tenant(self, tenant_id: str) -> list[RenewalApproval]:
        return [
            a
            for a in self._approvals.values()
            if a.tenant_id == tenant_id and a.status == ApprovalStatus.PENDING
        ]
