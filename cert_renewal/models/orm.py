"""SQLAlchemy adapter (optional — requires `pip install .[sqlalchemy]`).

Two new tables are introduced; the existing certificates table is NOT
duplicated here. Instead, SqlCertRepository is left abstract on the read
side so the integrating team maps their own certificates model in one method.

    cert_renewal_policies   one row per opted-in certificate
    cert_renewal_attempts   append-only audit log

If the product uses a different ORM, skip this module entirely and implement
the three ports in repository.py directly.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from cert_renewal.models.domain import (
    AttemptStatus,
    RenewalAttempt,
    RenewalMethod,
    RenewalPolicy,
)
from cert_renewal.repository import AttemptRepository, PolicyRepository


class Base(DeclarativeBase):
    pass


class RenewalPolicyRow(Base):
    __tablename__ = "cert_renewal_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "certificate_id", name="uq_policy_tenant_cert"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    certificate_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    auto_renew_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enabled_by: Mapped[Optional[str]] = mapped_column(String(256))
    enabled_at: Mapped[Optional[object]] = mapped_column(DateTime(timezone=True))
    disabled_by: Mapped[Optional[str]] = mapped_column(String(256))
    disabled_at: Mapped[Optional[object]] = mapped_column(DateTime(timezone=True))
    renewal_window_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    dry_run_override: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    max_attempts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    retry_interval_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_domain(self) -> RenewalPolicy:
        return RenewalPolicy(
            certificate_id=self.certificate_id,
            tenant_id=self.tenant_id,
            auto_renew_enabled=self.auto_renew_enabled,
            enabled_by=self.enabled_by,
            enabled_at=self.enabled_at,
            disabled_by=self.disabled_by,
            disabled_at=self.disabled_at,
            renewal_window_days=self.renewal_window_days,
            dry_run_override=self.dry_run_override,
            max_attempts=self.max_attempts,
            retry_interval_minutes=self.retry_interval_minutes,
            updated_at=self.updated_at,
        )

    def apply(self, p: RenewalPolicy) -> None:
        self.auto_renew_enabled = p.auto_renew_enabled
        self.enabled_by = p.enabled_by
        self.enabled_at = p.enabled_at
        self.disabled_by = p.disabled_by
        self.disabled_at = p.disabled_at
        self.renewal_window_days = p.renewal_window_days
        self.dry_run_override = p.dry_run_override
        self.max_attempts = p.max_attempts
        self.retry_interval_minutes = p.retry_interval_minutes
        self.updated_at = p.updated_at


class RenewalAttemptRow(Base):
    __tablename__ = "cert_renewal_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    certificate_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    method: Mapped[Optional[str]] = mapped_column(String(32))
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    triggered_by: Mapped[str] = mapped_column(String(256), default="scheduler")
    started_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    finished_at: Mapped[Optional[object]] = mapped_column(DateTime(timezone=True))
    new_expires_at: Mapped[Optional[object]] = mapped_column(DateTime(timezone=True))
    new_thumbprint: Mapped[Optional[str]] = mapped_column(String(128))
    error: Mapped[Optional[str]] = mapped_column(Text)
    work_item_id: Mapped[Optional[str]] = mapped_column(String(128))
    detail: Mapped[Optional[str]] = mapped_column(Text)

    @classmethod
    def from_domain(cls, a: RenewalAttempt) -> "RenewalAttemptRow":
        return cls(
            id=a.id,
            tenant_id=a.tenant_id,
            certificate_id=a.certificate_id,
            status=a.status.value,
            method=a.method.value if a.method else None,
            dry_run=a.dry_run,
            attempt_number=a.attempt_number,
            triggered_by=a.triggered_by,
            started_at=a.started_at,
            finished_at=a.finished_at,
            new_expires_at=a.new_expires_at,
            new_thumbprint=a.new_thumbprint,
            error=a.error,
            work_item_id=a.work_item_id,
            detail=a.detail,
        )

    def to_domain(self) -> RenewalAttempt:
        return RenewalAttempt(
            id=self.id,
            tenant_id=self.tenant_id,
            certificate_id=self.certificate_id,
            status=AttemptStatus(self.status),
            method=RenewalMethod(self.method) if self.method else None,
            dry_run=self.dry_run,
            attempt_number=self.attempt_number,
            triggered_by=self.triggered_by,
            started_at=self.started_at,
            finished_at=self.finished_at,
            new_expires_at=self.new_expires_at,
            new_thumbprint=self.new_thumbprint,
            error=self.error,
            work_item_id=self.work_item_id,
            detail=self.detail,
        )


class SqlPolicyRepository(PolicyRepository):
    """session_factory: a zero-arg callable returning a Session context
    manager, e.g. ``sessionmaker(engine)``."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def get(self, tenant_id: str, certificate_id: str) -> Optional[RenewalPolicy]:
        with self._session_factory() as s:
            row = self._row(s, tenant_id, certificate_id)
            return row.to_domain() if row else None

    def save(self, policy: RenewalPolicy) -> None:
        with self._session_factory() as s:
            row = self._row(s, policy.tenant_id, policy.certificate_id)
            if row is None:
                row = RenewalPolicyRow(
                    tenant_id=policy.tenant_id,
                    certificate_id=policy.certificate_id,
                    updated_at=policy.updated_at,
                )
                s.add(row)
            row.apply(policy)
            s.commit()

    def list_enabled_for_tenant(self, tenant_id: str) -> list[RenewalPolicy]:
        with self._session_factory() as s:
            rows = s.scalars(
                select(RenewalPolicyRow).where(
                    RenewalPolicyRow.tenant_id == tenant_id,
                    RenewalPolicyRow.auto_renew_enabled.is_(True),
                )
            ).all()
            return [r.to_domain() for r in rows]

    @staticmethod
    def _row(s: Session, tenant_id: str, certificate_id: str):
        return s.scalars(
            select(RenewalPolicyRow).where(
                RenewalPolicyRow.tenant_id == tenant_id,
                RenewalPolicyRow.certificate_id == certificate_id,
            )
        ).first()


class SqlAttemptRepository(AttemptRepository):
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def save(self, attempt: RenewalAttempt) -> None:
        with self._session_factory() as s:
            existing = s.get(RenewalAttemptRow, attempt.id)
            if existing is None:
                s.add(RenewalAttemptRow.from_domain(attempt))
            else:
                fresh = RenewalAttemptRow.from_domain(attempt)
                for col in RenewalAttemptRow.__table__.columns.keys():
                    setattr(existing, col, getattr(fresh, col))
            s.commit()

    def list_for_certificate(
        self, tenant_id: str, certificate_id: str, limit: int = 20
    ) -> list[RenewalAttempt]:
        with self._session_factory() as s:
            rows = s.scalars(
                select(RenewalAttemptRow)
                .where(
                    RenewalAttemptRow.tenant_id == tenant_id,
                    RenewalAttemptRow.certificate_id == certificate_id,
                )
                .order_by(RenewalAttemptRow.started_at.desc())
                .limit(limit)
            ).all()
            return [r.to_domain() for r in rows]

    def attempts_since_last_success(
        self, tenant_id: str, certificate_id: str
    ) -> list[RenewalAttempt]:
        terminal = [s.value for s in AttemptStatus if s.is_terminal]
        with self._session_factory() as s:
            rows = s.scalars(
                select(RenewalAttemptRow)
                .where(
                    RenewalAttemptRow.tenant_id == tenant_id,
                    RenewalAttemptRow.certificate_id == certificate_id,
                    RenewalAttemptRow.dry_run.is_(False),
                    RenewalAttemptRow.status.in_(terminal),
                )
                .order_by(RenewalAttemptRow.started_at.asc())
            ).all()
        streak: list[RenewalAttempt] = []
        for row in rows:
            if row.status == AttemptStatus.SUCCEEDED.value:
                streak = []
            else:
                streak.append(row.to_domain())
        return streak
