"""Scheduler entry point.

INTEGRATION POINT: Clear Ops already runs per-tenant background scans (the
Scans page). Call RenewalJob.run_tenant(tenant_id) from that same scheduler
— after a tenant's scan completes is the ideal hook, since certificate data
is freshest then. Alternatively run run_all() on a fixed interval (e.g.
hourly); every safety property (opt-in, window, retry cooldown, dry-run)
is enforced inside the engine, so over-calling the job is harmless.

The job never raises for per-certificate problems; it returns a per-tenant
summary suitable for the product's job/scan history.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Iterable

from cert_renewal.engine import RenewalEngine
from cert_renewal.models.domain import AttemptStatus, RenewalAttempt

log = logging.getLogger("cert_renewal.scheduler")


@dataclass
class SweepSummary:
    tenant_id: str
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    manual_required: int = 0
    dry_run: int = 0
    attempts: list[RenewalAttempt] = field(default_factory=list)


class RenewalJob:
    def __init__(self, engine: RenewalEngine):
        self._engine = engine

    def run_tenant(self, tenant_id: str) -> SweepSummary:
        """One isolated sweep for one tenant. An exception for tenant A can
        never affect tenant B because run_all isolates per-tenant calls."""
        summary = SweepSummary(tenant_id=tenant_id)
        attempts = self._engine.run_due_renewals(tenant_id)
        summary.attempts = attempts
        summary.attempted = len(attempts)
        for a in attempts:
            if a.dry_run:
                summary.dry_run += 1
            if a.status == AttemptStatus.SUCCEEDED:
                summary.succeeded += 1
            elif a.status == AttemptStatus.MANUAL_REQUIRED:
                summary.manual_required += 1
            elif a.status == AttemptStatus.FAILED:
                summary.failed += 1
        log.info(
            "[tenant=%s] Renewal sweep: %d attempted, %d succeeded, %d failed, "
            "%d manual, %d dry-run",
            tenant_id, summary.attempted, summary.succeeded, summary.failed,
            summary.manual_required, summary.dry_run,
        )
        return summary

    def run_all(
        self, tenant_ids: Iterable[str],
        on_tenant_error: Callable[[str, Exception], None] | None = None,
    ) -> list[SweepSummary]:
        """Sweep several tenants sequentially, isolating failures per tenant."""
        summaries = []
        for tenant_id in tenant_ids:
            try:
                summaries.append(self.run_tenant(tenant_id))
            except Exception as exc:
                log.exception("[tenant=%s] Renewal sweep crashed", tenant_id)
                if on_tenant_error:
                    on_tenant_error(tenant_id, exc)
        return summaries
