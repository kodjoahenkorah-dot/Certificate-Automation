"""Notification port.

INTEGRATION POINT: implement Notifier against the product's existing
notification system (email, in-app, Teams/Slack, ...). The engine calls
exactly these three hooks; each receives the certificate (with owner
name/email) and the full attempt record. Certs with no owner are still
reported — route those to a tenant-level default channel.

LoggingNotifier is the safe default used in dry-run rollouts.
"""

from __future__ import annotations

import abc
import logging

from cert_renewal.models.domain import Certificate, RenewalAttempt

log = logging.getLogger("cert_renewal.notifications")


class Notifier(abc.ABC):
    @abc.abstractmethod
    def renewal_succeeded(self, cert: Certificate, attempt: RenewalAttempt) -> None:
        ...

    @abc.abstractmethod
    def renewal_failed(self, cert: Certificate, attempt: RenewalAttempt) -> None:
        """Called on each failed attempt. attempt.attempt_number vs the
        policy's max_attempts tells you whether retries remain."""

    @abc.abstractmethod
    def manual_action_required(self, cert: Certificate, attempt: RenewalAttempt) -> None:
        """Automation is not possible (or retries are exhausted) and a Work
        Item was created — attempt.work_item_id references it."""


class LoggingNotifier(Notifier):
    def renewal_succeeded(self, cert: Certificate, attempt: RenewalAttempt) -> None:
        log.info(
            "[tenant=%s] Renewal succeeded for %s (owner=%s) new_expiry=%s dry_run=%s",
            cert.tenant_id, cert.name, cert.owner_email or "unassigned",
            attempt.new_expires_at, attempt.dry_run,
        )

    def renewal_failed(self, cert: Certificate, attempt: RenewalAttempt) -> None:
        log.warning(
            "[tenant=%s] Renewal attempt %d failed for %s (owner=%s): %s dry_run=%s",
            cert.tenant_id, attempt.attempt_number, cert.name,
            cert.owner_email or "unassigned", attempt.error, attempt.dry_run,
        )

    def manual_action_required(self, cert: Certificate, attempt: RenewalAttempt) -> None:
        log.warning(
            "[tenant=%s] Manual renewal required for %s (owner=%s) work_item=%s: %s",
            cert.tenant_id, cert.name, cert.owner_email or "unassigned",
            attempt.work_item_id, attempt.detail,
        )
