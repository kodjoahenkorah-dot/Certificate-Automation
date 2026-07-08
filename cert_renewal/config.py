"""Engine configuration.

Every value can come from the environment (CERT_RENEWAL_* variables) or be
constructed programmatically. Safety-relevant defaults:

  * dry_run defaults to True — nothing mutates real certificates until the
    integrating team flips CERT_RENEWAL_DRY_RUN=false (and even then,
    per-tenant and per-policy overrides can keep dry-run on).
  * default_renewal_window_days = 30, matching the product's
    "expiring <= 30 days" counter.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


@dataclass
class RenewalConfig:
    # Global dry-run switch. True (safe) unless explicitly disabled.
    dry_run: bool = True
    # Tenants forced into dry-run even when the global switch is off.
    dry_run_tenants: frozenset[str] = field(default_factory=frozenset)

    default_renewal_window_days: int = 30
    max_attempts: int = 3
    retry_interval_minutes: int = 60 * 6   # 6h between retries within a cycle

    # ACME
    acme_directory_url: str = "https://acme-v02.api.letsencrypt.org/directory"
    acme_contact_email: str | None = None

    # How many certs a single scheduler sweep may attempt per tenant, as a
    # blast-radius guard for the first production runs. 0 = unlimited.
    max_renewals_per_sweep: int = 0

    @classmethod
    def from_env(cls) -> "RenewalConfig":
        tenants = os.environ.get("CERT_RENEWAL_DRY_RUN_TENANTS", "")
        return cls(
            dry_run=_env_bool("CERT_RENEWAL_DRY_RUN", True),
            dry_run_tenants=frozenset(
                t.strip() for t in tenants.split(",") if t.strip()
            ),
            default_renewal_window_days=_env_int("CERT_RENEWAL_WINDOW_DAYS", 30),
            max_attempts=_env_int("CERT_RENEWAL_MAX_ATTEMPTS", 3),
            retry_interval_minutes=_env_int("CERT_RENEWAL_RETRY_INTERVAL_MINUTES", 360),
            acme_directory_url=os.environ.get(
                "CERT_RENEWAL_ACME_DIRECTORY",
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
            acme_contact_email=os.environ.get("CERT_RENEWAL_ACME_CONTACT") or None,
            max_renewals_per_sweep=_env_int("CERT_RENEWAL_MAX_PER_SWEEP", 0),
        )
