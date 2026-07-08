"""cert_renewal — opt-in automated certificate renewal for Clear Ops.

Layering (inner layers never import outer ones):

    models/domain.py      pure dataclasses + enums, no dependencies
    policy.py             opt-in enforcement + renewal-window math
    repository.py         abstract persistence ports (+ in-memory impl)
    engine.py             orchestration: policy gate -> provider -> audit -> notify
    providers/            Key Vault / App Service / ACME / manual fallback
    scheduler.py          per-tenant sweep, callable from any job runner
    ------- adapters (optional dependencies) -------
    models/orm.py         SQLAlchemy mappings          [pip install .[sqlalchemy]]
    api.py                FastAPI router               [pip install .[api]]
    providers/key_vault.py, app_service.py             [pip install .[azure]]
    providers/acme.py                                  [pip install .[acme]]

Everything above the adapter line imports only the standard library, so the
engine can be unit-tested and integrated without pulling in Azure or FastAPI.
"""

from cert_renewal.config import RenewalConfig
from cert_renewal.models.domain import (
    AttemptStatus,
    Certificate,
    CertSource,
    RenewalAttempt,
    RenewalMethod,
    RenewalPolicy,
)

__all__ = [
    "RenewalConfig",
    "Certificate",
    "CertSource",
    "RenewalPolicy",
    "RenewalAttempt",
    "RenewalMethod",
    "AttemptStatus",
]

__version__ = "0.1.0"
