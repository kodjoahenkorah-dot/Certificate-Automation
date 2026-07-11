-- Certificate renewal tables (PostgreSQL syntax — adapt types for SQL Server).
-- Alternative to an EF Core migration (`dotnet ef migrations add CertRenewal
-- --context CertRenewalDbContext`); apply one or the other, not both.
-- The existing certificates table is NOT modified.

CREATE TABLE IF NOT EXISTS cert_renewal_policies (
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id               varchar(64)  NOT NULL,
    certificate_id          varchar(128) NOT NULL,
    auto_renew_enabled      boolean      NOT NULL DEFAULT false,
    renewal_mode            varchar(32)  NOT NULL DEFAULT 'Automatic'
                            CHECK (renewal_mode IN ('Automatic', 'ApprovalRequired')),
    enabled_by              varchar(256),
    enabled_at              timestamptz,
    disabled_by             varchar(256),
    disabled_at             timestamptz,
    renewal_window_days     integer      NOT NULL DEFAULT 30,
    dry_run_override        boolean,
    max_attempts            integer,
    retry_interval_minutes  integer,
    updated_at              timestamptz  NOT NULL,
    CONSTRAINT uq_policy_tenant_cert UNIQUE (tenant_id, certificate_id)
);

CREATE TABLE IF NOT EXISTS cert_renewal_attempts (
    id                     varchar(36)  PRIMARY KEY,
    tenant_id              varchar(64)  NOT NULL,
    certificate_id         varchar(128) NOT NULL,
    status                 varchar(32)  NOT NULL
                           CHECK (status IN ('Pending', 'InProgress', 'Succeeded', 'Failed', 'ManualRequired')),
    method                 varchar(32),
    dry_run                boolean      NOT NULL DEFAULT true,
    attempt_number         integer      NOT NULL DEFAULT 1,
    expiration_window_key  varchar(32),
    triggered_by           varchar(256) NOT NULL DEFAULT 'scheduler',
    started_at             timestamptz  NOT NULL,
    finished_at            timestamptz,
    new_expires_at         timestamptz,
    new_thumbprint         varchar(128),
    error                  text,
    work_item_id           varchar(128),
    detail                 text
);

CREATE INDEX IF NOT EXISTS ix_attempts_cert_started
    ON cert_renewal_attempts (tenant_id, certificate_id, started_at);
CREATE INDEX IF NOT EXISTS ix_attempts_cert_window
    ON cert_renewal_attempts (tenant_id, certificate_id, expiration_window_key);

-- Only required when exposing RenewalMode.ApprovalRequired.
CREATE TABLE IF NOT EXISTS cert_renewal_approvals (
    id                     varchar(36)  PRIMARY KEY,
    tenant_id              varchar(64)  NOT NULL,
    certificate_id         varchar(128) NOT NULL,
    expiration_window_key  varchar(32)  NOT NULL,
    status                 varchar(16)  NOT NULL DEFAULT 'Pending'
                           CHECK (status IN ('Pending', 'Approved', 'Rejected')),
    requested_by           varchar(256) NOT NULL DEFAULT 'scheduler',
    requested_at           timestamptz  NOT NULL,
    approved_by            varchar(256),
    approved_at            timestamptz,
    rejected_by            varchar(256),
    rejected_at            timestamptz,
    notes                  text,
    CONSTRAINT uq_approval_tenant_cert_window
        UNIQUE (tenant_id, certificate_id, expiration_window_key)
);
