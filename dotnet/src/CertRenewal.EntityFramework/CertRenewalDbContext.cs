using CertRenewal.Core.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CertRenewal.EntityFramework;

/// <summary>
/// Three new tables are introduced; the existing certificates table is NOT
/// duplicated here — implement ICertificateRepository against your existing
/// certificates model instead.
///
///   cert_renewal_policies    one row per opted-in certificate
///   cert_renewal_attempts    append-mostly audit log
///   cert_renewal_approvals   one human sign-off per cert per expiry window
///
/// Either merge these entity configurations into the existing DbContext or
/// run this context side-by-side on the same database. Generate a migration
/// with `dotnet ef migrations add CertRenewal --context CertRenewalDbContext`.
/// </summary>
public sealed class CertRenewalDbContext(DbContextOptions<CertRenewalDbContext> options)
    : DbContext(options)
{
    public DbSet<PolicyRow> Policies => Set<PolicyRow>();
    public DbSet<AttemptRow> Attempts => Set<AttemptRow>();
    public DbSet<ApprovalRow> Approvals => Set<ApprovalRow>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<PolicyRow>(e =>
        {
            e.ToTable("cert_renewal_policies");
            e.HasKey(p => p.Id);
            e.HasIndex(p => new { p.TenantId, p.CertificateId }).IsUnique();
            e.Property(p => p.RenewalMode).HasConversion<string>().HasMaxLength(32);
        });
        modelBuilder.Entity<AttemptRow>(e =>
        {
            e.ToTable("cert_renewal_attempts");
            e.HasKey(a => a.Id);
            e.HasIndex(a => new { a.TenantId, a.CertificateId, a.StartedAt });
            e.HasIndex(a => new { a.TenantId, a.CertificateId, a.ExpirationWindowKey });
            e.Property(a => a.Status).HasConversion<string>().HasMaxLength(32);
            e.Property(a => a.Method).HasConversion<string>().HasMaxLength(32);
        });
        modelBuilder.Entity<ApprovalRow>(e =>
        {
            e.ToTable("cert_renewal_approvals");
            e.HasKey(a => a.Id);
            e.HasIndex(a => new { a.TenantId, a.CertificateId, a.ExpirationWindowKey }).IsUnique();
            e.Property(a => a.Status).HasConversion<string>().HasMaxLength(16);
        });

        // SQLite (used in tests / local dev) cannot order by DateTimeOffset;
        // store as ticks there. SQL Server / PostgreSQL are unaffected.
        if (Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true)
        {
            foreach (var entity in modelBuilder.Model.GetEntityTypes())
            foreach (var property in entity.GetProperties())
            {
                // UtcTicks keeps ordering correct regardless of offset.
                if (property.ClrType == typeof(DateTimeOffset))
                    property.SetValueConverter(new ValueConverter<DateTimeOffset, long>(
                        v => v.UtcTicks,
                        v => new DateTimeOffset(v, TimeSpan.Zero)));
                else if (property.ClrType == typeof(DateTimeOffset?))
                    property.SetValueConverter(new ValueConverter<DateTimeOffset?, long?>(
                        v => v.HasValue ? v.Value.UtcTicks : null,
                        v => v.HasValue ? new DateTimeOffset(v.Value, TimeSpan.Zero) : null));
            }
        }
    }
}

public sealed class PolicyRow
{
    public long Id { get; set; }
    public required string TenantId { get; set; }
    public required string CertificateId { get; set; }
    public bool AutoRenewEnabled { get; set; }
    public RenewalMode RenewalMode { get; set; } = RenewalMode.Automatic;
    public string? EnabledBy { get; set; }
    public DateTimeOffset? EnabledAt { get; set; }
    public string? DisabledBy { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }
    public int RenewalWindowDays { get; set; } = 30;
    public bool? DryRunOverride { get; set; }
    public int? MaxAttempts { get; set; }
    public int? RetryIntervalMinutes { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public RenewalPolicy ToDomain() => new()
    {
        TenantId = TenantId,
        CertificateId = CertificateId,
        AutoRenewEnabled = AutoRenewEnabled,
        RenewalMode = RenewalMode,
        EnabledBy = EnabledBy,
        EnabledAt = EnabledAt,
        DisabledBy = DisabledBy,
        DisabledAt = DisabledAt,
        RenewalWindowDays = RenewalWindowDays,
        DryRunOverride = DryRunOverride,
        MaxAttempts = MaxAttempts,
        RetryIntervalMinutes = RetryIntervalMinutes,
        UpdatedAt = UpdatedAt,
    };

    public void Apply(RenewalPolicy p)
    {
        AutoRenewEnabled = p.AutoRenewEnabled;
        RenewalMode = p.RenewalMode;
        EnabledBy = p.EnabledBy;
        EnabledAt = p.EnabledAt;
        DisabledBy = p.DisabledBy;
        DisabledAt = p.DisabledAt;
        RenewalWindowDays = p.RenewalWindowDays;
        DryRunOverride = p.DryRunOverride;
        MaxAttempts = p.MaxAttempts;
        RetryIntervalMinutes = p.RetryIntervalMinutes;
        UpdatedAt = p.UpdatedAt;
    }
}

public sealed class AttemptRow
{
    public required string Id { get; set; }
    public required string TenantId { get; set; }
    public required string CertificateId { get; set; }
    public AttemptStatus Status { get; set; }
    public RenewalMethod? Method { get; set; }
    public bool DryRun { get; set; } = true;
    public int AttemptNumber { get; set; } = 1;
    public string? ExpirationWindowKey { get; set; }
    public string TriggeredBy { get; set; } = "scheduler";
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public DateTimeOffset? NewExpiresAt { get; set; }
    public string? NewThumbprint { get; set; }
    public string? Error { get; set; }
    public string? WorkItemId { get; set; }
    public string? Detail { get; set; }

    public static AttemptRow FromDomain(RenewalAttempt a) => new()
    {
        Id = a.Id,
        TenantId = a.TenantId,
        CertificateId = a.CertificateId,
        Status = a.Status,
        Method = a.Method,
        DryRun = a.DryRun,
        AttemptNumber = a.AttemptNumber,
        ExpirationWindowKey = a.ExpirationWindowKey,
        TriggeredBy = a.TriggeredBy,
        StartedAt = a.StartedAt,
        FinishedAt = a.FinishedAt,
        NewExpiresAt = a.NewExpiresAt,
        NewThumbprint = a.NewThumbprint,
        Error = a.Error,
        WorkItemId = a.WorkItemId,
        Detail = a.Detail,
    };

    public RenewalAttempt ToDomain() => new()
    {
        Id = Id,
        TenantId = TenantId,
        CertificateId = CertificateId,
        Status = Status,
        Method = Method,
        DryRun = DryRun,
        AttemptNumber = AttemptNumber,
        ExpirationWindowKey = ExpirationWindowKey,
        TriggeredBy = TriggeredBy,
        StartedAt = StartedAt,
        FinishedAt = FinishedAt,
        NewExpiresAt = NewExpiresAt,
        NewThumbprint = NewThumbprint,
        Error = Error,
        WorkItemId = WorkItemId,
        Detail = Detail,
    };
}

public sealed class ApprovalRow
{
    public required string Id { get; set; }
    public required string TenantId { get; set; }
    public required string CertificateId { get; set; }
    public required string ExpirationWindowKey { get; set; }
    public ApprovalStatus Status { get; set; } = ApprovalStatus.Pending;
    public string RequestedBy { get; set; } = "scheduler";
    public DateTimeOffset RequestedAt { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAt { get; set; }
    public string? RejectedBy { get; set; }
    public DateTimeOffset? RejectedAt { get; set; }
    public string? Notes { get; set; }

    public static ApprovalRow FromDomain(RenewalApproval a) => new()
    {
        Id = a.Id,
        TenantId = a.TenantId,
        CertificateId = a.CertificateId,
        ExpirationWindowKey = a.ExpirationWindowKey,
        Status = a.Status,
        RequestedBy = a.RequestedBy,
        RequestedAt = a.RequestedAt,
        ApprovedBy = a.ApprovedBy,
        ApprovedAt = a.ApprovedAt,
        RejectedBy = a.RejectedBy,
        RejectedAt = a.RejectedAt,
        Notes = a.Notes,
    };

    public RenewalApproval ToDomain() => new()
    {
        Id = Id,
        TenantId = TenantId,
        CertificateId = CertificateId,
        ExpirationWindowKey = ExpirationWindowKey,
        Status = Status,
        RequestedBy = RequestedBy,
        RequestedAt = RequestedAt,
        ApprovedBy = ApprovedBy,
        ApprovedAt = ApprovedAt,
        RejectedBy = RejectedBy,
        RejectedAt = RejectedAt,
        Notes = Notes,
    };

    public void Apply(RenewalApproval a)
    {
        Status = a.Status;
        RequestedBy = a.RequestedBy;
        RequestedAt = a.RequestedAt;
        ApprovedBy = a.ApprovedBy;
        ApprovedAt = a.ApprovedAt;
        RejectedBy = a.RejectedBy;
        RejectedAt = a.RejectedAt;
        Notes = a.Notes;
    }
}
