namespace CertRenewal.Core.Models;

/// <summary>
/// Per-certificate opt-in record. THE default is AutoRenewEnabled = false.
/// A certificate with no policy row at all is treated identically to one
/// with an explicitly disabled policy: it is never renewed.
/// </summary>
public sealed class RenewalPolicy
{
    public required string CertificateId { get; init; }
    public required string TenantId { get; init; }

    public bool AutoRenewEnabled { get; set; }
    public RenewalMode RenewalMode { get; set; } = RenewalMode.Automatic;

    /// <summary>User identity who opted in. Required by the opt-in gate.</summary>
    public string? EnabledBy { get; set; }
    public DateTimeOffset? EnabledAt { get; set; }
    public string? DisabledBy { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }

    /// <summary>Renew when expiry is within this many days.</summary>
    public int RenewalWindowDays { get; set; } = 30;

    /// <summary>Per-cert dry-run override. Null = inherit tenant/global setting.
    /// The effective value is dry-run if ANY level (global, tenant, policy)
    /// says dry-run — see PolicyGuard.EffectiveDryRun.</summary>
    public bool? DryRunOverride { get; set; }

    /// <summary>Null = use RenewalOptions.MaxAttempts.</summary>
    public int? MaxAttempts { get; set; }
    /// <summary>Null = use RenewalOptions.RetryInterval.</summary>
    public int? RetryIntervalMinutes { get; set; }

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
