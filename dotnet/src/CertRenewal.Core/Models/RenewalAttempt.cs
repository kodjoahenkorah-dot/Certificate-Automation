namespace CertRenewal.Core.Models;

/// <summary>Audit-log row. One is written for every renewal attempt,
/// including dry runs and attempts resolved without touching a provider.</summary>
public sealed class RenewalAttempt
{
    public string Id { get; init; } = Guid.NewGuid().ToString();
    public required string TenantId { get; init; }
    public required string CertificateId { get; init; }

    public AttemptStatus Status { get; set; } = AttemptStatus.Pending;
    public RenewalMethod? Method { get; set; }
    public bool DryRun { get; set; } = true;
    /// <summary>1..MaxAttempts within a renewal cycle.</summary>
    public int AttemptNumber { get; set; } = 1;
    /// <summary>See Certificate.ExpirationWindowKey().</summary>
    public string? ExpirationWindowKey { get; set; }
    /// <summary>"scheduler", "api:&lt;user&gt;", or "approval:&lt;user&gt;".</summary>
    public string TriggeredBy { get; set; } = "scheduler";

    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedAt { get; set; }

    // Success outputs
    public DateTimeOffset? NewExpiresAt { get; set; }
    public string? NewThumbprint { get; set; }

    // Failure / manual outputs
    public string? Error { get; set; }
    /// <summary>Set when a fallback Work Item was created (or reused).</summary>
    public string? WorkItemId { get; set; }
    /// <summary>Human-readable narrative (especially for dry runs).</summary>
    public string? Detail { get; set; }
}

/// <summary>What a provider returns to the engine.</summary>
public sealed class RenewalResult
{
    public required AttemptStatus Status { get; init; }
    public DateTimeOffset? NewExpiresAt { get; init; }
    public string? NewThumbprint { get; init; }
    public string? Error { get; init; }
    public string? Detail { get; init; }
    public string? WorkItemId { get; init; }
}
