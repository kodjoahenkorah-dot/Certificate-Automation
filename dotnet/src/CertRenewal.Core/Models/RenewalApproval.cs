namespace CertRenewal.Core.Models;

/// <summary>One human sign-off per certificate per expiry window, used when
/// the policy's RenewalMode is ApprovalRequired.</summary>
public sealed class RenewalApproval
{
    public string Id { get; init; } = Guid.NewGuid().ToString();
    public required string TenantId { get; init; }
    public required string CertificateId { get; init; }
    public required string ExpirationWindowKey { get; init; }

    public ApprovalStatus Status { get; set; } = ApprovalStatus.Pending;
    public string RequestedBy { get; set; } = "scheduler";
    public DateTimeOffset RequestedAt { get; set; } = DateTimeOffset.UtcNow;
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAt { get; set; }
    public string? RejectedBy { get; set; }
    public DateTimeOffset? RejectedAt { get; set; }
    public string? Notes { get; set; }
}
