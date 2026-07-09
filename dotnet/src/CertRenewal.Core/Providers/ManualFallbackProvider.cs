using CertRenewal.Core.Models;

namespace CertRenewal.Core.Providers;

/// <summary>
/// Handles every certificate that cannot be renewed automatically — paid-CA
/// external certs (GlobalSign, Sectigo, GoDaddy, AlphaSSL, SSL2BUY, ...) and
/// anything the other providers hand back as ManualRequired at the engine
/// level. It creates a Work Item assigned to the certificate owner with
/// issuer-specific renewal instructions and reports ManualRequired so the
/// attempt is not retried as if it were a transient failure.
///
/// Dry run: no Work Item is created; the result describes the one that would be.
/// </summary>
public sealed class ManualFallbackProvider(IWorkItemSink workItems, TimeProvider? timeProvider = null)
    : IRenewalProvider
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public async Task<RenewalResult> RenewAsync(Certificate cert, ProviderContext ctx, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var instructions = ManualInstructions.Build(cert, now);
        var title = $"Renew certificate {cert.Name}";
        var severity = cert.IsExpired(now) ? "critical" : "high";

        if (ctx.DryRun)
        {
            return new RenewalResult
            {
                Status = AttemptStatus.ManualRequired,
                Detail = $"DRY RUN: would create a {severity} Work Item '{title}' assigned to " +
                         $"{cert.OwnerEmail ?? "Unassigned"} with these instructions:\n{instructions}",
            };
        }

        var workItemId = await workItems.CreateAsync(new WorkItemRequest
        {
            TenantId = cert.TenantId,
            Title = title,
            Description = instructions,
            Severity = severity,
            AssigneeEmail = cert.OwnerEmail,
            CertificateId = cert.Id,
            IdempotencyKey = $"{cert.Id}:{cert.ExpirationWindowKey()}",
        }, ct);

        return new RenewalResult
        {
            Status = AttemptStatus.ManualRequired,
            WorkItemId = workItemId,
            Detail = $"Automated renewal is not available for issuer '{cert.Issuer ?? "unknown"}'. " +
                     $"Work Item {workItemId} created for {cert.OwnerEmail ?? "Unassigned"}.",
        };
    }
}
