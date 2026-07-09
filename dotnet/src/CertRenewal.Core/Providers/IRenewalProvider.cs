using CertRenewal.Core.Models;

namespace CertRenewal.Core.Providers;

/// <summary>Everything a provider needs for one attempt. Tenant-specific
/// state always comes in here — providers must be stateless across calls
/// (the engine may reuse one instance across tenants).</summary>
public sealed class ProviderContext
{
    public required string TenantId { get; init; }
    public required bool DryRun { get; init; }
    public required RenewalOptions Options { get; init; }

    /// <summary>Azure.Core.TokenCredential for THIS tenant, resolved per
    /// attempt (typed as object to keep Core free of Azure references).</summary>
    public object? AzureCredential { get; init; }
    public string? AzureSubscriptionId { get; init; }
    public byte[]? AcmeAccountKeyPem { get; init; }
}

/// <summary>
/// A provider executes one renewal for one certificate and reports a
/// RenewalResult. Providers MUST honor ctx.DryRun: when it is true, no call
/// that mutates external state (Azure, ACME, DNS) may be made — describe what
/// would happen in RenewalResult.Detail instead. The engine additionally
/// verifies opt-in and tenant scope before a provider is ever invoked, so
/// providers can assume both.
/// </summary>
public interface IRenewalProvider
{
    Task<RenewalResult> RenewAsync(Certificate cert, ProviderContext ctx, CancellationToken ct = default);

    /// <summary>
    /// Post-renewal check, called by the engine after a live (non-dry-run)
    /// Succeeded result: re-read the renewed resource and confirm the new
    /// expiry actually took. Return null when verified, or an error string —
    /// the engine then records the attempt as Failed instead of trusting the
    /// RenewAsync result. Default: no verification.
    /// </summary>
    Task<string?> VerifyAsync(Certificate cert, RenewalResult result, ProviderContext ctx, CancellationToken ct = default) =>
        Task.FromResult<string?>(null);
}
