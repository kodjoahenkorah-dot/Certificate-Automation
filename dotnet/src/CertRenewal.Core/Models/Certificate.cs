namespace CertRenewal.Core.Models;

/// <summary>
/// Engine-side view of one certificate row.
///
/// INTEGRATION POINT: populate this from the existing certificates table via
/// your ICertificateRepository implementation. Only Id, TenantId, Source and
/// ExpiresAt are required for the policy logic; the per-source blocks are
/// required by the matching provider.
/// </summary>
public sealed class Certificate
{
    public required string Id { get; init; }
    public required string TenantId { get; init; }
    /// <summary>e.g. "ci-grc-pfx" or "*.cleardhan.ai".</summary>
    public required string Name { get; init; }
    public required CertSource Source { get; init; }
    public required DateTimeOffset ExpiresAt { get; set; }

    public IReadOnlyList<string> Domains { get; init; } = [];
    public string? Thumbprint { get; set; }
    /// <summary>e.g. "GlobalSign GCC ...", "Let's Encrypt".</summary>
    public string? Issuer { get; init; }
    /// <summary>Null =&gt; "Unassigned" in the UI.</summary>
    public string? OwnerName { get; init; }
    public string? OwnerEmail { get; init; }

    // -- KeyVault source --
    /// <summary>https://&lt;vault&gt;.vault.azure.net</summary>
    public string? KeyVaultUrl { get; init; }
    public string? KeyVaultCertName { get; init; }

    // -- AppService source --
    public string? AzureSubscriptionId { get; init; }
    public string? AzureResourceGroup { get; init; }
    /// <summary>Microsoft.Web/certificates resource name.</summary>
    public string? AppServiceCertName { get; init; }

    /// <summary>Free-form extras (resource ids, tags, ...). Never read by the
    /// engine; passed through to notifications and Work Items for context.</summary>
    public IReadOnlyDictionary<string, string> Metadata { get; init; } =
        new Dictionary<string, string>();

    public double DaysToExpiry(DateTimeOffset now) => (ExpiresAt - now).TotalDays;

    public bool IsExpired(DateTimeOffset now) => DaysToExpiry(now) <= 0;

    /// <summary>
    /// Identifies one renewal cycle: the certificate's current expiry date.
    /// Approvals and fallback Work Items are deduplicated on
    /// (tenant, certificate, window key), so repeated sweeps within the same
    /// cycle can never create duplicates. A successful renewal changes the
    /// expiry and therefore starts a fresh window automatically.
    /// </summary>
    public string ExpirationWindowKey() => ExpiresAt.UtcDateTime.ToString("yyyy-MM-dd");
}
