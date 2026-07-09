using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using CertRenewal.Core;
using CertRenewal.Core.Models;
using CertRenewal.Core.Providers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertRenewal.Azure;

/// <summary>
/// Azure Key Vault renewal provider.
///
/// How renewal works: for a Key Vault certificate that has an issuer policy
/// ("Self" or an integrated CA like DigiCert/GlobalSign-via-KV),
/// StartCreateCertificateAsync with the certificate's existing policy re-runs
/// issuance — the SDK equivalent of the portal's "New Version" /
/// `az keyvault certificate renew`. Certificates that were *imported* into
/// Key Vault (issuer "Unknown") have no issuance pipeline, so the provider
/// reports ManualRequired and lets the engine's fallback create a Work Item.
///
/// Dry run: reads the certificate and its policy (read-only) and reports what
/// would happen; StartCreateCertificateAsync is never called.
/// </summary>
public sealed class KeyVaultRenewalProvider(ILogger<KeyVaultRenewalProvider>? logger = null)
    : IRenewalProvider
{
    private readonly ILogger _log = logger ?? NullLogger<KeyVaultRenewalProvider>.Instance;

    /// <summary>How long to wait for the CA to issue before reporting failure.
    /// Integrated CAs usually complete in seconds-to-minutes; "Self" is immediate.</summary>
    public TimeSpan IssuanceTimeout { get; init; } = TimeSpan.FromMinutes(10);

    public async Task<RenewalResult> RenewAsync(
        Certificate cert, ProviderContext ctx, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(cert.KeyVaultUrl) || string.IsNullOrEmpty(cert.KeyVaultCertName))
            return new RenewalResult
            {
                Status = AttemptStatus.Failed,
                Error = "Certificate row is missing KeyVaultUrl / KeyVaultCertName; cannot target the vault.",
            };
        if (ctx.AzureCredential is not TokenCredential credential)
            return new RenewalResult
            {
                Status = AttemptStatus.Failed,
                Error = "No Azure credential resolved for this tenant.",
            };

        var client = new CertificateClient(new Uri(cert.KeyVaultUrl), credential);
        var name = cert.KeyVaultCertName;

        var current = (await client.GetCertificateAsync(name, ct)).Value;
        var policy = (await client.GetCertificatePolicyAsync(name, ct)).Value;
        var issuer = policy.IssuerName;

        if (string.IsNullOrEmpty(issuer) || issuer.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            return new RenewalResult
            {
                Status = AttemptStatus.ManualRequired,
                Detail = $"Key Vault certificate '{name}' was imported (issuer policy 'Unknown'); " +
                         "Key Vault cannot re-issue it. A Work Item with manual renewal steps is required.",
            };

        if (ctx.DryRun)
            return new RenewalResult
            {
                Status = AttemptStatus.Succeeded,
                Detail = $"DRY RUN: would call StartCreateCertificateAsync('{name}') on {cert.KeyVaultUrl} " +
                         $"with its existing policy (issuer='{issuer}'), current version " +
                         $"{current.Properties.Version}, current expiry {current.Properties.ExpiresOn}.",
            };

        var operation = await client.StartCreateCertificateAsync(name, policy, cancellationToken: ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(IssuanceTimeout);
        var renewed = await operation.WaitForCompletionAsync(timeout.Token);

        var newExpiry = renewed.Value.Properties.ExpiresOn;
        var thumbprint = renewed.Value.Properties.X509Thumbprint is { } bytes
            ? Convert.ToHexString(bytes)
            : null;

        _log.LogInformation("[tenant={Tenant}] Key Vault cert {Name} renewed; new expiry {Expiry}",
            ctx.TenantId, name, newExpiry);
        return new RenewalResult
        {
            Status = AttemptStatus.Succeeded,
            NewExpiresAt = newExpiry,
            NewThumbprint = thumbprint,
            Detail = $"New version created in {cert.KeyVaultUrl} (issuer '{issuer}').",
        };
    }

    /// <summary>Re-read the current certificate version and confirm the vault
    /// really serves the new expiry before the engine records success.</summary>
    public async Task<string?> VerifyAsync(
        Certificate cert, RenewalResult result, ProviderContext ctx, CancellationToken ct = default)
    {
        var client = new CertificateClient(
            new Uri(cert.KeyVaultUrl!), (TokenCredential)ctx.AzureCredential!);
        var current = (await client.GetCertificateAsync(cert.KeyVaultCertName, ct)).Value;
        var expiresOn = current.Properties.ExpiresOn;
        if (expiresOn is null || expiresOn <= cert.ExpiresAt)
            return $"Vault still reports expiry {expiresOn} (previous expiry {cert.ExpiresAt}).";
        return null;
    }
}
