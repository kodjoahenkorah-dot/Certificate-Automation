using Azure.Identity;
using CertRenewal.Core;

namespace CertRenewal.Azure;

/// <summary>
/// Local-testing credential resolver: reads
/// CERT_RENEWAL_TENANT_&lt;ID&gt;_{TENANT,CLIENT_ID,CLIENT_SECRET,SUBSCRIPTION_ID}
/// where &lt;ID&gt; is the tenant id uppercased with non-alphanumerics replaced
/// by underscores, and builds a ClientSecretCredential.
///
/// INTEGRATION POINT: replace with an implementation backed by the store
/// Clear Ops already uses for per-tenant scan credentials.
/// </summary>
public sealed class EnvTenantCredentialResolver : ITenantCredentialResolver
{
    private static string Key(string tenantId, string suffix)
    {
        var safe = string.Concat(tenantId.Select(c => char.IsLetterOrDigit(c) ? char.ToUpperInvariant(c) : '_'));
        return $"CERT_RENEWAL_TENANT_{safe}_{suffix}";
    }

    public Task<object> GetAzureCredentialAsync(string tenantId, CancellationToken ct = default)
    {
        var tenant = Environment.GetEnvironmentVariable(Key(tenantId, "TENANT"));
        var clientId = Environment.GetEnvironmentVariable(Key(tenantId, "CLIENT_ID"));
        var secret = Environment.GetEnvironmentVariable(Key(tenantId, "CLIENT_SECRET"));
        if (string.IsNullOrEmpty(tenant) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(secret))
            throw new CredentialNotConfiguredException(
                $"No Azure credential configured for tenant '{tenantId}' " +
                $"(set {Key(tenantId, "TENANT")} / _CLIENT_ID / _CLIENT_SECRET).");
        return Task.FromResult<object>(new ClientSecretCredential(tenant, clientId, secret));
    }

    public Task<string?> GetAzureSubscriptionIdAsync(string tenantId, CancellationToken ct = default) =>
        Task.FromResult(Environment.GetEnvironmentVariable(Key(tenantId, "SUBSCRIPTION_ID")));
}
