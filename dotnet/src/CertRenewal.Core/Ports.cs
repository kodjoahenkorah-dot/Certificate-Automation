using CertRenewal.Core.Models;
using Microsoft.Extensions.Logging;

namespace CertRenewal.Core;

// ---------------------------------------------------------------------------
// Integration ports: notifications, Work Items, per-tenant credentials.
// ---------------------------------------------------------------------------

/// <summary>
/// INTEGRATION POINT: implement against the product's existing notification
/// system (email, in-app, Teams/Slack, ...). The engine calls exactly these
/// three hooks; each receives the certificate (with owner name/email) and the
/// full attempt record. Certs with no owner are still reported — route those
/// to a tenant-level default channel. LoggingNotifier is the safe default
/// used in dry-run rollouts.
/// </summary>
public interface INotifier
{
    Task RenewalSucceededAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default);

    /// <summary>Called on each failed attempt. attempt.AttemptNumber vs the
    /// policy's max attempts tells you whether retries remain.</summary>
    Task RenewalFailedAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default);

    /// <summary>Automation is not possible (or retries are exhausted) and a
    /// Work Item was created — attempt.WorkItemId references it.</summary>
    Task ManualActionRequiredAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default);
}

public sealed class LoggingNotifier(ILogger<LoggingNotifier> logger) : INotifier
{
    public Task RenewalSucceededAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default)
    {
        logger.LogInformation(
            "[tenant={Tenant}] Renewal succeeded for {Cert} (owner={Owner}) newExpiry={Expiry} dryRun={DryRun}",
            cert.TenantId, cert.Name, cert.OwnerEmail ?? "unassigned", attempt.NewExpiresAt, attempt.DryRun);
        return Task.CompletedTask;
    }

    public Task RenewalFailedAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default)
    {
        logger.LogWarning(
            "[tenant={Tenant}] Renewal attempt {N} failed for {Cert} (owner={Owner}): {Error} dryRun={DryRun}",
            cert.TenantId, attempt.AttemptNumber, cert.Name, cert.OwnerEmail ?? "unassigned",
            attempt.Error, attempt.DryRun);
        return Task.CompletedTask;
    }

    public Task ManualActionRequiredAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default)
    {
        logger.LogWarning(
            "[tenant={Tenant}] Manual renewal required for {Cert} (owner={Owner}) workItem={WorkItem}: {Detail}",
            cert.TenantId, cert.Name, cert.OwnerEmail ?? "unassigned", attempt.WorkItemId, attempt.Detail);
        return Task.CompletedTask;
    }
}

public sealed class WorkItemRequest
{
    public required string TenantId { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    /// <summary>Matches the product severity pills: "critical" or "high".</summary>
    public string Severity { get; init; } = "high";
    /// <summary>Cert owner; null =&gt; Unassigned.</summary>
    public string? AssigneeEmail { get; init; }
    public string? CertificateId { get; init; }
    /// <summary>"&lt;certificateId&gt;:&lt;expirationWindowKey&gt;". The engine already
    /// deduplicates via the audit log; implementations that upsert on this key
    /// get a second layer of protection (e.g. across data restores).</summary>
    public string? IdempotencyKey { get; init; }
    public IReadOnlyList<string> Labels { get; init; } = ["certificate-renewal"];
}

/// <summary>
/// INTEGRATION POINT: implement against the product's existing Work Items
/// feature. The manual-fallback provider calls CreateAsync when a certificate
/// cannot be renewed automatically (paid CA, missing DNS control, retries
/// exhausted). Return your Work Item's id so it can be stored on the audit
/// record and linked from the UI.
/// </summary>
public interface IWorkItemSink
{
    Task<string> CreateAsync(WorkItemRequest request, CancellationToken ct = default);
}

/// <summary>Default no-op sink: logs and returns a synthetic id. Replace before
/// going live so manual-renewal tasks reach the real Work Items queue.</summary>
public sealed class LoggingWorkItemSink(ILogger<LoggingWorkItemSink> logger) : IWorkItemSink
{
    /// <summary>Inspectable in tests/dev.</summary>
    public List<WorkItemRequest> Created { get; } = [];

    public Task<string> CreateAsync(WorkItemRequest request, CancellationToken ct = default)
    {
        Created.Add(request);
        var id = $"wi-{Guid.NewGuid().ToString()[..8]}";
        logger.LogInformation(
            "[tenant={Tenant}] Work Item {Id}: {Title} (assignee={Assignee})",
            request.TenantId, id, request.Title, request.AssigneeEmail ?? "unassigned");
        return Task.FromResult(id);
    }
}

public sealed class CredentialNotConfiguredException(string message) : Exception(message);

/// <summary>
/// INTEGRATION POINT: Clear Ops already holds per-tenant Azure credentials
/// for its scan jobs — implement this on top of that store. The engine never
/// caches credentials across tenants; it asks the resolver per attempt, keyed
/// by the certificate's own tenant id (which PolicyGuard.AssertTenantScope
/// has already validated). The return type is object to keep this assembly
/// free of Azure dependencies; the Azure providers cast it to
/// Azure.Core.TokenCredential.
/// </summary>
public interface ITenantCredentialResolver
{
    /// <summary>Return an Azure.Core.TokenCredential scoped to this tenant.
    /// Throw CredentialNotConfiguredException if none exists.</summary>
    Task<object> GetAzureCredentialAsync(string tenantId, CancellationToken ct = default);

    /// <summary>Default Azure subscription for management-plane calls when
    /// the certificate row doesn't carry one.</summary>
    Task<string?> GetAzureSubscriptionIdAsync(string tenantId, CancellationToken ct = default);

    /// <summary>Optional per-tenant ACME account key (PEM). Null =&gt; the ACME
    /// provider registers a fresh account (fine for Let's Encrypt).</summary>
    Task<byte[]?> GetAcmeAccountKeyPemAsync(string tenantId, CancellationToken ct = default) =>
        Task.FromResult<byte[]?>(null);
}

public static class ManualInstructions
{
    /// <summary>Issuer-aware renewal instructions used as the Work Item body —
    /// the same tone as the product's remediation texts on the Findings page.</summary>
    public static string Build(Certificate cert, DateTimeOffset now)
    {
        var days = cert.DaysToExpiry(now);
        var urgency = days <= 0
            ? $"This certificate EXPIRED {Math.Abs((int)days)} days ago."
            : $"This certificate expires in {(int)days} days.";

        var lines = new List<string>
        {
            $"Certificate: {cert.Name}",
            $"Domains: {(cert.Domains.Count > 0 ? string.Join(", ", cert.Domains) : "n/a")}",
            $"Thumbprint: {cert.Thumbprint ?? "n/a"}",
            $"Issuer: {cert.Issuer ?? "unknown"}",
            $"Expiry: {cert.ExpiresAt:yyyy-MM-dd} — {urgency}",
            "",
            "Automated renewal is not available for this certificate. Steps:",
        };

        switch (cert.Source)
        {
            case CertSource.KeyVault:
                lines.Add(
                    $"1. Renew in Key Vault: az keyvault certificate create --vault-name <vault> " +
                    $"--name {cert.KeyVaultCertName ?? cert.Name} --policy @policy.json " +
                    "(or merge a CSR signed by the CA).");
                break;
            case CertSource.AppService:
                lines.Add(
                    "1. Azure portal > App Service > Custom domains > Certificates, " +
                    "renew or re-import the certificate.");
                break;
            default:
                lines.Add($"1. Purchase/renew the certificate with {cert.Issuer ?? "the issuing CA"}.");
                lines.Add("2. Generate a CSR for the listed domains and complete the CA's validation flow.");
                lines.Add("3. Install the issued certificate on the serving endpoint(s) and update any Azure bindings.");
                break;
        }

        lines.Add(
            "Finally: re-run a scan (Scans > Run Full Scan) so Clear Ops picks up " +
            "the new expiry and closes the finding.");
        return string.Join("\n", lines);
    }
}
