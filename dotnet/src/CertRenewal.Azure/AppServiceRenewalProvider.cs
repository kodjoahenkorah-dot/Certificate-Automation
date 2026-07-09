using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.AppService;
using CertRenewal.Core.Models;
using CertRenewal.Core.Providers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertRenewal.Azure;

/// <summary>
/// Azure App Service certificate renewal provider.
///
/// Covers App Service *managed* certificates (the free certs Azure issues for
/// custom domains, resource type Microsoft.Web/certificates with a canonical
/// name). Renewal = re-PUT the certificate resource with the same properties;
/// Azure re-issues against the current domain validation. Uploaded/BYO
/// certificates in Microsoft.Web/certificates cannot be re-issued by Azure,
/// so they report ManualRequired (portal: App Service &gt; Custom domains &gt;
/// Certificates, as the product's remediation text already says).
///
/// Dry run: reads the certificate resource only.
/// </summary>
public sealed class AppServiceRenewalProvider(ILogger<AppServiceRenewalProvider>? logger = null)
    : IRenewalProvider
{
    private readonly ILogger _log = logger ?? NullLogger<AppServiceRenewalProvider>.Instance;

    private static ResourceIdentifier CertificateId(Certificate cert, string subscriptionId) =>
        AppCertificateResource.CreateResourceIdentifier(
            subscriptionId, cert.AzureResourceGroup!, cert.AppServiceCertName!);

    public async Task<RenewalResult> RenewAsync(
        Certificate cert, ProviderContext ctx, CancellationToken ct = default)
    {
        var missing = new List<string>();
        if (string.IsNullOrEmpty(cert.AzureResourceGroup)) missing.Add("AzureResourceGroup");
        if (string.IsNullOrEmpty(cert.AppServiceCertName)) missing.Add("AppServiceCertName");
        if (string.IsNullOrEmpty(ctx.AzureSubscriptionId)) missing.Add("AzureSubscriptionId");
        if (missing.Count > 0)
            return new RenewalResult
            {
                Status = AttemptStatus.Failed,
                Error = $"Certificate row is missing {string.Join(", ", missing)}; " +
                        "cannot target the App Service certificate resource.",
            };
        if (ctx.AzureCredential is not TokenCredential credential)
            return new RenewalResult
            {
                Status = AttemptStatus.Failed,
                Error = "No Azure credential resolved for this tenant.",
            };

        var arm = new ArmClient(credential);
        var resource = arm.GetAppCertificateResource(CertificateId(cert, ctx.AzureSubscriptionId!));
        var data = (await resource.GetAsync(ct)).Value.Data;

        // Managed certs carry a canonical name; uploaded PFX certs don't and
        // cannot be re-issued by Azure.
        var canonical = data.CanonicalName;
        if (string.IsNullOrEmpty(canonical))
            return new RenewalResult
            {
                Status = AttemptStatus.ManualRequired,
                Detail = $"App Service certificate '{cert.AppServiceCertName}' is an uploaded certificate, " +
                         "not an App Service managed certificate; Azure cannot re-issue it. Renew with the " +
                         "issuing CA and re-import via the portal (App Service > Custom domains > Certificates).",
            };

        if (ctx.DryRun)
            return new RenewalResult
            {
                Status = AttemptStatus.Succeeded,
                Detail = $"DRY RUN: would re-issue App Service managed certificate '{cert.AppServiceCertName}' " +
                         $"(canonical name {canonical}) in resource group '{cert.AzureResourceGroup}' of " +
                         $"subscription {ctx.AzureSubscriptionId} by re-submitting the certificate resource; " +
                         $"current expiry {data.ExpireOn}.",
            };

        var subscription = await arm.GetSubscriptionResource(
                new ResourceIdentifier($"/subscriptions/{ctx.AzureSubscriptionId}"))
            .GetAsync(ct);
        var resourceGroup = await subscription.Value
            .GetResourceGroupAsync(cert.AzureResourceGroup, ct);
        var operation = await resourceGroup.Value.GetAppCertificates()
            .CreateOrUpdateAsync(WaitUntil.Completed, cert.AppServiceCertName!, data, ct);

        var renewed = operation.Value.Data;
        _log.LogInformation("[tenant={Tenant}] App Service cert {Name} renewed; new expiry {Expiry}",
            ctx.TenantId, cert.AppServiceCertName, renewed.ExpireOn);
        return new RenewalResult
        {
            Status = AttemptStatus.Succeeded,
            NewExpiresAt = renewed.ExpireOn,
            NewThumbprint = renewed.ThumbprintString,
            Detail = $"Managed certificate re-issued for {canonical}.",
        };
    }

    /// <summary>Re-read the certificate resource and confirm Azure reports the
    /// new expiry before the engine records success.</summary>
    public async Task<string?> VerifyAsync(
        Certificate cert, RenewalResult result, ProviderContext ctx, CancellationToken ct = default)
    {
        var arm = new ArmClient((TokenCredential)ctx.AzureCredential!);
        var resource = arm.GetAppCertificateResource(CertificateId(cert, ctx.AzureSubscriptionId!));
        var data = (await resource.GetAsync(ct)).Value.Data;
        if (data.ExpireOn is null || data.ExpireOn <= cert.ExpiresAt)
            return $"Azure still reports expiry {data.ExpireOn} (previous expiry {cert.ExpiresAt}).";
        return null;
    }
}
