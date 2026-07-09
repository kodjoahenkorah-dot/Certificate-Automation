using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertRenewal.Acme;

/// <summary>
/// DNS-01 solver backed by Azure DNS. Requires DNS Zone Contributor on the
/// zone. Configure with a domain-suffix map: suffix ->
/// (subscriptionId, resourceGroup, zoneName); the longest matching suffix wins.
/// The credential must be an Azure.Core.TokenCredential for the tenant that
/// owns the zones.
/// </summary>
public sealed class AzureDnsChallengeSolver(
    TokenCredential credential,
    IReadOnlyDictionary<string, (string SubscriptionId, string ResourceGroup, string ZoneName)> zoneMap,
    ILogger<AzureDnsChallengeSolver>? logger = null) : IChallengeSolver
{
    private readonly ILogger _log = logger ?? NullLogger<AzureDnsChallengeSolver>.Instance;

    public string ChallengeType => "dns-01";

    private (string Suffix, (string Sub, string Rg, string Zone) Target) ZoneFor(string domain)
    {
        (string, (string, string, string))? best = null;
        foreach (var (suffix, target) in zoneMap)
        {
            if (domain == suffix || domain.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
            {
                if (best is null || suffix.Length > best.Value.Item1.Length)
                    best = (suffix, (target.SubscriptionId, target.ResourceGroup, target.ZoneName));
            }
        }
        return best ?? throw new KeyNotFoundException($"No Azure DNS zone configured for '{domain}'.");
    }

    private static string RecordName(string domain, string zoneSuffix)
    {
        var bare = domain.StartsWith("*.") ? domain[2..] : domain;
        var prefix = bare[..^zoneSuffix.Length].TrimEnd('.');
        return prefix.Length > 0 ? $"_acme-challenge.{prefix}" : "_acme-challenge";
    }

    private DnsZoneResource Zone(string sub, string rg, string zone) =>
        new ArmClient(credential).GetDnsZoneResource(
            DnsZoneResource.CreateResourceIdentifier(sub, rg, zone));

    public async Task SetupAsync(
        string domain, string token, string keyAuthorization, string dnsTxtValue,
        CancellationToken ct = default)
    {
        var (suffix, (sub, rg, zone)) = ZoneFor(domain);
        var records = Zone(sub, rg, zone).GetDnsTxtRecords();
        var data = new DnsTxtRecordData { TtlInSeconds = 60 };
        data.DnsTxtRecords.Add(new DnsTxtRecordInfo { Values = { dnsTxtValue } });
        await records.CreateOrUpdateAsync(WaitUntil.Completed, RecordName(domain, suffix), data, cancellationToken: ct);
        _log.LogInformation("Created _acme-challenge TXT for {Domain} in zone {Zone}", domain, zone);
    }

    public async Task CleanupAsync(string domain, string token, CancellationToken ct = default)
    {
        var (suffix, (sub, rg, zone)) = ZoneFor(domain);
        try
        {
            var record = await Zone(sub, rg, zone).GetDnsTxtRecordAsync(RecordName(domain, suffix), ct);
            await record.Value.DeleteAsync(WaitUntil.Completed, cancellationToken: ct);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // already gone
        }
    }
}
