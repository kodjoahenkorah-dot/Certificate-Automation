using CertRenewal.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CertRenewal.Api;

/// <summary>
/// INTEGRATION POINT: supplies the tenant ids the sweep should cover — back
/// this with the same tenant registry the scan scheduler uses.
/// </summary>
public interface ITenantSource
{
    Task<IReadOnlyList<string>> GetTenantIdsAsync(CancellationToken ct = default);
}

/// <summary>
/// Optional standalone scheduler: runs the renewal sweep for every tenant on
/// a fixed interval (default hourly). If Clear Ops prefers to trigger the
/// sweep from its existing scan pipeline instead (recommended — cert data is
/// freshest right after a scan), skip this service and call
/// RenewalSweepJob.RunTenantAsync from that pipeline.
/// </summary>
public sealed class RenewalSweepHostedService(
    RenewalSweepJob job,
    ITenantSource tenants,
    ILogger<RenewalSweepHostedService> logger,
    TimeSpan? interval = null) : BackgroundService
{
    private readonly TimeSpan _interval = interval ?? TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_interval);
        do
        {
            try
            {
                var tenantIds = await tenants.GetTenantIdsAsync(stoppingToken);
                await job.RunAllAsync(tenantIds, ct: stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Renewal sweep cycle failed; will retry next interval");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
