using CertRenewal.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertRenewal.Core;

public sealed class SweepSummary
{
    public required string TenantId { get; init; }
    public int Attempted { get; set; }
    public int Succeeded { get; set; }
    public int Failed { get; set; }
    public int ManualRequired { get; set; }
    public int DryRun { get; set; }
    public List<RenewalAttempt> Attempts { get; init; } = [];
}

/// <summary>
/// Scheduler entry point.
///
/// INTEGRATION POINT: Clear Ops already runs per-tenant background scans (the
/// Scans page). Call RunTenantAsync(tenantId) from that same scheduler — after
/// a tenant's scan completes is the ideal hook, since certificate data is
/// freshest then. Alternatively run RunAllAsync on a fixed interval (e.g.
/// hourly, via a BackgroundService); every safety property (opt-in, window,
/// retry cooldown, dry-run, approvals) is enforced inside the engine, so
/// over-calling the job is harmless.
/// </summary>
public sealed class RenewalSweepJob(RenewalEngine engine, ILogger<RenewalSweepJob>? logger = null)
{
    private readonly ILogger _log = logger ?? NullLogger<RenewalSweepJob>.Instance;

    public async Task<SweepSummary> RunTenantAsync(string tenantId, CancellationToken ct = default)
    {
        var attempts = await engine.RunDueRenewalsAsync(tenantId, ct);
        var summary = new SweepSummary { TenantId = tenantId, Attempted = attempts.Count };
        summary.Attempts.AddRange(attempts);
        foreach (var a in attempts)
        {
            if (a.DryRun) summary.DryRun++;
            switch (a.Status)
            {
                case AttemptStatus.Succeeded: summary.Succeeded++; break;
                case AttemptStatus.ManualRequired: summary.ManualRequired++; break;
                case AttemptStatus.Failed: summary.Failed++; break;
            }
        }
        _log.LogInformation(
            "[tenant={Tenant}] Renewal sweep: {Attempted} attempted, {Succeeded} succeeded, " +
            "{Failed} failed, {Manual} manual, {DryRun} dry-run",
            tenantId, summary.Attempted, summary.Succeeded, summary.Failed,
            summary.ManualRequired, summary.DryRun);
        return summary;
    }

    /// <summary>Sweep several tenants sequentially, isolating failures per
    /// tenant — an exception for tenant A never affects tenant B.</summary>
    public async Task<IReadOnlyList<SweepSummary>> RunAllAsync(
        IEnumerable<string> tenantIds,
        Action<string, Exception>? onTenantError = null,
        CancellationToken ct = default)
    {
        var summaries = new List<SweepSummary>();
        foreach (var tenantId in tenantIds)
        {
            try
            {
                summaries.Add(await RunTenantAsync(tenantId, ct));
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "[tenant={Tenant}] Renewal sweep crashed", tenantId);
                onTenantError?.Invoke(tenantId, ex);
            }
        }
        return summaries;
    }
}
