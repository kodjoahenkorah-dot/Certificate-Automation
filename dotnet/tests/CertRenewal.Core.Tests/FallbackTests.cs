using CertRenewal.Core.Models;
using Xunit;

namespace CertRenewal.Core.Tests;

/// <summary>Manual fallback: paid-CA external certs become owner-assigned Work Items.</summary>
public class FallbackTests
{
    private static Certificate ExternalCert(double daysToExpiry, string? ownerEmail = "owner@anadata.com") =>
        Harness.MakeCert(
            source: CertSource.External,
            issuer: "GlobalSign GCC R3 DV TLS CA 2020",
            daysToExpiry: daysToExpiry,
            ownerEmail: ownerEmail);

    [Fact]
    public async Task PaidCaCreatesWorkItem()
    {
        var h = new Harness();
        var cert = ExternalCert(5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.ManualRequired, attempt.Status);
        Assert.NotNull(attempt.WorkItemId);
        var wi = Assert.Single(h.WorkItems.Created);
        Assert.Equal("tenant-a", wi.TenantId);
        Assert.Equal("owner@anadata.com", wi.AssigneeEmail);
        Assert.Contains("GlobalSign", wi.Description);
        Assert.Contains(cert.Name, wi.Title);
        Assert.Single(h.Notifier.Manual);
    }

    [Fact]
    public async Task ExpiredCertWorkItemIsCritical()
    {
        var h = new Harness();
        var cert = ExternalCert(-40);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal("critical", h.WorkItems.Created[0].Severity);
    }

    [Fact]
    public async Task ExpiringCertWorkItemIsHigh()
    {
        var h = new Harness();
        var cert = ExternalCert(10);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal("high", h.WorkItems.Created[0].Severity);
    }

    [Fact]
    public async Task UnassignedOwnerCreatesUnassignedWorkItem()
    {
        var h = new Harness();
        var cert = ExternalCert(5, ownerEmail: null);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.ManualRequired, attempt.Status);
        Assert.Null(h.WorkItems.Created[0].AssigneeEmail);
    }

    [Fact]
    public async Task DryRunDescribesWorkItemWithoutCreating()
    {
        var h = new Harness();
        h.Options.DryRun = true;
        var cert = ExternalCert(5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.ManualRequired, attempt.Status);
        Assert.Null(attempt.WorkItemId);
        Assert.Empty(h.WorkItems.Created);
        Assert.Contains("DRY RUN", attempt.Detail);
    }

    [Fact]
    public async Task ManualRequiredIsNotRetriedAsFailure()
    {
        // ManualRequired counts against the failure streak, so the sweep
        // does not re-create Work Items every hour.
        var h = new Harness();
        var cert = ExternalCert(5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        h.Clock.Advance(TimeSpan.FromMinutes(30));
        Assert.Empty(await h.Engine.RunDueRenewalsAsync("tenant-a")); // cooldown holds
    }

    [Fact]
    public async Task SameWindowReusesWorkItem()
    {
        var h = new Harness();
        var cert = ExternalCert(5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var first = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        h.Clock.Advance(TimeSpan.FromHours(25)); // well past any cooldown
        var second = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1", force: true);
        Assert.NotNull(first.WorkItemId);
        Assert.Equal(first.WorkItemId, second.WorkItemId);
        Assert.Single(h.WorkItems.Created);
        Assert.Contains("already open", second.Detail);
    }

    [Fact]
    public async Task WorkItemRequestCarriesIdempotencyKey()
    {
        var h = new Harness();
        var cert = ExternalCert(5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal($"cert-1:{cert.ExpirationWindowKey()}", h.WorkItems.Created[0].IdempotencyKey);
    }

    [Fact]
    public async Task RetryExhaustionReusesExistingWorkItem()
    {
        // If a Work Item already exists for this window, exhausting retries
        // must not create a second one.
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Attempts.SaveAsync(new RenewalAttempt
        {
            TenantId = "tenant-a",
            CertificateId = "cert-1",
            Status = AttemptStatus.ManualRequired,
            DryRun = false,
            ExpirationWindowKey = cert.ExpirationWindowKey(),
            WorkItemId = "wi-existing",
            StartedAt = Harness.Now,
            FinishedAt = Harness.Now,
        });
        h.KeyVaultProvider.Result = new RenewalResult { Status = AttemptStatus.Failed, Error = "boom" };
        RenewalAttempt last = null!;
        for (var i = 0; i < 3; i++)
        {
            h.Clock.Advance(TimeSpan.FromMinutes(61));
            last = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1", force: true);
        }
        Assert.Equal(AttemptStatus.ManualRequired, last.Status);
        Assert.Equal("wi-existing", last.WorkItemId);
        Assert.Empty(h.WorkItems.Created);
    }
}
