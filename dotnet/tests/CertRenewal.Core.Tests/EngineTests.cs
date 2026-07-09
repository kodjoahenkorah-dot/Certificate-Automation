using CertRenewal.Core.Models;
using Xunit;

namespace CertRenewal.Core.Tests;

public class OptInEnforcementTests
{
    [Fact]
    public async Task RenewalWithoutOptInIsRejected()
    {
        var h = new Harness();
        h.Certs.Add(Harness.MakeCert(daysToExpiry: 5));
        await Assert.ThrowsAsync<OptInRequiredException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-1"));
        Assert.Empty(h.KeyVaultProvider.Calls);
    }

    [Fact]
    public async Task ForceDoesNotBypassOptIn()
    {
        var h = new Harness();
        h.Certs.Add(Harness.MakeCert(daysToExpiry: 5));
        await Assert.ThrowsAsync<OptInRequiredException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-1", force: true));
        Assert.Empty(h.KeyVaultProvider.Calls);
    }

    [Fact]
    public async Task OptedInCertRenews()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.Succeeded, attempt.Status);
        Assert.Single(h.KeyVaultProvider.Calls);
    }

    [Fact]
    public async Task SweepSkipsNonOptedIn()
    {
        var h = new Harness();
        var opted = Harness.MakeCert("opted", daysToExpiry: 5);
        var notOpted = Harness.MakeCert("not-opted", daysToExpiry: 5);
        h.Certs.Add(opted);
        h.Certs.Add(notOpted);
        await h.OptInAsync(opted);
        var results = await h.Engine.RunDueRenewalsAsync("tenant-a");
        Assert.Equal(["opted"], results.Select(a => a.CertificateId));
    }
}

public class RenewalWindowAndSweepTests
{
    [Fact]
    public async Task OutsideWindowIsSkipped()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 183);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await Assert.ThrowsAsync<RenewalSkippedException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-1"));
        Assert.Empty(await h.Engine.RunDueRenewalsAsync("tenant-a"));
    }

    [Fact]
    public async Task ExpiredCertIsRenewed()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: -333);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var results = await h.Engine.RunDueRenewalsAsync("tenant-a");
        Assert.Single(results);
        Assert.Equal(AttemptStatus.Succeeded, results[0].Status);
    }

    [Fact]
    public async Task ForceBypassesWindowOnly()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 183);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1", force: true);
        Assert.Equal(AttemptStatus.Succeeded, attempt.Status);
    }

    [Fact]
    public async Task SweepBudgetLimitsAttempts()
    {
        var h = new Harness();
        h.Options.MaxRenewalsPerSweep = 1;
        for (var i = 0; i < 3; i++)
        {
            var cert = Harness.MakeCert($"c{i}", daysToExpiry: 5);
            h.Certs.Add(cert);
            await h.OptInAsync(cert);
        }
        Assert.Single(await h.Engine.RunDueRenewalsAsync("tenant-a"));
    }
}

public class DryRunTests
{
    [Fact]
    public async Task DryRunRecordsAttemptWithoutTouchingCertTable()
    {
        var h = new Harness();
        h.Options.DryRun = true;
        var cert = Harness.MakeCert(daysToExpiry: 5);
        var originalExpiry = cert.ExpiresAt;
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.True(attempt.DryRun);
        Assert.NotEmpty(await h.Attempts.ListForCertificateAsync("tenant-a", "cert-1"));
        Assert.Equal(originalExpiry, (await h.Certs.GetAsync("tenant-a", "cert-1"))!.ExpiresAt);
    }

    [Fact]
    public async Task DryRunFlagReachesProvider()
    {
        var h = new Harness();
        h.Options.DryRun = true;
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.True(h.KeyVaultProvider.Calls.Single().Ctx.DryRun);
    }

    [Fact]
    public async Task LiveRunUpdatesCertTable()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.False(attempt.DryRun);
        var updated = await h.Certs.GetAsync("tenant-a", "cert-1");
        Assert.Equal(attempt.NewExpiresAt, updated!.ExpiresAt);
        Assert.Equal("AA11BB22CC33", updated.Thumbprint);
    }

    [Fact]
    public async Task PolicyDryRunOverride()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        var policy = await h.OptInAsync(cert);
        policy.DryRunOverride = true;
        await h.Policies.SaveAsync(policy);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.True(attempt.DryRun);
    }

    [Fact]
    public async Task DryRunFailuresNeverCreateWorkItems()
    {
        var h = new Harness();
        h.Options.DryRun = true;
        h.Options.MaxAttempts = 1;
        h.KeyVaultProvider.Result = new RenewalResult { Status = AttemptStatus.Failed, Error = "boom" };
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.Failed, attempt.Status);
        Assert.Empty(h.WorkItems.Created);
    }
}

public class RetryAndFailureTests
{
    [Fact]
    public async Task ProviderExceptionBecomesFailedAttempt()
    {
        var h = new Harness();
        h.KeyVaultProvider.ThrowOnRenew = new InvalidOperationException("azure timeout");
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.Failed, attempt.Status);
        Assert.Contains("azure timeout", attempt.Error);
        Assert.Single(h.Notifier.Failed);
    }

    [Fact]
    public async Task CooldownBlocksImmediateRetry()
    {
        var h = new Harness();
        h.KeyVaultProvider.Result = new RenewalResult { Status = AttemptStatus.Failed, Error = "boom" };
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        await Assert.ThrowsAsync<RenewalSkippedException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-1"));
        h.Clock.Advance(TimeSpan.FromMinutes(61));
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(2, attempt.AttemptNumber);
    }

    [Fact]
    public async Task ExhaustedRetriesEscalateToWorkItem()
    {
        var h = new Harness();
        h.KeyVaultProvider.Result = new RenewalResult { Status = AttemptStatus.Failed, Error = "persistent failure" };
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        RenewalAttempt last = null!;
        for (var i = 0; i < 3; i++) // Options.MaxAttempts == 3
        {
            last = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
            h.Clock.Advance(TimeSpan.FromMinutes(61));
        }
        Assert.Equal(AttemptStatus.ManualRequired, last.Status);
        Assert.NotNull(last.WorkItemId);
        Assert.Single(h.WorkItems.Created);
        Assert.Equal("owner@anadata.com", h.WorkItems.Created[0].AssigneeEmail);
        Assert.Single(h.Notifier.Manual);
        // budget now exhausted
        await Assert.ThrowsAsync<RenewalSkippedException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-1"));
    }

    [Fact]
    public async Task SuccessResetsFailureStreak()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        h.KeyVaultProvider.Result = new RenewalResult { Status = AttemptStatus.Failed, Error = "boom" };
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        h.Clock.Advance(TimeSpan.FromMinutes(61));
        h.KeyVaultProvider.Result = new RenewalResult
        {
            Status = AttemptStatus.Succeeded,
            NewExpiresAt = Harness.Now.AddDays(365),
        };
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Empty(await h.Attempts.AttemptsSinceLastSuccessAsync("tenant-a", "cert-1"));
    }
}

public class NotificationTests
{
    [Fact]
    public async Task SuccessNotifiesOwner()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        var (notifiedCert, attempt) = Assert.Single(h.Notifier.Succeeded);
        Assert.Equal("owner@anadata.com", notifiedCert.OwnerEmail);
        Assert.Equal(AttemptStatus.Succeeded, attempt.Status);
    }

    [Fact]
    public async Task NotifierCrashDoesNotBreakRenewal()
    {
        var h = new Harness();
        h.Notifier.ThrowOnSuccess = new InvalidOperationException("smtp down");
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.Succeeded, attempt.Status);
        var saved = (await h.Attempts.ListForCertificateAsync("tenant-a", "cert-1")).Single();
        Assert.Equal(AttemptStatus.Succeeded, saved.Status);
    }
}

public class AuditTests
{
    [Fact]
    public async Task EveryAttemptIsRecorded()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1", "api:alice@anadata.com");
        var row = Assert.Single(await h.Attempts.ListForCertificateAsync("tenant-a", "cert-1"));
        Assert.Equal("api:alice@anadata.com", row.TriggeredBy);
        Assert.Equal(RenewalMethod.KeyVault, row.Method);
        Assert.Equal(Harness.Now, row.StartedAt);
        Assert.Equal(Harness.Now, row.FinishedAt);
        Assert.Equal("AA11BB22CC33", row.NewThumbprint);
    }
}

public class MethodSelectionTests
{
    [Fact]
    public void KeyVault() =>
        Assert.Equal(RenewalMethod.KeyVault, RenewalEngine.SelectMethod(Harness.MakeCert()));

    [Fact]
    public void AppService() =>
        Assert.Equal(RenewalMethod.AppService,
            RenewalEngine.SelectMethod(Harness.MakeCert(source: CertSource.AppService)));

    [Theory]
    [InlineData("Let's Encrypt R11")]
    [InlineData("ZeroSSL RSA CA")]
    public void ExternalAcmeIssuer(string issuer) =>
        Assert.Equal(RenewalMethod.Acme,
            RenewalEngine.SelectMethod(Harness.MakeCert(source: CertSource.External, issuer: issuer)));

    [Theory]
    [InlineData("GlobalSign GCC R3")]
    [InlineData("Sectigo Public Server")]
    [InlineData("Go Daddy Secure CA")]
    [InlineData("AlphaSSL CA - SHA256")]
    [InlineData("SSL2BUY EMEA")]
    [InlineData(null)]
    public void ExternalPaidCaGoesManual(string? issuer) =>
        Assert.Equal(RenewalMethod.Manual,
            RenewalEngine.SelectMethod(Harness.MakeCert(source: CertSource.External, issuer: issuer)));
}
