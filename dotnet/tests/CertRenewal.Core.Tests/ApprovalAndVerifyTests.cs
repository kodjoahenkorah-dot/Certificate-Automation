using CertRenewal.Core.Models;
using Xunit;

namespace CertRenewal.Core.Tests;

public class ApprovalRequiredModeTests
{
    private static async Task<(Harness H, Certificate Cert)> SetupAsync()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert, mode: RenewalMode.ApprovalRequired);
        return (h, cert);
    }

    [Fact]
    public async Task SweepCreatesPendingApprovalAndDoesNotRenew()
    {
        var (h, cert) = await SetupAsync();
        Assert.Empty(await h.Engine.RunDueRenewalsAsync("tenant-a"));
        Assert.Empty(h.KeyVaultProvider.Calls);
        var pending = Assert.Single(await h.Approvals.ListPendingForTenantAsync("tenant-a"));
        Assert.Equal("cert-1", pending.CertificateId);
        Assert.Equal(cert.ExpirationWindowKey(), pending.ExpirationWindowKey);
    }

    [Fact]
    public async Task RepeatedSweepsDoNotDuplicateApprovals()
    {
        var (h, _) = await SetupAsync();
        await h.Engine.RunDueRenewalsAsync("tenant-a");
        await h.Engine.RunDueRenewalsAsync("tenant-a");
        await h.Engine.RunDueRenewalsAsync("tenant-a");
        Assert.Single(await h.Approvals.ListPendingForTenantAsync("tenant-a"));
    }

    [Fact]
    public async Task ApproveRunsRenewal()
    {
        var (h, _) = await SetupAsync();
        await h.Engine.RunDueRenewalsAsync("tenant-a");
        var approval = (await h.Approvals.ListPendingForTenantAsync("tenant-a")).Single();
        var attempt = await h.Engine.ApproveRenewalAsync("tenant-a", approval.Id, "boss@anadata.com");
        Assert.Equal(AttemptStatus.Succeeded, attempt.Status);
        Assert.Equal("approval:boss@anadata.com", attempt.TriggeredBy);
        var stored = await h.Approvals.GetAsync("tenant-a", approval.Id);
        Assert.Equal(ApprovalStatus.Approved, stored!.Status);
        Assert.Equal("boss@anadata.com", stored.ApprovedBy);
        Assert.Single(h.KeyVaultProvider.Calls);
    }

    [Fact]
    public async Task RejectBlocksRenewalForTheWindow()
    {
        var (h, _) = await SetupAsync();
        await h.Engine.RunDueRenewalsAsync("tenant-a");
        var approval = (await h.Approvals.ListPendingForTenantAsync("tenant-a")).Single();
        var rejected = await h.Engine.RejectRenewalAsync("tenant-a", approval.Id, "boss@anadata.com", "not now");
        Assert.Equal(ApprovalStatus.Rejected, rejected.Status);
        // subsequent sweeps neither renew nor recreate the approval
        Assert.Empty(await h.Engine.RunDueRenewalsAsync("tenant-a"));
        Assert.Empty(h.KeyVaultProvider.Calls);
        Assert.Empty(await h.Approvals.ListPendingForTenantAsync("tenant-a"));
    }

    [Fact]
    public async Task DirectRenewalThrowsApprovalPending()
    {
        var (h, _) = await SetupAsync();
        await Assert.ThrowsAsync<ApprovalPendingException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-1"));
    }

    [Fact]
    public async Task ForceDoesNotBypassApproval()
    {
        var (h, _) = await SetupAsync();
        await Assert.ThrowsAsync<ApprovalPendingException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-1", force: true));
    }

    [Fact]
    public async Task ApprovalIsTenantScoped()
    {
        var (h, _) = await SetupAsync();
        await h.Engine.RunDueRenewalsAsync("tenant-a");
        var approval = (await h.Approvals.ListPendingForTenantAsync("tenant-a")).Single();
        await Assert.ThrowsAsync<TenantScopeException>(
            () => h.Engine.ApproveRenewalAsync("tenant-b", approval.Id, "evil@b.com"));
    }

    [Fact]
    public async Task DoubleApproveIsRejected()
    {
        var (h, _) = await SetupAsync();
        await h.Engine.RunDueRenewalsAsync("tenant-a");
        var approval = (await h.Approvals.ListPendingForTenantAsync("tenant-a")).Single();
        await h.Engine.ApproveRenewalAsync("tenant-a", approval.Id, "boss@anadata.com");
        await Assert.ThrowsAsync<RenewalSkippedException>(
            () => h.Engine.ApproveRenewalAsync("tenant-a", approval.Id, "boss@anadata.com"));
    }
}

public class VerifyTests
{
    [Fact]
    public async Task VerifyFailureTurnsSuccessIntoFailed()
    {
        var h = new Harness();
        h.KeyVaultProvider.VerifyError = "vault still reports old expiry";
        var cert = Harness.MakeCert(daysToExpiry: 5);
        var originalExpiry = cert.ExpiresAt;
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.Failed, attempt.Status);
        Assert.Contains("verification failed", attempt.Error);
        Assert.Empty(h.Notifier.Succeeded);
        Assert.Single(h.Notifier.Failed);
        // cert table must NOT be updated with the unverified expiry
        Assert.Equal(originalExpiry, (await h.Certs.GetAsync("tenant-a", "cert-1"))!.ExpiresAt);
    }

    [Fact]
    public async Task VerifyPassRecordsSuccess()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        var attempt = await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(AttemptStatus.Succeeded, attempt.Status);
        Assert.Equal(1, h.KeyVaultProvider.VerifyCalls);
    }

    [Fact]
    public async Task DryRunSkipsVerify()
    {
        var h = new Harness();
        h.Options.DryRun = true;
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(0, h.KeyVaultProvider.VerifyCalls);
    }
}
