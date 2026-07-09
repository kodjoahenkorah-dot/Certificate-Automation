using Xunit;

namespace CertRenewal.Core.Tests;

/// <summary>Multi-tenant safety: one tenant's job can never touch another's certs.</summary>
public class TenantScopingTests
{
    [Fact]
    public async Task CrossTenantRenewalRejected()
    {
        var h = new Harness();
        var certB = Harness.MakeCert("cert-b", tenantId: "tenant-b", daysToExpiry: 5);
        h.Certs.Add(certB);
        await h.OptInAsync(certB);
        // tenant-a's job asks for tenant-b's cert id
        await Assert.ThrowsAsync<TenantScopeException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-b"));
    }

    [Fact]
    public async Task CrossTenantForceRejected()
    {
        var h = new Harness();
        var certB = Harness.MakeCert("cert-b", tenantId: "tenant-b", daysToExpiry: 5);
        h.Certs.Add(certB);
        await h.OptInAsync(certB);
        await Assert.ThrowsAsync<TenantScopeException>(
            () => h.Engine.RenewCertificateAsync("tenant-a", "cert-b", force: true));
    }

    [Fact]
    public async Task SweepOnlyTouchesOwnTenant()
    {
        var h = new Harness();
        var certA = Harness.MakeCert("cert-a", tenantId: "tenant-a", daysToExpiry: 5);
        var certB = Harness.MakeCert("cert-b", tenantId: "tenant-b", daysToExpiry: 5);
        h.Certs.Add(certA);
        h.Certs.Add(certB);
        await h.OptInAsync(certA);
        await h.OptInAsync(certB);
        var results = await h.Engine.RunDueRenewalsAsync("tenant-a");
        Assert.Equal(["cert-a"], results.Select(a => a.CertificateId));
        Assert.All(results, a => Assert.Equal("tenant-a", a.TenantId));
    }

    [Fact]
    public async Task CredentialsResolvedFromCertificateTenant()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Equal(["tenant-a"], h.Credentials.RequestedTenants);
    }

    [Fact]
    public async Task ProviderContextCarriesCorrectTenant()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        var ctx = h.KeyVaultProvider.Calls.Single().Ctx;
        Assert.Equal("tenant-a", ctx.TenantId);
        Assert.Equal("credential-for-tenant-a", ctx.AzureCredential);
    }

    [Fact]
    public void PolicyCannotBeAttachedAcrossTenants()
    {
        var cert = Harness.MakeCert(tenantId: "tenant-a");
        var foreign = new Core.Models.RenewalPolicy { CertificateId = "cert-1", TenantId = "tenant-b" };
        Assert.Throws<TenantScopeException>(() =>
            PolicyGuard.EnableAutoRenewal(foreign, cert, "a@b.c", Harness.Now));
    }

    [Fact]
    public async Task AttemptHistoryIsTenantFiltered()
    {
        var h = new Harness();
        var cert = Harness.MakeCert(daysToExpiry: 5);
        h.Certs.Add(cert);
        await h.OptInAsync(cert);
        await h.Engine.RenewCertificateAsync("tenant-a", "cert-1");
        Assert.Empty(await h.Attempts.ListForCertificateAsync("tenant-b", "cert-1"));
    }
}
