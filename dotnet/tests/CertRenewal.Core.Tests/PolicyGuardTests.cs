using CertRenewal.Core.Models;
using Xunit;

namespace CertRenewal.Core.Tests;

public class OptInTests
{
    private static readonly DateTimeOffset Now = Harness.Now;

    [Fact]
    public void NoPolicyFailsClosed() =>
        Assert.Throws<OptInRequiredException>(() => PolicyGuard.AssertOptedIn(null));

    [Fact]
    public void DisabledPolicyFails()
    {
        var policy = new RenewalPolicy { CertificateId = "c", TenantId = "t" };
        Assert.False(policy.AutoRenewEnabled); // the default is OFF
        Assert.Throws<OptInRequiredException>(() => PolicyGuard.AssertOptedIn(policy));
    }

    [Fact]
    public void EnabledWithoutActorFails()
    {
        // A policy flipped on without going through EnableAutoRenewal
        // (no recorded actor) is rejected.
        var policy = new RenewalPolicy { CertificateId = "c", TenantId = "t", AutoRenewEnabled = true };
        Assert.Throws<OptInRequiredException>(() => PolicyGuard.AssertOptedIn(policy));
    }

    [Fact]
    public void EnableRecordsActorAndTimestamp()
    {
        var cert = Harness.MakeCert();
        var policy = PolicyGuard.EnableAutoRenewal(null, cert, "alice@anadata.com", Now);
        Assert.True(policy.AutoRenewEnabled);
        Assert.Equal("alice@anadata.com", policy.EnabledBy);
        Assert.Equal(Now, policy.EnabledAt);
        PolicyGuard.AssertOptedIn(policy); // passes the gate
    }

    [Fact]
    public void EnableRequiresActor() =>
        Assert.Throws<ArgumentException>(() =>
            PolicyGuard.EnableAutoRenewal(null, Harness.MakeCert(), "  ", Now));

    [Fact]
    public void DisableRecordsActor()
    {
        var cert = Harness.MakeCert();
        var policy = PolicyGuard.EnableAutoRenewal(null, cert, "alice@anadata.com", Now);
        PolicyGuard.DisableAutoRenewal(policy, "bob@anadata.com", Now);
        Assert.False(policy.AutoRenewEnabled);
        Assert.Equal("bob@anadata.com", policy.DisabledBy);
        Assert.Throws<OptInRequiredException>(() => PolicyGuard.AssertOptedIn(policy));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(400)]
    public void EnableWindowBounds(int window) =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PolicyGuard.EnableAutoRenewal(null, Harness.MakeCert(), "a@b.c", Now, window));
}

public class RenewalWindowTests
{
    private static readonly DateTimeOffset Now = Harness.Now;

    private static RenewalPolicy Policy(Certificate cert, int window = 30) =>
        PolicyGuard.EnableAutoRenewal(null, cert, "a@b.c", Now, window);

    [Theory]
    [InlineData(10, true)]     // inside window
    [InlineData(183, false)]   // outside window
    [InlineData(-333, true)]   // expired certs are inside the window
    [InlineData(30, true)]     // boundary: exactly window days
    public void WindowMath(double daysToExpiry, bool expected)
    {
        var cert = Harness.MakeCert(daysToExpiry: daysToExpiry);
        Assert.Equal(expected, PolicyGuard.InRenewalWindow(cert, Policy(cert), Now));
    }

    [Fact]
    public void CustomWindow()
    {
        var cert = Harness.MakeCert(daysToExpiry: 50);
        Assert.False(PolicyGuard.InRenewalWindow(cert, Policy(cert, 30), Now));
        Assert.True(PolicyGuard.InRenewalWindow(cert, Policy(cert, 60), Now));
    }

    [Fact]
    public void ShouldRenewRequiresOptInAndWindow()
    {
        var cert = Harness.MakeCert(daysToExpiry: 10);
        Assert.False(PolicyGuard.ShouldRenew(cert, null, Now));
        Assert.True(PolicyGuard.ShouldRenew(cert, Policy(cert), Now));

        var far = Harness.MakeCert("cert-far", daysToExpiry: 200);
        Assert.False(PolicyGuard.ShouldRenew(far, Policy(far), Now));
    }

    [Fact]
    public void ShouldRenewRejectsMismatchedPolicy()
    {
        var cert = Harness.MakeCert(daysToExpiry: 5);
        var other = Harness.MakeCert("other-cert", daysToExpiry: 5);
        Assert.False(PolicyGuard.ShouldRenew(cert, Policy(other), Now));
    }
}

public class EffectiveDryRunTests
{
    [Fact]
    public void GlobalDefaultIsDryRun()
    {
        Assert.True(new RenewalOptions().DryRun);
        Assert.True(PolicyGuard.EffectiveDryRun(new RenewalOptions(), null, "t"));
    }

    [Fact]
    public void GlobalDryRunWinsOverPolicyOverride()
    {
        var policy = new RenewalPolicy { CertificateId = "c", TenantId = "t", DryRunOverride = false };
        Assert.True(PolicyGuard.EffectiveDryRun(new RenewalOptions { DryRun = true }, policy, "t"));
    }

    [Fact]
    public void TenantDryRunWins()
    {
        var options = new RenewalOptions { DryRun = false, DryRunTenants = ["t"] };
        var policy = new RenewalPolicy { CertificateId = "c", TenantId = "t", DryRunOverride = false };
        Assert.True(PolicyGuard.EffectiveDryRun(options, policy, "t"));
        Assert.False(PolicyGuard.EffectiveDryRun(options, policy, "other"));
    }

    [Fact]
    public void PolicyOverrideKeepsDryRunOn()
    {
        var options = new RenewalOptions { DryRun = false };
        var policy = new RenewalPolicy { CertificateId = "c", TenantId = "t", DryRunOverride = true };
        Assert.True(PolicyGuard.EffectiveDryRun(options, policy, "t"));
    }

    [Fact]
    public void LiveWhenAllLevelsAllow() =>
        Assert.False(PolicyGuard.EffectiveDryRun(new RenewalOptions { DryRun = false }, null, "t"));
}

public class RetryBudgetTests
{
    private static readonly DateTimeOffset Now = Harness.Now;

    private static RenewalAttempt Failed(int minutesAgo, int n) => new()
    {
        TenantId = "t",
        CertificateId = "c",
        Status = AttemptStatus.Failed,
        DryRun = false,
        AttemptNumber = n,
        StartedAt = Now.AddMinutes(-minutesAgo),
        FinishedAt = Now.AddMinutes(-minutesAgo),
    };

    [Fact]
    public void FirstAttemptAllowed() =>
        Assert.Equal((true, 1), PolicyGuard.RetryAllowed([], 3, TimeSpan.FromHours(1), Now));

    [Fact]
    public void CooldownBlocks() =>
        Assert.Equal((false, 2), PolicyGuard.RetryAllowed([Failed(10, 1)], 3, TimeSpan.FromHours(1), Now));

    [Fact]
    public void AfterCooldownAllowed() =>
        Assert.Equal((true, 2), PolicyGuard.RetryAllowed([Failed(90, 1)], 3, TimeSpan.FromHours(1), Now));

    [Fact]
    public void MaxAttemptsExhausted()
    {
        var streak = new[] { Failed(300, 1), Failed(200, 2), Failed(100, 3) };
        var (allowed, _) = PolicyGuard.RetryAllowed(streak, 3, TimeSpan.FromHours(1), Now);
        Assert.False(allowed);
    }
}
