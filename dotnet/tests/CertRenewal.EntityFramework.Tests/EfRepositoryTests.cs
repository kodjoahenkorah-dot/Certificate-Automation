using CertRenewal.Core.Models;
using CertRenewal.EntityFramework;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CertRenewal.EntityFramework.Tests;

/// <summary>
/// Smoke tests against a real (in-memory SQLite) database: prove that every
/// entity materializes, every repository method round-trips, and the
/// window/streak queries behave — the class of bug that only shows up when a
/// live DbContext executes the model.
/// </summary>
public sealed class EfRepositoryTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 7, 8, 12, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;
    private readonly IDbContextFactory<CertRenewalDbContext> _factory;

    public EfRepositoryTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        var options = new DbContextOptionsBuilder<CertRenewalDbContext>()
            .UseSqlite(_connection)
            .Options;
        using (var db = new CertRenewalDbContext(options))
        {
            db.Database.EnsureCreated();
        }
        _factory = new FixedFactory(options);
    }

    public void Dispose() => _connection.Dispose();

    private sealed class FixedFactory(DbContextOptions<CertRenewalDbContext> options)
        : IDbContextFactory<CertRenewalDbContext>
    {
        public CertRenewalDbContext CreateDbContext() => new(options);
    }

    [Fact]
    public async Task PolicyRoundTripsIncludingModeAndOverrides()
    {
        var repo = new EfPolicyRepository(_factory);
        var policy = new RenewalPolicy
        {
            TenantId = "t1",
            CertificateId = "c1",
            AutoRenewEnabled = true,
            RenewalMode = RenewalMode.ApprovalRequired,
            EnabledBy = "alice@anadata.com",
            EnabledAt = Now,
            RenewalWindowDays = 45,
            DryRunOverride = true,
            MaxAttempts = 5,
            RetryIntervalMinutes = 120,
            UpdatedAt = Now,
        };
        await repo.SaveAsync(policy);

        var loaded = await repo.GetAsync("t1", "c1");
        Assert.NotNull(loaded);
        Assert.Equal(RenewalMode.ApprovalRequired, loaded!.RenewalMode);
        Assert.Equal("alice@anadata.com", loaded.EnabledBy);
        Assert.Equal(45, loaded.RenewalWindowDays);
        Assert.True(loaded.DryRunOverride);
        Assert.Equal(5, loaded.MaxAttempts);

        // update path (existing row)
        loaded.AutoRenewEnabled = false;
        loaded.DisabledBy = "bob@anadata.com";
        loaded.DisabledAt = Now.AddHours(1);
        await repo.SaveAsync(loaded);
        var reloaded = await repo.GetAsync("t1", "c1");
        Assert.False(reloaded!.AutoRenewEnabled);
        Assert.Equal("bob@anadata.com", reloaded.DisabledBy);

        Assert.Null(await repo.GetAsync("t2", "c1")); // tenant filtered
    }

    [Fact]
    public async Task ListEnabledForTenantFiltersByTenantAndFlag()
    {
        var repo = new EfPolicyRepository(_factory);
        await repo.SaveAsync(Enabled("t1", "c1"));
        var disabled = Enabled("t1", "c2");
        disabled.AutoRenewEnabled = false;
        await repo.SaveAsync(disabled);
        await repo.SaveAsync(Enabled("t2", "c3"));

        var rows = await repo.ListEnabledForTenantAsync("t1");
        Assert.Equal(["c1"], rows.Select(r => r.CertificateId));
    }

    [Fact]
    public async Task AttemptRoundTripsAndStreakAndWindowQueriesWork()
    {
        var repo = new EfAttemptRepository(_factory);

        var first = MakeAttempt("a1", AttemptStatus.Failed, minutesAgo: 300);
        await repo.SaveAsync(first);
        await repo.SaveAsync(MakeAttempt("a2", AttemptStatus.Succeeded, minutesAgo: 200));
        await repo.SaveAsync(MakeAttempt("a3", AttemptStatus.Failed, minutesAgo: 100));
        await repo.SaveAsync(MakeAttempt("a4", AttemptStatus.ManualRequired, minutesAgo: 50,
            workItemId: "wi-9", windowKey: "2026-07-13"));
        await repo.SaveAsync(MakeAttempt("a5", AttemptStatus.Failed, minutesAgo: 25, dryRun: true));

        var recent = await repo.ListForCertificateAsync("t1", "c1", limit: 3);
        Assert.Equal(["a5", "a4", "a3"], recent.Select(a => a.Id)); // newest first

        // streak = terminal non-dry-run attempts after the last success
        var streak = await repo.AttemptsSinceLastSuccessAsync("t1", "c1");
        Assert.Equal(["a3", "a4"], streak.Select(a => a.Id));

        Assert.Equal("wi-9", await repo.FindWorkItemForWindowAsync("t1", "c1", "2026-07-13"));
        Assert.Null(await repo.FindWorkItemForWindowAsync("t1", "c1", "2026-08-01"));
        Assert.Null(await repo.FindWorkItemForWindowAsync("t2", "c1", "2026-07-13"));

        // update path: status transition on the same row id
        first.Status = AttemptStatus.Succeeded;
        first.NewExpiresAt = Now.AddDays(365);
        first.NewThumbprint = "AA11";
        await repo.SaveAsync(first);
        var updated = (await repo.ListForCertificateAsync("t1", "c1", limit: 10))
            .Single(a => a.Id == "a1");
        Assert.Equal(AttemptStatus.Succeeded, updated.Status);
        Assert.Equal("AA11", updated.NewThumbprint);
    }

    [Fact]
    public async Task ApprovalRoundTripsAndUniqueWindowConstraintHolds()
    {
        var repo = new EfApprovalRepository(_factory);
        var approval = new RenewalApproval
        {
            TenantId = "t1",
            CertificateId = "c1",
            ExpirationWindowKey = "2026-07-13",
            RequestedAt = Now,
        };
        await repo.SaveAsync(approval);

        var pending = await repo.ListPendingForTenantAsync("t1");
        Assert.Single(pending);
        Assert.Equal(approval.Id, (await repo.FindForWindowAsync("t1", "c1", "2026-07-13"))!.Id);
        Assert.Null(await repo.GetAsync("t2", approval.Id)); // tenant filtered

        approval.Status = ApprovalStatus.Approved;
        approval.ApprovedBy = "boss@anadata.com";
        approval.ApprovedAt = Now.AddHours(1);
        await repo.SaveAsync(approval);
        var loaded = await repo.GetAsync("t1", approval.Id);
        Assert.Equal(ApprovalStatus.Approved, loaded!.Status);
        Assert.Empty(await repo.ListPendingForTenantAsync("t1"));

        // DB-level dedup: second row for the same cert + window must be rejected
        var duplicate = new RenewalApproval
        {
            TenantId = "t1",
            CertificateId = "c1",
            ExpirationWindowKey = "2026-07-13",
            RequestedAt = Now.AddHours(2),
        };
        await Assert.ThrowsAsync<DbUpdateException>(() => repo.SaveAsync(duplicate));
    }

    private static RenewalPolicy Enabled(string tenantId, string certId) => new()
    {
        TenantId = tenantId,
        CertificateId = certId,
        AutoRenewEnabled = true,
        EnabledBy = "a@b.c",
        EnabledAt = Now,
        UpdatedAt = Now,
    };

    private static RenewalAttempt MakeAttempt(
        string id, AttemptStatus status, int minutesAgo,
        bool dryRun = false, string? workItemId = null, string windowKey = "2026-07-13") => new()
    {
        Id = id,
        TenantId = "t1",
        CertificateId = "c1",
        Status = status,
        Method = RenewalMethod.KeyVault,
        DryRun = dryRun,
        ExpirationWindowKey = windowKey,
        WorkItemId = workItemId,
        StartedAt = Now.AddMinutes(-minutesAgo),
        FinishedAt = Now.AddMinutes(-minutesAgo),
    };
}
