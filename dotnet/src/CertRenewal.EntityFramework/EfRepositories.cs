using CertRenewal.Core;
using CertRenewal.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace CertRenewal.EntityFramework;

/// <summary>EF Core implementation of IPolicyRepository. Inject
/// IDbContextFactory so repository calls are safe from singleton services
/// (the engine and background jobs).</summary>
public sealed class EfPolicyRepository(IDbContextFactory<CertRenewalDbContext> factory)
    : IPolicyRepository
{
    public async Task<RenewalPolicy?> GetAsync(string tenantId, string certificateId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var row = await db.Policies.AsNoTracking().FirstOrDefaultAsync(
            p => p.TenantId == tenantId && p.CertificateId == certificateId, ct);
        return row?.ToDomain();
    }

    public async Task SaveAsync(RenewalPolicy policy, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var row = await db.Policies.FirstOrDefaultAsync(
            p => p.TenantId == policy.TenantId && p.CertificateId == policy.CertificateId, ct);
        if (row is null)
        {
            row = new PolicyRow { TenantId = policy.TenantId, CertificateId = policy.CertificateId };
            db.Policies.Add(row);
        }
        row.Apply(policy);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RenewalPolicy>> ListEnabledForTenantAsync(
        string tenantId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.Policies.AsNoTracking()
            .Where(p => p.TenantId == tenantId && p.AutoRenewEnabled)
            .ToListAsync(ct);
        return rows.Select(r => r.ToDomain()).ToList();
    }
}

public sealed class EfAttemptRepository(IDbContextFactory<CertRenewalDbContext> factory)
    : IAttemptRepository
{
    public async Task SaveAsync(RenewalAttempt attempt, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var existing = await db.Attempts.FindAsync([attempt.Id], ct);
        if (existing is null)
            db.Attempts.Add(AttemptRow.FromDomain(attempt));
        else
            db.Entry(existing).CurrentValues.SetValues(AttemptRow.FromDomain(attempt));
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RenewalAttempt>> ListForCertificateAsync(
        string tenantId, string certificateId, int limit = 20, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.Attempts.AsNoTracking()
            .Where(a => a.TenantId == tenantId && a.CertificateId == certificateId)
            .OrderByDescending(a => a.StartedAt)
            .Take(limit)
            .ToListAsync(ct);
        return rows.Select(r => r.ToDomain()).ToList();
    }

    public async Task<IReadOnlyList<RenewalAttempt>> AttemptsSinceLastSuccessAsync(
        string tenantId, string certificateId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var terminal = new[] { AttemptStatus.Succeeded, AttemptStatus.Failed, AttemptStatus.ManualRequired };
        var rows = await db.Attempts.AsNoTracking()
            .Where(a => a.TenantId == tenantId
                        && a.CertificateId == certificateId
                        && !a.DryRun
                        && terminal.Contains(a.Status))
            .OrderBy(a => a.StartedAt)
            .ToListAsync(ct);

        var streak = new List<RenewalAttempt>();
        foreach (var row in rows)
        {
            if (row.Status == AttemptStatus.Succeeded) streak.Clear();
            else streak.Add(row.ToDomain());
        }
        return streak;
    }

    public async Task<string?> FindWorkItemForWindowAsync(
        string tenantId, string certificateId, string expirationWindowKey, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.Attempts.AsNoTracking()
            .Where(a => a.TenantId == tenantId
                        && a.CertificateId == certificateId
                        && a.ExpirationWindowKey == expirationWindowKey
                        && a.WorkItemId != null)
            .OrderByDescending(a => a.StartedAt)
            .Select(a => a.WorkItemId)
            .FirstOrDefaultAsync(ct);
    }
}

public sealed class EfApprovalRepository(IDbContextFactory<CertRenewalDbContext> factory)
    : IApprovalRepository
{
    public async Task<RenewalApproval?> GetAsync(string tenantId, string approvalId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var row = await db.Approvals.AsNoTracking().FirstOrDefaultAsync(
            a => a.Id == approvalId && a.TenantId == tenantId, ct);
        return row?.ToDomain();
    }

    public async Task<RenewalApproval?> FindForWindowAsync(
        string tenantId, string certificateId, string expirationWindowKey, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var row = await db.Approvals.AsNoTracking()
            .Where(a => a.TenantId == tenantId
                        && a.CertificateId == certificateId
                        && a.ExpirationWindowKey == expirationWindowKey)
            .OrderByDescending(a => a.RequestedAt)
            .FirstOrDefaultAsync(ct);
        return row?.ToDomain();
    }

    public async Task SaveAsync(RenewalApproval approval, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var existing = await db.Approvals.FindAsync([approval.Id], ct);
        if (existing is null)
            db.Approvals.Add(ApprovalRow.FromDomain(approval));
        else
            existing.Apply(approval);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RenewalApproval>> ListPendingForTenantAsync(
        string tenantId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.Approvals.AsNoTracking()
            .Where(a => a.TenantId == tenantId && a.Status == ApprovalStatus.Pending)
            .ToListAsync(ct);
        return rows.Select(r => r.ToDomain()).ToList();
    }
}
