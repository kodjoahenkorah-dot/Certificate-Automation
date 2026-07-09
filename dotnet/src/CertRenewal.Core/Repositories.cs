using System.Collections.Concurrent;
using CertRenewal.Core.Models;

namespace CertRenewal.Core;

// ---------------------------------------------------------------------------
// Persistence ports.
//
// INTEGRATION POINT: the engine talks to storage only through these four
// interfaces. Implement them against the existing Clear Ops database (an
// EF Core implementation is provided in CertRenewal.EntityFramework as a
// reference / default). The in-memory implementations below are used by the
// test suite and are handy for local experimentation.
//
// Every method takes tenantId explicitly — implementations MUST filter by it.
// ---------------------------------------------------------------------------

/// <summary>Read-side access to the product's existing certificates table.</summary>
public interface ICertificateRepository
{
    /// <summary>Return the cert only if it belongs to tenantId, else null.</summary>
    Task<Certificate?> GetAsync(string tenantId, string certificateId, CancellationToken ct = default);

    Task<IReadOnlyList<Certificate>> ListForTenantAsync(string tenantId, CancellationToken ct = default);

    /// <summary>Write the renewed expiry/thumbprint back to the certificates
    /// table so the UI reflects the renewal before the next full scan.</summary>
    Task UpdateAfterRenewalAsync(
        string tenantId, string certificateId,
        DateTimeOffset? newExpiresAt, string? newThumbprint,
        CancellationToken ct = default);
}

public interface IPolicyRepository
{
    Task<RenewalPolicy?> GetAsync(string tenantId, string certificateId, CancellationToken ct = default);
    Task SaveAsync(RenewalPolicy policy, CancellationToken ct = default);
    Task<IReadOnlyList<RenewalPolicy>> ListEnabledForTenantAsync(string tenantId, CancellationToken ct = default);
}

public interface IAttemptRepository
{
    /// <summary>Insert or update (matched on attempt.Id).</summary>
    Task SaveAsync(RenewalAttempt attempt, CancellationToken ct = default);

    /// <summary>Most recent first.</summary>
    Task<IReadOnlyList<RenewalAttempt>> ListForCertificateAsync(
        string tenantId, string certificateId, int limit = 20, CancellationToken ct = default);

    /// <summary>Terminal, non-dry-run attempts after the latest Succeeded one
    /// (i.e. the current failure streak). Used for retry budgeting.</summary>
    Task<IReadOnlyList<RenewalAttempt>> AttemptsSinceLastSuccessAsync(
        string tenantId, string certificateId, CancellationToken ct = default);

    /// <summary>Id of a Work Item already created for this cert in this expiry
    /// window, if any. Used to deduplicate manual-fallback Work Items.</summary>
    Task<string?> FindWorkItemForWindowAsync(
        string tenantId, string certificateId, string expirationWindowKey,
        CancellationToken ct = default);
}

/// <summary>Persistence for ApprovalRequired-mode sign-offs.</summary>
public interface IApprovalRepository
{
    Task<RenewalApproval?> GetAsync(string tenantId, string approvalId, CancellationToken ct = default);

    /// <summary>Most recent approval for this cert + window, any status.</summary>
    Task<RenewalApproval?> FindForWindowAsync(
        string tenantId, string certificateId, string expirationWindowKey,
        CancellationToken ct = default);

    Task SaveAsync(RenewalApproval approval, CancellationToken ct = default);

    Task<IReadOnlyList<RenewalApproval>> ListPendingForTenantAsync(
        string tenantId, CancellationToken ct = default);
}

// ---------------------------------------------------------------------------
// In-memory implementations (tests / local experimentation)
// ---------------------------------------------------------------------------

public sealed class InMemoryCertificateRepository : ICertificateRepository
{
    private readonly ConcurrentDictionary<string, Certificate> _certs = new();

    public void Add(Certificate cert) => _certs[cert.Id] = cert;

    public Task<Certificate?> GetAsync(string tenantId, string certificateId, CancellationToken ct = default)
    {
        _certs.TryGetValue(certificateId, out var cert);
        return Task.FromResult(cert?.TenantId == tenantId ? cert : null);
    }

    public Task<IReadOnlyList<Certificate>> ListForTenantAsync(string tenantId, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<Certificate>>(
            _certs.Values.Where(c => c.TenantId == tenantId).ToList());

    public Task UpdateAfterRenewalAsync(
        string tenantId, string certificateId,
        DateTimeOffset? newExpiresAt, string? newThumbprint, CancellationToken ct = default)
    {
        if (_certs.TryGetValue(certificateId, out var cert) && cert.TenantId == tenantId)
        {
            if (newExpiresAt is not null) cert.ExpiresAt = newExpiresAt.Value;
            if (newThumbprint is not null) cert.Thumbprint = newThumbprint;
        }
        return Task.CompletedTask;
    }
}

public sealed class InMemoryPolicyRepository : IPolicyRepository
{
    private readonly ConcurrentDictionary<(string, string), RenewalPolicy> _policies = new();

    public Task<RenewalPolicy?> GetAsync(string tenantId, string certificateId, CancellationToken ct = default)
    {
        _policies.TryGetValue((tenantId, certificateId), out var policy);
        return Task.FromResult(policy);
    }

    public Task SaveAsync(RenewalPolicy policy, CancellationToken ct = default)
    {
        _policies[(policy.TenantId, policy.CertificateId)] = policy;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<RenewalPolicy>> ListEnabledForTenantAsync(string tenantId, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<RenewalPolicy>>(
            _policies.Where(kv => kv.Key.Item1 == tenantId && kv.Value.AutoRenewEnabled)
                .Select(kv => kv.Value).ToList());
}

public sealed class InMemoryAttemptRepository : IAttemptRepository
{
    private readonly ConcurrentDictionary<string, RenewalAttempt> _attempts = new();

    public Task SaveAsync(RenewalAttempt attempt, CancellationToken ct = default)
    {
        _attempts[attempt.Id] = attempt;
        return Task.CompletedTask;
    }

    private IEnumerable<RenewalAttempt> ForCert(string tenantId, string certificateId) =>
        _attempts.Values.Where(a => a.TenantId == tenantId && a.CertificateId == certificateId);

    public Task<IReadOnlyList<RenewalAttempt>> ListForCertificateAsync(
        string tenantId, string certificateId, int limit = 20, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<RenewalAttempt>>(
            ForCert(tenantId, certificateId)
                .OrderByDescending(a => a.StartedAt).Take(limit).ToList());

    public Task<IReadOnlyList<RenewalAttempt>> AttemptsSinceLastSuccessAsync(
        string tenantId, string certificateId, CancellationToken ct = default)
    {
        var streak = new List<RenewalAttempt>();
        foreach (var a in ForCert(tenantId, certificateId).OrderBy(a => a.StartedAt))
        {
            if (a.DryRun || !a.Status.IsTerminal()) continue;
            if (a.Status == AttemptStatus.Succeeded) streak.Clear();
            else streak.Add(a);
        }
        return Task.FromResult<IReadOnlyList<RenewalAttempt>>(streak);
    }

    public Task<string?> FindWorkItemForWindowAsync(
        string tenantId, string certificateId, string expirationWindowKey, CancellationToken ct = default) =>
        Task.FromResult(
            ForCert(tenantId, certificateId)
                .Where(a => a.WorkItemId is not null && a.ExpirationWindowKey == expirationWindowKey)
                .OrderByDescending(a => a.StartedAt)
                .Select(a => a.WorkItemId)
                .FirstOrDefault());
}

public sealed class InMemoryApprovalRepository : IApprovalRepository
{
    private readonly ConcurrentDictionary<string, RenewalApproval> _approvals = new();

    public Task<RenewalApproval?> GetAsync(string tenantId, string approvalId, CancellationToken ct = default)
    {
        _approvals.TryGetValue(approvalId, out var approval);
        return Task.FromResult(approval?.TenantId == tenantId ? approval : null);
    }

    public Task<RenewalApproval?> FindForWindowAsync(
        string tenantId, string certificateId, string expirationWindowKey, CancellationToken ct = default) =>
        Task.FromResult(
            _approvals.Values
                .Where(a => a.TenantId == tenantId
                            && a.CertificateId == certificateId
                            && a.ExpirationWindowKey == expirationWindowKey)
                .OrderByDescending(a => a.RequestedAt)
                .FirstOrDefault());

    public Task SaveAsync(RenewalApproval approval, CancellationToken ct = default)
    {
        _approvals[approval.Id] = approval;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<RenewalApproval>> ListPendingForTenantAsync(
        string tenantId, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<RenewalApproval>>(
            _approvals.Values
                .Where(a => a.TenantId == tenantId && a.Status == ApprovalStatus.Pending)
                .ToList());
}
