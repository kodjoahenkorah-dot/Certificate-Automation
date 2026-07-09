using CertRenewal.Core.Models;

namespace CertRenewal.Core;

/// <summary>Raised when a renewal is attempted for a cert that was never opted in.</summary>
public sealed class OptInRequiredException(string message) : Exception(message);

/// <summary>Raised when an operation crosses tenant boundaries.</summary>
public sealed class TenantScopeException(string message) : Exception(message);

/// <summary>The attempt did not run (retry budget, cooldown, wrong state). Not an error.</summary>
public sealed class RenewalSkippedException(string message) : Exception(message);

/// <summary>The policy requires human approval and none has been granted for
/// the current expiry window. Not an error; the approval (newly created or
/// already open) is attached.</summary>
public sealed class ApprovalPendingException(string message, RenewalApproval? approval = null)
    : Exception(message)
{
    public RenewalApproval? Approval { get; } = approval;
}

/// <summary>
/// Opt-in enforcement and renewal-window math. This is the single place where
/// "is this certificate allowed to be renewed automatically?" is decided. The
/// engine calls AssertOptedIn before every attempt, so the guarantee holds
/// even for attempts triggered manually through the API or by a misbehaving
/// scheduler.
/// </summary>
public static class PolicyGuard
{
    /// <summary>
    /// Gatekeeper: a cert is renewable only with an explicit, attributed opt-in.
    /// No policy row, a disabled policy, or an enabled policy with no recorded
    /// actor/timestamp (which should never exist if EnableAutoRenewal was used)
    /// all fail closed.
    /// </summary>
    public static RenewalPolicy AssertOptedIn(RenewalPolicy? policy)
    {
        if (policy is null || !policy.AutoRenewEnabled)
            throw new OptInRequiredException(
                "Automated renewal is disabled for this certificate. " +
                "A user must explicitly enable it first.");
        if (string.IsNullOrWhiteSpace(policy.EnabledBy) || policy.EnabledAt is null)
            throw new OptInRequiredException(
                "Renewal policy is enabled but has no recorded actor/timestamp; " +
                "refusing to renew. Re-enable via EnableAutoRenewal.");
        return policy;
    }

    public static void AssertTenantScope(Certificate cert, string tenantId)
    {
        if (!string.Equals(cert.TenantId, tenantId, StringComparison.Ordinal))
            throw new TenantScopeException(
                $"Certificate {cert.Id} belongs to tenant '{cert.TenantId}', " +
                $"but the operation is scoped to tenant '{tenantId}'.");
    }

    /// <summary>
    /// Turn auto-renew ON for one certificate, recording who and when.
    /// <paramref name="actor"/> is required and must be non-empty — anonymous
    /// opt-ins are rejected so the audit trail is always complete.
    /// </summary>
    public static RenewalPolicy EnableAutoRenewal(
        RenewalPolicy? policy,
        Certificate certificate,
        string actor,
        DateTimeOffset now,
        int? renewalWindowDays = null,
        RenewalMode? renewalMode = null,
        RenewalOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(actor))
            throw new ArgumentException("actor is required to enable auto-renewal", nameof(actor));
        options ??= new RenewalOptions();

        var window = renewalWindowDays
            ?? policy?.RenewalWindowDays
            ?? options.DefaultRenewalWindowDays;
        if (window is < 1 or > 365)
            throw new ArgumentOutOfRangeException(
                nameof(renewalWindowDays), "renewal window must be between 1 and 365 days");

        policy ??= new RenewalPolicy
        {
            CertificateId = certificate.Id,
            TenantId = certificate.TenantId,
        };
        if (!string.Equals(policy.CertificateId, certificate.Id, StringComparison.Ordinal))
            throw new ArgumentException("policy does not belong to this certificate");
        AssertTenantScope(certificate, policy.TenantId);

        policy.AutoRenewEnabled = true;
        policy.EnabledBy = actor.Trim();
        policy.EnabledAt = now;
        policy.RenewalWindowDays = window;
        if (renewalMode is not null) policy.RenewalMode = renewalMode.Value;
        policy.UpdatedAt = now;
        return policy;
    }

    public static RenewalPolicy DisableAutoRenewal(
        RenewalPolicy policy, string actor, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(actor))
            throw new ArgumentException("actor is required to disable auto-renewal", nameof(actor));
        policy.AutoRenewEnabled = false;
        policy.DisabledBy = actor.Trim();
        policy.DisabledAt = now;
        policy.UpdatedAt = now;
        return policy;
    }

    /// <summary>
    /// True when the cert is expired or expires within the policy window.
    /// Expired certs are deliberately included: the product surfaces them as
    /// Critical findings and they are the most urgent renewal case.
    /// </summary>
    public static bool InRenewalWindow(Certificate cert, RenewalPolicy policy, DateTimeOffset now) =>
        cert.ExpiresAt <= now.AddDays(policy.RenewalWindowDays);

    /// <summary>
    /// Scheduler predicate: opted in AND inside the renewal window. Unlike
    /// AssertOptedIn this doesn't throw — the sweep silently skips
    /// non-opted-in certs.
    /// </summary>
    public static bool ShouldRenew(Certificate cert, RenewalPolicy? policy, DateTimeOffset now)
    {
        if (policy is null || !policy.AutoRenewEnabled) return false;
        if (string.IsNullOrWhiteSpace(policy.EnabledBy) || policy.EnabledAt is null) return false;
        if (cert.TenantId != policy.TenantId || cert.Id != policy.CertificateId) return false;
        return InRenewalWindow(cert, policy, now);
    }

    /// <summary>
    /// Dry-run wins if ANY level asks for it: global options, per-tenant list,
    /// or the per-certificate policy override. A policy override of false can
    /// only take effect once global and tenant levels allow live runs.
    /// </summary>
    public static bool EffectiveDryRun(RenewalOptions options, RenewalPolicy? policy, string tenantId)
    {
        if (options.DryRun) return true;
        if (options.DryRunTenants.Contains(tenantId)) return true;
        if (policy?.DryRunOverride is not null) return policy.DryRunOverride.Value;
        return false;
    }

    /// <summary>
    /// Decide whether another attempt may run and what its number would be.
    /// <paramref name="attemptsThisCycle"/> = attempts for this cert since it
    /// last entered the renewal window with no success in between (the
    /// repository provides this via AttemptsSinceLastSuccessAsync).
    /// </summary>
    public static (bool Allowed, int NextAttemptNumber) RetryAllowed(
        IReadOnlyList<RenewalAttempt> attemptsThisCycle,
        int maxAttempts,
        TimeSpan retryInterval,
        DateTimeOffset now)
    {
        if (attemptsThisCycle.Count == 0) return (true, 1);
        var last = attemptsThisCycle.MaxBy(a => a.StartedAt)!;
        var n = attemptsThisCycle.Count;
        if (n >= maxAttempts) return (false, n + 1);
        var anchor = last.FinishedAt ?? last.StartedAt;
        if (now - anchor < retryInterval) return (false, n + 1);
        return (true, n + 1);
    }
}
