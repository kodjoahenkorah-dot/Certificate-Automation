using CertRenewal.Core.Models;
using CertRenewal.Core.Providers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertRenewal.Core;

/// <summary>
/// Orchestrates a single certificate renewal. Pipeline for every attempt
/// (manual API trigger and scheduler alike):
///
///   load cert (tenant-filtered) -> tenant-scope check -> OPT-IN GATE
///     -> approval gate (ApprovalRequired mode) -> renewal-window check
///     -> retry budget -> method selection -> dry-run resolution
///     -> provider.RenewAsync -> provider.VerifyAsync (live successes)
///     -> audit record -> cert table write-back
///     -> Work Item on exhaustion -> notification
///
/// Every attempt — including rejected and dry-run ones — leaves a
/// RenewalAttempt audit row. Safe to call from any job runner; if you
/// parallelize, parallelize across tenants, never within one without
/// external per-certificate locking.
/// </summary>
public sealed class RenewalEngine(
    ICertificateRepository certs,
    IPolicyRepository policies,
    IAttemptRepository attempts,
    IReadOnlyDictionary<RenewalMethod, IRenewalProvider> providers,
    ITenantCredentialResolver credentials,
    INotifier notifier,
    IWorkItemSink workItems,
    IApprovalRepository? approvals = null,
    RenewalOptions? options = null,
    TimeProvider? timeProvider = null,
    ILogger<RenewalEngine>? logger = null)
{
    // Approvals only matter for ApprovalRequired policies; default to an
    // in-memory store so purely-automatic deployments need no extra table.
    private readonly IApprovalRepository _approvals = approvals ?? new InMemoryApprovalRepository();
    private readonly RenewalOptions _options = options ?? new RenewalOptions();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ILogger _log = logger ?? NullLogger<RenewalEngine>.Instance;

    /// <summary>
    /// CAs whose certificates we can re-issue automatically via ACME. Anything
    /// else (GlobalSign, Sectigo, GoDaddy, AlphaSSL, SSL2BUY, ...) is a paid CA
    /// whose renewal is a purchase/CSR workflow -> manual Work Item fallback.
    /// </summary>
    public static readonly string[] AcmeAutomatableIssuers =
        ["let's encrypt", "lets encrypt", "zerossl", "buypass"];

    /// <summary>
    /// Choose the renewal method from the cert's source and issuer. KeyVault
    /// and AppService certs go to their Azure providers (the provider itself
    /// falls back to ManualRequired when the cert turns out to be
    /// non-renewable, e.g. an imported Key Vault cert with no issuer policy).
    /// External certs are ACME-renewable only when issued by an ACME CA; paid
    /// CAs become manual Work Items.
    /// </summary>
    public static RenewalMethod SelectMethod(Certificate cert)
    {
        if (cert.Source == CertSource.KeyVault) return RenewalMethod.KeyVault;
        if (cert.Source == CertSource.AppService) return RenewalMethod.AppService;
        var issuer = (cert.Issuer ?? "").ToLowerInvariant();
        return AcmeAutomatableIssuers.Any(issuer.Contains)
            ? RenewalMethod.Acme
            : RenewalMethod.Manual;
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// <summary>
    /// Run one renewal attempt. Throws OptInRequiredException /
    /// TenantScopeException / ApprovalPendingException / RenewalSkippedException;
    /// any provider exception is caught and recorded as a failed attempt.
    /// <paramref name="force"/> (manual API trigger) bypasses the
    /// renewal-window and retry-cooldown checks but NEVER the opt-in,
    /// tenant-scope, or approval gates.
    /// </summary>
    public async Task<RenewalAttempt> RenewCertificateAsync(
        string tenantId, string certificateId,
        string triggeredBy = "scheduler", bool force = false,
        CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var cert = await certs.GetAsync(tenantId, certificateId, ct)
            ?? throw new TenantScopeException(
                $"Certificate '{certificateId}' not found in tenant '{tenantId}'.");
        PolicyGuard.AssertTenantScope(cert, tenantId);

        var policy = PolicyGuard.AssertOptedIn(await policies.GetAsync(tenantId, certificateId, ct));

        if (!force && !PolicyGuard.InRenewalWindow(cert, policy, now))
            throw new RenewalSkippedException(
                $"Certificate {cert.Name} is outside its {policy.RenewalWindowDays}-day renewal window.");

        if (policy.RenewalMode == RenewalMode.ApprovalRequired)
            await RequireApprovalAsync(cert, triggeredBy, now, ct);

        var maxAttempts = policy.MaxAttempts ?? _options.MaxAttempts;
        var retryInterval = policy.RetryIntervalMinutes is int m
            ? TimeSpan.FromMinutes(m)
            : _options.RetryInterval;
        var streak = await attempts.AttemptsSinceLastSuccessAsync(tenantId, certificateId, ct);
        var (allowed, attemptNumber) = PolicyGuard.RetryAllowed(streak, maxAttempts, retryInterval, now);
        if (!allowed && !force)
            throw new RenewalSkippedException(
                $"Retry budget/cooldown: {streak.Count} of {maxAttempts} attempts used.");
        if (force) attemptNumber = streak.Count + 1;

        var dryRun = PolicyGuard.EffectiveDryRun(_options, policy, tenantId);
        var method = SelectMethod(cert);
        var windowKey = cert.ExpirationWindowKey();

        var attempt = new RenewalAttempt
        {
            TenantId = tenantId,
            CertificateId = certificateId,
            Status = AttemptStatus.Pending,
            Method = method,
            DryRun = dryRun,
            AttemptNumber = attemptNumber,
            ExpirationWindowKey = windowKey,
            TriggeredBy = triggeredBy,
            StartedAt = now,
        };
        await attempts.SaveAsync(attempt, ct);

        // Idempotency: if a Work Item already exists for this expiry window,
        // the manual path has nothing left to do — reference it and stop
        // instead of creating a duplicate on every sweep.
        if (method == RenewalMethod.Manual && !dryRun)
        {
            var existing = await attempts.FindWorkItemForWindowAsync(tenantId, certificateId, windowKey, ct);
            if (existing is not null)
            {
                attempt.Status = AttemptStatus.ManualRequired;
                attempt.FinishedAt = _time.GetUtcNow();
                attempt.WorkItemId = existing;
                attempt.Detail = $"Work Item {existing} already open for this expiry window; no duplicate created.";
                await attempts.SaveAsync(attempt, ct);
                return attempt;
            }
        }

        attempt.Status = AttemptStatus.InProgress;
        await attempts.SaveAsync(attempt, ct);

        var result = await ExecuteAsync(cert, method, dryRun, ct);
        await FinalizeAsync(cert, attempt, result, maxAttempts, ct);
        return attempt;
    }

    /// <summary>
    /// One scheduler sweep for one tenant: attempt every opted-in cert that is
    /// inside its renewal window and has retry budget. Never throws for
    /// per-cert errors; each outcome is in the returned audit records.
    /// </summary>
    public async Task<IReadOnlyList<RenewalAttempt>> RunDueRenewalsAsync(
        string tenantId, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var results = new List<RenewalAttempt>();
        var budget = _options.MaxRenewalsPerSweep;

        foreach (var policy in await policies.ListEnabledForTenantAsync(tenantId, ct))
        {
            var cert = await certs.GetAsync(tenantId, policy.CertificateId, ct);
            if (cert is null || !PolicyGuard.ShouldRenew(cert, policy, now)) continue;
            if (budget > 0 && results.Count >= budget)
            {
                _log.LogInformation(
                    "[tenant={Tenant}] Sweep budget ({Budget}) reached; remaining certs will be picked up next sweep.",
                    tenantId, budget);
                break;
            }

            try
            {
                results.Add(await RenewCertificateAsync(tenantId, cert.Id, "scheduler", ct: ct));
            }
            catch (RenewalSkippedException ex)
            {
                _log.LogDebug("[tenant={Tenant}] {Cert}: {Reason}", tenantId, cert.Name, ex.Message);
            }
            catch (ApprovalPendingException ex)
            {
                _log.LogInformation("[tenant={Tenant}] {Cert}: {Reason}", tenantId, cert.Name, ex.Message);
            }
            catch (OptInRequiredException)
            {
                // Race: policy disabled between listing and attempting.
                _log.LogInformation("[tenant={Tenant}] {Cert} no longer opted in; skipped.", tenantId, cert.Name);
            }
        }
        return results;
    }

    /// <summary>Approve a pending ApprovalRequired renewal and run it
    /// immediately. The approval covers only the certificate's current
    /// expiry window.</summary>
    public async Task<RenewalAttempt> ApproveRenewalAsync(
        string tenantId, string approvalId, string actor, string? notes = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(actor))
            throw new ArgumentException("actor is required to approve a renewal", nameof(actor));
        var approval = await _approvals.GetAsync(tenantId, approvalId, ct)
            ?? throw new TenantScopeException(
                $"Approval '{approvalId}' not found in tenant '{tenantId}'.");
        if (approval.Status != ApprovalStatus.Pending)
            throw new RenewalSkippedException($"Approval {approvalId} is already {approval.Status}.");

        approval.Status = ApprovalStatus.Approved;
        approval.ApprovedBy = actor.Trim();
        approval.ApprovedAt = _time.GetUtcNow();
        approval.Notes = notes ?? approval.Notes;
        await _approvals.SaveAsync(approval, ct);

        return await RenewCertificateAsync(
            tenantId, approval.CertificateId, $"approval:{actor}", ct: ct);
    }

    /// <summary>Reject a pending approval. The cert will not be renewed this
    /// expiry window unless a user re-triggers and re-approves.</summary>
    public async Task<RenewalApproval> RejectRenewalAsync(
        string tenantId, string approvalId, string actor, string? notes = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(actor))
            throw new ArgumentException("actor is required to reject a renewal", nameof(actor));
        var approval = await _approvals.GetAsync(tenantId, approvalId, ct)
            ?? throw new TenantScopeException(
                $"Approval '{approvalId}' not found in tenant '{tenantId}'.");
        if (approval.Status != ApprovalStatus.Pending)
            throw new RenewalSkippedException($"Approval {approvalId} is already {approval.Status}.");

        approval.Status = ApprovalStatus.Rejected;
        approval.RejectedBy = actor.Trim();
        approval.RejectedAt = _time.GetUtcNow();
        approval.Notes = notes ?? approval.Notes;
        await _approvals.SaveAsync(approval, ct);
        return approval;
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /// <summary>Gate for ApprovalRequired mode. Proceeds only when an Approved
    /// approval exists for the cert's current expiry window; otherwise ensures
    /// exactly one Pending approval exists (idempotent per window) and throws
    /// ApprovalPendingException.</summary>
    private async Task RequireApprovalAsync(
        Certificate cert, string triggeredBy, DateTimeOffset now, CancellationToken ct)
    {
        var windowKey = cert.ExpirationWindowKey();
        var approval = await _approvals.FindForWindowAsync(cert.TenantId, cert.Id, windowKey, ct);

        switch (approval?.Status)
        {
            case ApprovalStatus.Approved:
                return;
            case ApprovalStatus.Pending:
                throw new ApprovalPendingException(
                    $"Renewal of {cert.Name} awaits approval (approval {approval.Id}, window {windowKey}).",
                    approval);
            case ApprovalStatus.Rejected:
                throw new ApprovalPendingException(
                    $"Renewal of {cert.Name} was rejected by {approval.RejectedBy} for window {windowKey}; not retrying.",
                    approval);
        }

        var created = new RenewalApproval
        {
            TenantId = cert.TenantId,
            CertificateId = cert.Id,
            ExpirationWindowKey = windowKey,
            RequestedBy = triggeredBy,
            RequestedAt = now,
        };
        await _approvals.SaveAsync(created, ct);
        throw new ApprovalPendingException(
            $"Renewal of {cert.Name} requires approval; created approval {created.Id} for window {windowKey}.",
            created);
    }

    private async Task<RenewalResult> ExecuteAsync(
        Certificate cert, RenewalMethod method, bool dryRun, CancellationToken ct)
    {
        if (!providers.TryGetValue(method, out var provider))
            return new RenewalResult
            {
                Status = AttemptStatus.Failed,
                Error = $"No provider registered for method '{method}'.",
            };

        ProviderContext ctx;
        try
        {
            ctx = await BuildContextAsync(cert, method, dryRun, ct);
        }
        catch (CredentialNotConfiguredException ex)
        {
            return new RenewalResult { Status = AttemptStatus.Failed, Error = ex.Message };
        }

        try
        {
            var result = await provider.RenewAsync(cert, ctx, ct);
            // Trust-but-verify: a live success must survive the provider's
            // own re-read of the renewed resource before we record it.
            if (result.Status == AttemptStatus.Succeeded && !dryRun)
            {
                var verifyError = await provider.VerifyAsync(cert, result, ctx, ct);
                if (verifyError is not null)
                    return new RenewalResult
                    {
                        Status = AttemptStatus.Failed,
                        Error = $"Renewal reported success but verification failed: {verifyError}",
                        Detail = result.Detail,
                    };
            }
            return result;
        }
        catch (Exception ex) // provider bugs/timeouts become failed attempts
        {
            _log.LogError(ex, "[tenant={Tenant}] Provider {Method} threw for cert {Cert}",
                cert.TenantId, method, cert.Id);
            return new RenewalResult
            {
                Status = AttemptStatus.Failed,
                Error = $"{ex.GetType().Name}: {ex.Message}",
            };
        }
    }

    private async Task<ProviderContext> BuildContextAsync(
        Certificate cert, RenewalMethod method, bool dryRun, CancellationToken ct)
    {
        object? credential = null;
        string? subscriptionId = null;
        byte[]? acmeKey = null;

        if (method is RenewalMethod.KeyVault or RenewalMethod.AppService)
        {
            // Credentials resolved from the CERT's tenant — combined with
            // AssertTenantScope this makes cross-tenant renewal impossible.
            credential = await credentials.GetAzureCredentialAsync(cert.TenantId, ct);
            subscriptionId = cert.AzureSubscriptionId
                ?? await credentials.GetAzureSubscriptionIdAsync(cert.TenantId, ct);
        }
        else if (method == RenewalMethod.Acme)
        {
            acmeKey = await credentials.GetAcmeAccountKeyPemAsync(cert.TenantId, ct);
        }

        return new ProviderContext
        {
            TenantId = cert.TenantId,
            DryRun = dryRun,
            Options = _options,
            AzureCredential = credential,
            AzureSubscriptionId = subscriptionId,
            AcmeAccountKeyPem = acmeKey,
        };
    }

    private async Task FinalizeAsync(
        Certificate cert, RenewalAttempt attempt, RenewalResult result,
        int maxAttempts, CancellationToken ct)
    {
        attempt.Status = result.Status;
        attempt.FinishedAt = _time.GetUtcNow();
        attempt.NewExpiresAt = result.NewExpiresAt;
        attempt.NewThumbprint = result.NewThumbprint;
        attempt.Error = result.Error;
        attempt.Detail = result.Detail;
        attempt.WorkItemId = result.WorkItemId;

        if (result.Status == AttemptStatus.Succeeded && !attempt.DryRun)
        {
            await certs.UpdateAfterRenewalAsync(
                cert.TenantId, cert.Id, result.NewExpiresAt, result.NewThumbprint, ct);
        }

        // Exhausted retries with no Work Item yet -> escalate to manual.
        if (result.Status == AttemptStatus.Failed
            && attempt.AttemptNumber >= maxAttempts
            && !attempt.DryRun
            && attempt.WorkItemId is null)
        {
            attempt.WorkItemId = await CreateFallbackWorkItemAsync(
                cert,
                $"Automated renewal failed {attempt.AttemptNumber} time(s); last error: {result.Error}",
                ct);
            attempt.Status = AttemptStatus.ManualRequired;
            attempt.Detail = (attempt.Detail is null ? "" : attempt.Detail + "\n")
                + "Retry budget exhausted; escalated to a Work Item.";
        }

        await attempts.SaveAsync(attempt, ct);
        await NotifyAsync(cert, attempt, ct);
    }

    private async Task<string> CreateFallbackWorkItemAsync(
        Certificate cert, string reason, CancellationToken ct)
    {
        var windowKey = cert.ExpirationWindowKey();
        var existing = await attempts.FindWorkItemForWindowAsync(cert.TenantId, cert.Id, windowKey, ct);
        if (existing is not null) return existing;

        var now = _time.GetUtcNow();
        return await workItems.CreateAsync(new WorkItemRequest
        {
            TenantId = cert.TenantId,
            Title = $"Renew certificate {cert.Name}",
            Description = reason + "\n\n" + ManualInstructions.Build(cert, now),
            Severity = cert.IsExpired(now) ? "critical" : "high",
            AssigneeEmail = cert.OwnerEmail,
            CertificateId = cert.Id,
            IdempotencyKey = $"{cert.Id}:{windowKey}",
        }, ct);
    }

    private async Task NotifyAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct)
    {
        try
        {
            var task = attempt.Status switch
            {
                AttemptStatus.Succeeded => notifier.RenewalSucceededAsync(cert, attempt, ct),
                AttemptStatus.ManualRequired => notifier.ManualActionRequiredAsync(cert, attempt, ct),
                AttemptStatus.Failed => notifier.RenewalFailedAsync(cert, attempt, ct),
                _ => Task.CompletedTask,
            };
            await task;
        }
        catch (Exception ex)
        {
            // A broken notification channel must not fail the renewal itself.
            _log.LogError(ex, "[tenant={Tenant}] Notifier threw for cert {Cert}", cert.TenantId, cert.Id);
        }
    }
}
