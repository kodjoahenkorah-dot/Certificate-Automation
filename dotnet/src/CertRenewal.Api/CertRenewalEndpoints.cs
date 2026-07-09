using CertRenewal.Core;
using CertRenewal.Core.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace CertRenewal.Api;

/// <summary>
/// INTEGRATION POINT: replace the default header-based resolver with the
/// product's real authentication. Must return a stable user identity
/// (email/UPN) for the audit trail, and enforce that the caller may act on
/// the tenant (RBAC). The engine still enforces data-level tenant scoping,
/// but authorization is the host app's job.
/// </summary>
public interface IActorResolver
{
    /// <summary>Return the acting user's identity, or null =&gt; 401.</summary>
    string? ResolveActor(HttpContext http);

    /// <summary>Return true when the actor may act on the tenant. Default
    /// allows everything — replace before production.</summary>
    bool AuthorizeTenant(HttpContext http, string actor, string tenantId) => true;
}

/// <summary>Placeholder that reads X-User-Email. Dev/test only.</summary>
public sealed class HeaderActorResolver : IActorResolver
{
    public string? ResolveActor(HttpContext http) =>
        http.Request.Headers.TryGetValue("X-User-Email", out var v) && !string.IsNullOrWhiteSpace(v)
            ? v.ToString()
            : null;
}

// --------------------------------------------------------------------------
// DTOs
// --------------------------------------------------------------------------

public sealed record EnableRequest(int? RenewalWindowDays, string? RenewalMode);
public sealed record PatchRequest(
    int? RenewalWindowDays, string? RenewalMode, bool? DryRunOverride,
    int? MaxAttempts, int? RetryIntervalMinutes);
public sealed record ApprovalDecision(string? Notes);

public sealed record PolicyDto(
    string CertificateId, string TenantId, bool AutoRenewEnabled, string RenewalMode,
    string? EnabledBy, DateTimeOffset? EnabledAt, string? DisabledBy, DateTimeOffset? DisabledAt,
    int RenewalWindowDays, bool? DryRunOverride, bool EffectiveDryRun, string RenewalMethod)
{
    public static PolicyDto From(RenewalPolicy p, RenewalOptions options, Certificate cert) => new(
        p.CertificateId, p.TenantId, p.AutoRenewEnabled,
        ToSnake(p.RenewalMode.ToString()),
        p.EnabledBy, p.EnabledAt, p.DisabledBy, p.DisabledAt,
        p.RenewalWindowDays, p.DryRunOverride,
        PolicyGuard.EffectiveDryRun(options, p, p.TenantId),
        ToSnake(RenewalEngine.SelectMethod(cert).ToString()));

    internal static string ToSnake(string pascal) =>
        string.Concat(pascal.Select((c, i) =>
            char.IsUpper(c) && i > 0 ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
}

public sealed record AttemptDto(
    string Id, string Status, string? Method, bool DryRun, int AttemptNumber,
    string TriggeredBy, DateTimeOffset StartedAt, DateTimeOffset? FinishedAt,
    DateTimeOffset? NewExpiresAt, string? NewThumbprint, string? Error,
    string? WorkItemId, string? Detail)
{
    public static AttemptDto From(RenewalAttempt a) => new(
        a.Id, PolicyDto.ToSnake(a.Status.ToString()),
        a.Method is null ? null : PolicyDto.ToSnake(a.Method.ToString()!),
        a.DryRun, a.AttemptNumber, a.TriggeredBy, a.StartedAt, a.FinishedAt,
        a.NewExpiresAt, a.NewThumbprint, a.Error, a.WorkItemId, a.Detail);
}

public sealed record ApprovalDto(
    string Id, string CertificateId, string ExpirationWindowKey, string Status,
    string RequestedBy, DateTimeOffset RequestedAt, string? ApprovedBy,
    DateTimeOffset? ApprovedAt, string? RejectedBy, DateTimeOffset? RejectedAt, string? Notes)
{
    public static ApprovalDto From(RenewalApproval a) => new(
        a.Id, a.CertificateId, a.ExpirationWindowKey, PolicyDto.ToSnake(a.Status.ToString()),
        a.RequestedBy, a.RequestedAt, a.ApprovedBy, a.ApprovedAt, a.RejectedBy, a.RejectedAt, a.Notes);
}

public sealed record RenewalStateDto(PolicyDto Policy, IReadOnlyList<AttemptDto> RecentAttempts);

// --------------------------------------------------------------------------
// Endpoints
// --------------------------------------------------------------------------

public static class CertRenewalEndpoints
{
    /// <summary>
    /// Map the renewal endpoints. Wire the required services in DI first:
    /// ICertificateRepository, IPolicyRepository, IAttemptRepository,
    /// IApprovalRepository (for approval mode), RenewalEngine, RenewalOptions,
    /// IActorResolver.
    ///
    ///   GET    tenants/{t}/certificates/{c}/renewal            policy + last 10 attempts
    ///   PUT    tenants/{t}/certificates/{c}/renewal/enable
    ///   PUT    tenants/{t}/certificates/{c}/renewal/disable
    ///   PATCH  tenants/{t}/certificates/{c}/renewal
    ///   GET    tenants/{t}/certificates/{c}/renewal/attempts
    ///   POST   tenants/{t}/certificates/{c}/renewal/trigger    (202 when awaiting approval)
    ///   GET    tenants/{t}/renewal-approvals
    ///   POST   tenants/{t}/renewal-approvals/{id}/approve
    ///   POST   tenants/{t}/renewal-approvals/{id}/reject
    /// </summary>
    public static IEndpointRouteBuilder MapCertRenewalEndpoints(
        this IEndpointRouteBuilder routes, string prefix = "/api/v1")
    {
        var group = routes.MapGroup(prefix).WithTags("certificate-renewal");
        var certBase = "tenants/{tenantId}/certificates/{certId}/renewal";

        group.MapGet(certBase, async (
            string tenantId, string certId, HttpContext http,
            ICertificateRepository certs, IPolicyRepository policies,
            IAttemptRepository attempts, RenewalOptions options, IActorResolver auth,
            CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var cert = await certs.GetAsync(tenantId, certId, ct);
            if (cert is null) return Results.NotFound();
            var policy = await policies.GetAsync(tenantId, certId, ct)
                ?? new RenewalPolicy
                {
                    TenantId = tenantId,
                    CertificateId = certId,
                    RenewalWindowDays = options.DefaultRenewalWindowDays,
                };
            var recent = await attempts.ListForCertificateAsync(tenantId, certId, 10, ct);
            return Results.Ok(new RenewalStateDto(
                PolicyDto.From(policy, options, cert),
                recent.Select(AttemptDto.From).ToList()));
        });

        group.MapPut(certBase + "/enable", async (
            string tenantId, string certId, EnableRequest body, HttpContext http,
            ICertificateRepository certs, IPolicyRepository policies,
            RenewalOptions options, IActorResolver auth, TimeProvider time,
            CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var actor = auth.ResolveActor(http)!;
            var cert = await certs.GetAsync(tenantId, certId, ct);
            if (cert is null) return Results.NotFound();
            RenewalMode? mode = body.RenewalMode is null
                ? null
                : ParseMode(body.RenewalMode);
            if (body.RenewalMode is not null && mode is null)
                return Results.BadRequest(new { detail = "renewalMode must be 'automatic' or 'approval_required'" });
            var policy = PolicyGuard.EnableAutoRenewal(
                await policies.GetAsync(tenantId, certId, ct),
                cert, actor, time.GetUtcNow(), body.RenewalWindowDays, mode, options);
            await policies.SaveAsync(policy, ct);
            return Results.Ok(PolicyDto.From(policy, options, cert));
        });

        group.MapPut(certBase + "/disable", async (
            string tenantId, string certId, HttpContext http,
            ICertificateRepository certs, IPolicyRepository policies,
            RenewalOptions options, IActorResolver auth, TimeProvider time,
            CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var actor = auth.ResolveActor(http)!;
            var cert = await certs.GetAsync(tenantId, certId, ct);
            if (cert is null) return Results.NotFound();
            var policy = await policies.GetAsync(tenantId, certId, ct);
            if (policy is null) return Results.NotFound(new { detail = "No renewal policy exists" });
            PolicyGuard.DisableAutoRenewal(policy, actor, time.GetUtcNow());
            await policies.SaveAsync(policy, ct);
            return Results.Ok(PolicyDto.From(policy, options, cert));
        });

        group.MapPatch(certBase, async (
            string tenantId, string certId, PatchRequest body, HttpContext http,
            ICertificateRepository certs, IPolicyRepository policies,
            RenewalOptions options, IActorResolver auth, TimeProvider time,
            CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var cert = await certs.GetAsync(tenantId, certId, ct);
            if (cert is null) return Results.NotFound();
            var policy = await policies.GetAsync(tenantId, certId, ct);
            if (policy is null) return Results.NotFound(new { detail = "No renewal policy exists" });
            if (body.RenewalWindowDays is int w)
            {
                if (w is < 1 or > 365)
                    return Results.BadRequest(new { detail = "renewalWindowDays must be 1..365" });
                policy.RenewalWindowDays = w;
            }
            if (body.RenewalMode is not null)
            {
                var mode = ParseMode(body.RenewalMode);
                if (mode is null)
                    return Results.BadRequest(new { detail = "renewalMode must be 'automatic' or 'approval_required'" });
                policy.RenewalMode = mode.Value;
            }
            if (body.DryRunOverride is not null) policy.DryRunOverride = body.DryRunOverride;
            if (body.MaxAttempts is not null) policy.MaxAttempts = body.MaxAttempts;
            if (body.RetryIntervalMinutes is not null) policy.RetryIntervalMinutes = body.RetryIntervalMinutes;
            policy.UpdatedAt = time.GetUtcNow();
            await policies.SaveAsync(policy, ct);
            return Results.Ok(PolicyDto.From(policy, options, cert));
        });

        group.MapGet(certBase + "/attempts", async (
            string tenantId, string certId, HttpContext http, int? limit,
            ICertificateRepository certs, IAttemptRepository attempts,
            IActorResolver auth, CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            if (await certs.GetAsync(tenantId, certId, ct) is null) return Results.NotFound();
            var rows = await attempts.ListForCertificateAsync(
                tenantId, certId, Math.Min(limit ?? 50, 200), ct);
            return Results.Ok(rows.Select(AttemptDto.From).ToList());
        });

        group.MapPost(certBase + "/trigger", async (
            string tenantId, string certId, HttpContext http,
            RenewalEngine engine, IActorResolver auth, CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var actor = auth.ResolveActor(http)!;
            try
            {
                var attempt = await engine.RenewCertificateAsync(
                    tenantId, certId, $"api:{actor}", force: true, ct: ct);
                return Results.Ok(AttemptDto.From(attempt));
            }
            catch (OptInRequiredException ex) { return Results.Conflict(new { detail = ex.Message }); }
            catch (TenantScopeException ex) { return Results.NotFound(new { detail = ex.Message }); }
            catch (RenewalSkippedException ex)
            {
                return Results.Json(new { detail = ex.Message }, statusCode: StatusCodes.Status429TooManyRequests);
            }
            catch (ApprovalPendingException ex)
            {
                // Not an error: the renewal now awaits a human decision.
                return Results.Accepted(value: new
                {
                    detail = ex.Message,
                    approval = ex.Approval is null ? null : ApprovalDto.From(ex.Approval),
                });
            }
        });

        // ---- Approvals (ApprovalRequired mode) ----

        group.MapGet("tenants/{tenantId}/renewal-approvals", async (
            string tenantId, HttpContext http,
            IApprovalRepository approvals, IActorResolver auth, CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var pending = await approvals.ListPendingForTenantAsync(tenantId, ct);
            return Results.Ok(pending.Select(ApprovalDto.From).ToList());
        });

        group.MapPost("tenants/{tenantId}/renewal-approvals/{approvalId}/approve", async (
            string tenantId, string approvalId, ApprovalDecision body, HttpContext http,
            RenewalEngine engine, IActorResolver auth, CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var actor = auth.ResolveActor(http)!;
            try
            {
                var attempt = await engine.ApproveRenewalAsync(tenantId, approvalId, actor, body.Notes, ct);
                return Results.Ok(AttemptDto.From(attempt));
            }
            catch (TenantScopeException ex) { return Results.NotFound(new { detail = ex.Message }); }
            catch (OptInRequiredException ex) { return Results.Conflict(new { detail = ex.Message }); }
            catch (RenewalSkippedException ex) { return Results.Conflict(new { detail = ex.Message }); }
        });

        group.MapPost("tenants/{tenantId}/renewal-approvals/{approvalId}/reject", async (
            string tenantId, string approvalId, ApprovalDecision body, HttpContext http,
            RenewalEngine engine, IActorResolver auth, CancellationToken ct) =>
        {
            if (Authenticate(http, auth, tenantId) is { } failure) return failure;
            var actor = auth.ResolveActor(http)!;
            try
            {
                var approval = await engine.RejectRenewalAsync(tenantId, approvalId, actor, body.Notes, ct);
                return Results.Ok(ApprovalDto.From(approval));
            }
            catch (TenantScopeException ex) { return Results.NotFound(new { detail = ex.Message }); }
            catch (RenewalSkippedException ex) { return Results.Conflict(new { detail = ex.Message }); }
        });

        return routes;
    }

    private static IResult? Authenticate(HttpContext http, IActorResolver auth, string tenantId)
    {
        var actor = auth.ResolveActor(http);
        if (actor is null)
            return Results.Unauthorized();
        if (!auth.AuthorizeTenant(http, actor, tenantId))
            return Results.Forbid();
        return null;
    }

    private static RenewalMode? ParseMode(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "automatic" => RenewalMode.Automatic,
        "approval_required" => RenewalMode.ApprovalRequired,
        _ => null,
    };
}
