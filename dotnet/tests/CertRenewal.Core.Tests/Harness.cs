using CertRenewal.Core;
using CertRenewal.Core.Models;
using CertRenewal.Core.Providers;

namespace CertRenewal.Core.Tests;

/// <summary>Shared fixtures: in-memory repos, fake providers, frozen clock.
/// No Azure/ACME/ASP.NET dependencies — the engine and policy layers are pure.</summary>
public sealed class Harness
{
    public static readonly DateTimeOffset Now = new(2026, 7, 8, 12, 0, 0, TimeSpan.Zero);

    public FrozenTimeProvider Clock { get; } = new(Now);
    public InMemoryCertificateRepository Certs { get; } = new();
    public InMemoryPolicyRepository Policies { get; } = new();
    public InMemoryAttemptRepository Attempts { get; } = new();
    public InMemoryApprovalRepository Approvals { get; } = new();
    public RecordingWorkItemSink WorkItems { get; } = new();
    public RecordingNotifier Notifier { get; } = new();
    public FakeCredentials Credentials { get; } = new();
    public FakeProvider KeyVaultProvider { get; } = new();

    // Live mode by default in tests so dry-run behavior is opted into
    // explicitly by the tests that cover it.
    public RenewalOptions Options { get; } = new()
    {
        DryRun = false,
        RetryIntervalMinutes = 60,
        MaxAttempts = 3,
    };

    public RenewalEngine Engine => _engine ??= new RenewalEngine(
        Certs, Policies, Attempts,
        new Dictionary<RenewalMethod, IRenewalProvider>
        {
            [RenewalMethod.KeyVault] = KeyVaultProvider,
            [RenewalMethod.AppService] = new FakeProvider(),
            [RenewalMethod.Acme] = new FakeProvider(),
            [RenewalMethod.Manual] = new ManualFallbackProvider(WorkItems, Clock),
        },
        Credentials, Notifier, WorkItems, Approvals, Options, Clock);

    private RenewalEngine? _engine;

    public static Certificate MakeCert(
        string certId = "cert-1",
        string tenantId = "tenant-a",
        CertSource source = CertSource.KeyVault,
        double daysToExpiry = 10,
        string? issuer = "GlobalSign GCC R3",
        string? ownerEmail = "owner@anadata.com") => new()
    {
        Id = certId,
        TenantId = tenantId,
        Name = $"cert-{certId}",
        Source = source,
        ExpiresAt = Now.AddDays(daysToExpiry),
        Domains = ["example.anadata.com"],
        Thumbprint = "00FFAA",
        Issuer = issuer,
        OwnerEmail = ownerEmail,
        KeyVaultUrl = "https://kv.vault.azure.net",
        KeyVaultCertName = "kv-cert",
    };

    public async Task<RenewalPolicy> OptInAsync(
        Certificate cert, string actor = "alice@anadata.com",
        int? windowDays = null, RenewalMode? mode = null)
    {
        var policy = PolicyGuard.EnableAutoRenewal(
            await Policies.GetAsync(cert.TenantId, cert.Id),
            cert, actor, Now, windowDays, mode, Options);
        await Policies.SaveAsync(policy);
        return policy;
    }
}

public sealed class FrozenTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; private set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>Scripted provider that records every call it receives.</summary>
public sealed class FakeProvider : IRenewalProvider
{
    public RenewalResult Result { get; set; } = new()
    {
        Status = AttemptStatus.Succeeded,
        NewExpiresAt = Harness.Now.AddDays(365),
        NewThumbprint = "AA11BB22CC33",
    };

    public List<(Certificate Cert, ProviderContext Ctx)> Calls { get; } = [];
    public Exception? ThrowOnRenew { get; set; }
    public string? VerifyError { get; set; }
    public int VerifyCalls { get; private set; }

    public Task<RenewalResult> RenewAsync(Certificate cert, ProviderContext ctx, CancellationToken ct = default)
    {
        Calls.Add((cert, ctx));
        if (ThrowOnRenew is not null) throw ThrowOnRenew;
        return Task.FromResult(Result);
    }

    public Task<string?> VerifyAsync(Certificate cert, RenewalResult result, ProviderContext ctx, CancellationToken ct = default)
    {
        VerifyCalls++;
        return Task.FromResult(VerifyError);
    }
}

public sealed class FakeCredentials : ITenantCredentialResolver
{
    public List<string> RequestedTenants { get; } = [];

    public Task<object> GetAzureCredentialAsync(string tenantId, CancellationToken ct = default)
    {
        RequestedTenants.Add(tenantId);
        return Task.FromResult<object>($"credential-for-{tenantId}");
    }

    public Task<string?> GetAzureSubscriptionIdAsync(string tenantId, CancellationToken ct = default) =>
        Task.FromResult<string?>($"sub-{tenantId}");
}

public sealed class RecordingNotifier : INotifier
{
    public List<(Certificate, RenewalAttempt)> Succeeded { get; } = [];
    public List<(Certificate, RenewalAttempt)> Failed { get; } = [];
    public List<(Certificate, RenewalAttempt)> Manual { get; } = [];
    public Exception? ThrowOnSuccess { get; set; }

    public Task RenewalSucceededAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default)
    {
        if (ThrowOnSuccess is not null) throw ThrowOnSuccess;
        Succeeded.Add((cert, attempt));
        return Task.CompletedTask;
    }

    public Task RenewalFailedAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default)
    {
        Failed.Add((cert, attempt));
        return Task.CompletedTask;
    }

    public Task ManualActionRequiredAsync(Certificate cert, RenewalAttempt attempt, CancellationToken ct = default)
    {
        Manual.Add((cert, attempt));
        return Task.CompletedTask;
    }
}

public sealed class RecordingWorkItemSink : IWorkItemSink
{
    public List<WorkItemRequest> Created { get; } = [];

    public Task<string> CreateAsync(WorkItemRequest request, CancellationToken ct = default)
    {
        Created.Add(request);
        return Task.FromResult($"wi-{Created.Count}");
    }
}
