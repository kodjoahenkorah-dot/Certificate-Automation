using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme;
using CertRenewal.Core.Models;
using CertRenewal.Core.Providers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertRenewal.Acme;

/// <summary>Proves control of a domain for one ACME challenge.</summary>
public interface IChallengeSolver
{
    /// <summary>"dns-01" or "http-01".</summary>
    string ChallengeType { get; }

    /// <summary>For DNS-01: create the _acme-challenge TXT record with
    /// <paramref name="dnsTxtValue"/>. For HTTP-01: serve
    /// <paramref name="keyAuthorization"/> at /.well-known/acme-challenge/&lt;token&gt;.</summary>
    Task SetupAsync(string domain, string token, string keyAuthorization, string dnsTxtValue, CancellationToken ct = default);

    Task CleanupAsync(string domain, string token, CancellationToken ct = default);

    TimeSpan PropagationWait => ChallengeType == "dns-01" ? TimeSpan.FromSeconds(30) : TimeSpan.Zero;
}

/// <summary>Installs issued PEM material where traffic terminates (e.g.
/// imports into Key Vault, pushes to a CDN, updates an App Gateway listener).</summary>
public interface ICertificateInstaller
{
    Task InstallAsync(Certificate cert, byte[] fullchainPem, byte[] privateKeyPem, CancellationToken ct = default);
}

/// <summary>
/// ACME renewal provider (Let's Encrypt / ZeroSSL / any RFC 8555 CA).
///
/// The engine routes an External cert here only when its issuer is an ACME CA
/// (see RenewalEngine.AcmeAutomatableIssuers); paid-CA certs never reach this
/// provider. Even so, this provider needs a challenge solver to prove domain
/// control and an installer to put the issued cert where traffic terminates —
/// both deployment-specific, both ports. If either is missing, the provider
/// reports ManualRequired instead of failing, and the engine's fallback
/// creates a Work Item.
///
/// Dry run: no ACME order is placed, no DNS records are written. The provider
/// reports the exact plan (directory, domains, challenge type).
/// </summary>
public sealed class AcmeRenewalProvider(
    IChallengeSolver? solver = null,
    ICertificateInstaller? installer = null,
    ILogger<AcmeRenewalProvider>? logger = null) : IRenewalProvider
{
    private readonly ILogger _log = logger ?? NullLogger<AcmeRenewalProvider>.Instance;

    public async Task<RenewalResult> RenewAsync(
        Certificate cert, ProviderContext ctx, CancellationToken ct = default)
    {
        var domains = cert.Domains.Count > 0
            ? cert.Domains.ToList()
            : cert.Name.Contains('.') ? [cert.Name] : new List<string>();

        if (domains.Count == 0)
            return new RenewalResult
            {
                Status = AttemptStatus.Failed,
                Error = "Certificate row has no domains; cannot build an ACME order.",
            };
        if (solver is null)
            return new RenewalResult
            {
                Status = AttemptStatus.ManualRequired,
                Detail = "No ACME challenge solver is configured for this deployment, so domain control " +
                         "cannot be proven automatically. Renew manually or configure a DNS-01/HTTP-01 solver.",
            };
        if (installer is null)
            return new RenewalResult
            {
                Status = AttemptStatus.ManualRequired,
                Detail = "No ICertificateInstaller is configured; an ACME cert could be issued but not " +
                         "installed anywhere. Configure an installer (e.g. Key Vault import) before " +
                         "enabling live ACME renewals.",
            };
        var wildcards = domains.Where(d => d.StartsWith("*.")).ToList();
        if (wildcards.Count > 0 && solver.ChallengeType != "dns-01")
            return new RenewalResult
            {
                Status = AttemptStatus.ManualRequired,
                Detail = $"Wildcard domains ({string.Join(", ", wildcards)}) require DNS-01, " +
                         $"but the configured solver is {solver.ChallengeType}.",
            };

        if (ctx.DryRun)
            return new RenewalResult
            {
                Status = AttemptStatus.Succeeded,
                Detail = $"DRY RUN: would order a certificate for {string.Join(", ", domains)} from " +
                         $"{ctx.Options.AcmeDirectoryUrl} using {solver.ChallengeType}, then install via " +
                         $"{installer.GetType().Name}. No ACME order placed, no DNS/HTTP changes made.",
            };

        return await IssueAsync(cert, domains, ctx, ct);
    }

    private async Task<RenewalResult> IssueAsync(
        Certificate cert, List<string> domains, ProviderContext ctx, CancellationToken ct)
    {
        // Account key: per-tenant if provided, else ephemeral registration.
        var acme = ctx.AcmeAccountKeyPem is { } pem
            ? new AcmeContext(new Uri(ctx.Options.AcmeDirectoryUrl),
                KeyFactory.FromPem(Encoding.UTF8.GetString(pem)))
            : new AcmeContext(new Uri(ctx.Options.AcmeDirectoryUrl));

        if (ctx.AcmeAccountKeyPem is null)
            await acme.NewAccount(ctx.Options.AcmeContactEmail ?? "admin@" + domains[0].TrimStart('*', '.'), true);
        else
            await acme.Account(); // bind existing account for this key

        var order = await acme.NewOrder(domains);
        var solved = new List<(string Domain, string Token)>();
        try
        {
            foreach (var authz in await order.Authorizations())
            {
                var resource = await authz.Resource();
                var domain = resource.Identifier.Value;
                if (solver!.ChallengeType == "dns-01")
                {
                    var challenge = await authz.Dns()
                        ?? throw new InvalidOperationException($"CA offered no dns-01 challenge for {domain}.");
                    var txt = acme.AccountKey.DnsTxt(challenge.Token);
                    await solver.SetupAsync(domain, challenge.Token, challenge.KeyAuthz, txt, ct);
                    solved.Add((domain, challenge.Token));
                }
                else
                {
                    var challenge = await authz.Http()
                        ?? throw new InvalidOperationException($"CA offered no http-01 challenge for {domain}.");
                    await solver.SetupAsync(domain, challenge.Token, challenge.KeyAuthz, "", ct);
                    solved.Add((domain, challenge.Token));
                }
            }

            if (solver!.PropagationWait > TimeSpan.Zero)
                await Task.Delay(solver.PropagationWait, ct);

            foreach (var authz in await order.Authorizations())
            {
                var challenge = solver.ChallengeType == "dns-01" ? await authz.Dns() : await authz.Http();
                await challenge!.Validate();
            }

            var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var chain = await order.Generate(new CsrInfo(), privateKey);

            var fullchainPem = Encoding.UTF8.GetBytes(chain.ToPem());
            var keyPem = Encoding.UTF8.GetBytes(privateKey.ToPem());
            await installer!.InstallAsync(cert, fullchainPem, keyPem, ct);

            using var leaf = new X509Certificate2(chain.Certificate.ToDer());
            var expires = new DateTimeOffset(leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            _log.LogInformation("[tenant={Tenant}] ACME renewal for {Domains} succeeded; new expiry {Expiry}",
                ctx.TenantId, string.Join(",", domains), expires);
            return new RenewalResult
            {
                Status = AttemptStatus.Succeeded,
                NewExpiresAt = expires,
                NewThumbprint = leaf.Thumbprint,
                Detail = $"Issued by {ctx.Options.AcmeDirectoryUrl} and installed via {installer.GetType().Name}.",
            };
        }
        finally
        {
            foreach (var (domain, token) in solved)
            {
                try { await solver!.CleanupAsync(domain, token, ct); }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to clean up challenge record for {Domain}", domain);
                }
            }
        }
    }
}
