namespace CertRenewal.Core;

/// <summary>
/// Engine configuration. Bind from IConfiguration (section "CertRenewal") or
/// build from environment variables via FromEnvironment(). Safety defaults:
///
///   * DryRun defaults to true — nothing mutates real certificates until
///     CERT_RENEWAL_DRY_RUN=false (and even then, per-tenant and per-policy
///     overrides can keep dry-run on).
///   * DefaultRenewalWindowDays = 30, matching the product's
///     "expiring &lt;= 30 days" counter.
/// </summary>
public sealed class RenewalOptions
{
    public const string SectionName = "CertRenewal";

    /// <summary>Global dry-run switch. True (safe) unless explicitly disabled.</summary>
    public bool DryRun { get; set; } = true;

    /// <summary>Tenants forced into dry-run even when the global switch is off.</summary>
    public HashSet<string> DryRunTenants { get; set; } = [];

    public int DefaultRenewalWindowDays { get; set; } = 30;
    public int MaxAttempts { get; set; } = 3;
    /// <summary>Cooldown between retries within a cycle. Default 6h.</summary>
    public int RetryIntervalMinutes { get; set; } = 360;

    // ACME
    public string AcmeDirectoryUrl { get; set; } =
        "https://acme-v02.api.letsencrypt.org/directory";
    public string? AcmeContactEmail { get; set; }

    /// <summary>Blast-radius guard for early rollouts: how many certs a single
    /// scheduler sweep may attempt per tenant. 0 = unlimited.</summary>
    public int MaxRenewalsPerSweep { get; set; }

    public TimeSpan RetryInterval => TimeSpan.FromMinutes(RetryIntervalMinutes);

    public static RenewalOptions FromEnvironment()
    {
        static bool EnvBool(string name, bool fallback)
        {
            var raw = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrWhiteSpace(raw)) return fallback;
            return raw.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
        }

        static int EnvInt(string name, int fallback) =>
            int.TryParse(Environment.GetEnvironmentVariable(name), out var v) ? v : fallback;

        var tenants = Environment.GetEnvironmentVariable("CERT_RENEWAL_DRY_RUN_TENANTS") ?? "";
        return new RenewalOptions
        {
            DryRun = EnvBool("CERT_RENEWAL_DRY_RUN", true),
            DryRunTenants = tenants
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(),
            DefaultRenewalWindowDays = EnvInt("CERT_RENEWAL_WINDOW_DAYS", 30),
            MaxAttempts = EnvInt("CERT_RENEWAL_MAX_ATTEMPTS", 3),
            RetryIntervalMinutes = EnvInt("CERT_RENEWAL_RETRY_INTERVAL_MINUTES", 360),
            AcmeDirectoryUrl =
                Environment.GetEnvironmentVariable("CERT_RENEWAL_ACME_DIRECTORY")
                ?? "https://acme-v02.api.letsencrypt.org/directory",
            AcmeContactEmail =
                Environment.GetEnvironmentVariable("CERT_RENEWAL_ACME_CONTACT"),
            MaxRenewalsPerSweep = EnvInt("CERT_RENEWAL_MAX_PER_SWEEP", 0),
        };
    }
}
