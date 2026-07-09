namespace CertRenewal.Core.Models;

/// <summary>Where the certificate lives — mirrors the Source column on the
/// Certificates page (Azure vs External), split by Azure resource type.</summary>
public enum CertSource
{
    /// <summary>Microsoft.KeyVault/vaults certificate.</summary>
    KeyVault,
    /// <summary>Microsoft.Web/certificates.</summary>
    AppService,
    /// <summary>Discovered/imported cert not managed in Azure.</summary>
    External,
}

/// <summary>How a renewal is executed. Selected from the cert's source + issuer.</summary>
public enum RenewalMethod
{
    KeyVault,
    AppService,
    Acme,
    Manual,
}

public enum AttemptStatus
{
    Pending,
    InProgress,
    Succeeded,
    Failed,
    ManualRequired,
}

/// <summary>How an opted-in certificate is renewed. Only meaningful once
/// AutoRenewEnabled is true — a disabled policy is never renewed at all.</summary>
public enum RenewalMode
{
    /// <summary>The sweep renews with no human in the loop.</summary>
    Automatic,
    /// <summary>The sweep creates a RenewalApproval; renewal runs only after
    /// a user approves it (once per expiry window).</summary>
    ApprovalRequired,
}

public enum ApprovalStatus
{
    Pending,
    Approved,
    Rejected,
}

public static class AttemptStatusExtensions
{
    public static bool IsTerminal(this AttemptStatus status) =>
        status is AttemptStatus.Succeeded or AttemptStatus.Failed or AttemptStatus.ManualRequired;
}
