namespace CryptEscrow;

/// <summary>
/// Exit codes for Intune proactive remediation compatibility.
/// </summary>
public static class ExitCodes
{
    /// <summary>Key escrowed successfully.</summary>
    public const int Success = 0;
    
    /// <summary>BitLocker is not enabled on the drive.</summary>
    public const int BitLockerNotEnabled = 1;
    
    /// <summary>No recovery password protector found.</summary>
    public const int NoRecoveryProtector = 2;
    
    /// <summary>Network or server error (retry-able).</summary>
    public const int NetworkError = 3;
    
    /// <summary>Configuration error (missing server URL, etc.).</summary>
    public const int ConfigurationError = 4;
    
    /// <summary>Key rotation failed.</summary>
    public const int RotationFailed = 5;
    
    /// <summary>Insufficient permissions (requires administrator).</summary>
    public const int PermissionDenied = 6;
    
    /// <summary>Authentication failed (invalid or missing API key).</summary>
    public const int AuthenticationError = 7;
    
    /// <summary>Key already escrowed, no action needed.</summary>
    public const int AlreadyEscrowed = 10;
}
