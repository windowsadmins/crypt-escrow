namespace CryptEscrow.Gui;

/// <summary>The fixed operations the app's Run tab offers. Each maps to one CLI command.</summary>
public enum RunMode
{
    /// <summary>Escrow the current recovery key now, ignoring the escrow interval.</summary>
    EscrowNow,

    /// <summary>Check the server holds this device's current key. Changes nothing.</summary>
    Verify,

    /// <summary>Create a new recovery key, escrow it, then remove the old ones if the setting says so.</summary>
    RotateKey
}

public static class RunModes
{
    public static IReadOnlyList<RunMode> All { get; } = [RunMode.EscrowNow, RunMode.Verify, RunMode.RotateKey];

    public static string Label(RunMode mode) => mode switch
    {
        RunMode.EscrowNow => "Escrow now",
        RunMode.Verify => "Verify escrow",
        RunMode.RotateKey => "Rotate key",
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };

    public static string Description(RunMode mode) => mode switch
    {
        RunMode.EscrowNow => "Send this device's current recovery key to the server now.",
        RunMode.Verify => "Check that the server holds this device's current recovery key. Changes nothing.",
        RunMode.RotateKey => "Create a new recovery key, escrow it, and then remove the old keys if \"Remove old recovery keys after rotation\" is on.",
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };

    /// <summary>Rotation replaces the recovery key, so the app asks before running it.</summary>
    public static bool NeedsConfirmation(RunMode mode) => mode == RunMode.RotateKey;

    /// <summary>
    /// The CLI arguments for <paramref name="mode"/>. Nothing configurable goes on the
    /// command line: the run reads its settings from policy and machine settings, as the
    /// scheduled task does. Rotation passes the cleanup setting explicitly because the
    /// CLI's own default for <c>rotate</c> is to clean up.
    /// </summary>
    public static IReadOnlyList<string> Arguments(RunMode mode, bool cleanupOldProtectors) => mode switch
    {
        RunMode.EscrowNow => ["escrow", "--force"],
        RunMode.Verify => ["verify"],
        RunMode.RotateKey => ["rotate", "--cleanup", cleanupOldProtectors ? "true" : "false"],
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };
}
