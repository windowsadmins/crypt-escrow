namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Snapshots the values of a set of environment variables on construction and
/// restores them on dispose. Use in tests that need to set env vars without
/// leaking state into other tests.
/// </summary>
internal sealed class EnvironmentSnapshot : IDisposable
{
    private readonly Dictionary<string, string?> _saved = new();

    public EnvironmentSnapshot(params string[] names)
    {
        foreach (var name in names)
        {
            _saved[name] = Environment.GetEnvironmentVariable(name);
            // Start each test with the var cleared so it's explicit when a test sets it.
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    public void Set(string name, string? value)
    {
        if (!_saved.ContainsKey(name))
            _saved[name] = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
    }

    public void Dispose()
    {
        foreach (var (name, value) in _saved)
            Environment.SetEnvironmentVariable(name, value);
    }
}
