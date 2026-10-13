using CryptEscrow.Gui;

namespace CryptEscrow.App;

/// <summary>
/// The entry point. Normally starts the app; with <c>--apply-settings &lt;pipe&gt;</c> it is the
/// elevated copy Save starts, which writes the pending settings and exits without a window.
/// </summary>
public static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (PrefsElevation.ApplySettingsPipe(args) is { } pipe)
            return SettingsApply.RunFromPipe(pipe);

        WinRT.ComWrappersSupport.InitializeComWrappers();
        Microsoft.UI.Xaml.Application.Start(p =>
        {
            var context = new Microsoft.UI.Dispatching.DispatcherQueueSynchronizationContext(
                Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread());
            SynchronizationContext.SetSynchronizationContext(context);
            _ = new App();
        });
        return 0;
    }
}
