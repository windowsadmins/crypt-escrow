using System.Runtime.InteropServices;
using CryptEscrow.Gui;

namespace CryptEscrow.App.Services;

/// <summary>
/// Reads the state of the tool's scheduled task from the Task Scheduler, through its COM
/// API. Read-only, and needs no elevation: a task the user cannot read shows as Unknown.
/// </summary>
public static class ComponentStatusReader
{
    private const int FileNotFound = unchecked((int)0x80070002);
    private const int PathNotFound = unchecked((int)0x80070003);

    public static Task<IReadOnlyList<ComponentStatus>> ReadAllAsync() =>
        Task.Run<IReadOnlyList<ComponentStatus>>(() => InstalledComponents.All.Select(Read).ToList());

    private static ComponentStatus Read(InstalledComponent component) =>
        component.Kind == ComponentKind.ScheduledTask
            ? ReadTask(component)
            // The installer creates no services; there is nothing to query.
            : InstalledComponents.Unknown(component);

    private static ComponentStatus ReadTask(InstalledComponent component)
    {
        dynamic? scheduler = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
                return InstalledComponents.Unknown(component);

            scheduler = Activator.CreateInstance(type)!;
            scheduler.Connect();
            dynamic task = scheduler.GetFolder("\\").GetTask(component.Name);

            int state = task.State;
            DateTime lastRun = task.LastRunTime;
            int result = task.LastTaskResult;
            string xml = task.Xml;

            return new ComponentStatus(
                component,
                InstalledComponents.TaskStateWords(state),
                InstalledComponents.TaskResultWords(result, lastRun),
                InstalledComponents.TriggersToWords(xml));
        }
        catch (COMException ex) when (ex.HResult is FileNotFound or PathNotFound)
        {
            return InstalledComponents.NotInstalled(component);
        }
        catch (Exception)
        {
            // Access denied, or the scheduler is unavailable.
            return InstalledComponents.Unknown(component);
        }
        finally
        {
            if (scheduler is not null && Marshal.IsComObject(scheduler))
                Marshal.FinalReleaseComObject(scheduler);
        }
    }
}
