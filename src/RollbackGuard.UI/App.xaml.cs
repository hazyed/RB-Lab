using System.Windows;
using RollbackGuard.Common.Diagnostics;
using RollbackGuard.Common.Runtime;

namespace RollbackGuard.UI;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        try
        {
            RuntimePaths.EnsureAll();
            StartupLog.Write("UI", "startup begin");

            DispatcherUnhandledException += (_, args) =>
            {
                StartupLog.Write("UI", "dispatcher unhandled exception", args.Exception);
                MessageBox.Show(
                    $"UI 发生未处理异常:\n{args.Exception.Message}\n\n日志: {RuntimePaths.StartupLogPath}",
                    "RollbackGuard.UI",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                args.Handled = true;
                Shutdown(-1);
            };

            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                if (args.ExceptionObject is Exception ex)
                {
                    StartupLog.Write("UI", "appdomain unhandled exception", ex);
                }
                else
                {
                    StartupLog.Write("UI", "appdomain unhandled exception: non-exception object");
                }
            };

            TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                StartupLog.Write("UI", "task unobserved exception", args.Exception);
                args.SetObserved();
            };

            base.OnStartup(e);
        }
        catch (Exception ex)
        {
            StartupLog.Write("UI", "startup fatal", ex);
            MessageBox.Show(
                $"UI 启动失败:\n{ex.Message}\n\n日志: {RuntimePaths.StartupLogPath}",
                "RollbackGuard.UI",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(-1);
        }
    }
}
