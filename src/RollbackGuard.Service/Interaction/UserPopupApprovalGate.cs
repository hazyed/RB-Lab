using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using RollbackGuard.Common.Models;
using RollbackGuard.Common.Threats;
using RollbackGuard.Service.Rollback;
using System.Diagnostics;

namespace RollbackGuard.Service.Interaction;

public sealed class UserPopupApprovalGate : IUserApprovalGate
{
    private static int _visualStylesInitialized;
    private static readonly IntPtr HwndTopMost = new(-1);
    private const uint SwpNoSize = 0x0001;
    private const uint SwpNoMove = 0x0002;
    private const uint SwpShowWindow = 0x0040;
    private const int SwShowNormal = 1;
    private static readonly TimeSpan EnforcementDialogTimeout = TimeSpan.Zero;
    private static readonly TimeSpan RollbackDialogTimeout = TimeSpan.Zero;

    public EnforcementChoice RequestEnforcement(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        string containmentSummary,
        int pendingRollbackEntries,
        out string auditMessage)
    {
        if (!Environment.UserInteractive)
        {
            auditMessage = $"user-approval skipped: non-interactive session; enforce pid={telemetryEvent.ProcessId}";
            return EnforcementChoice.Ignore;
        }

        try
        {
            var result = ShowOnStaThread(
                () => BuildEnforcementForm(telemetryEvent, decision, containmentSummary, pendingRollbackEntries),
                EnforcementDialogTimeout,
                DialogResult.Cancel,
                out var timedOut);

            var choice = result == DialogResult.OK
                ? EnforcementChoice.Terminate
                : EnforcementChoice.Ignore;

            if (timedOut)
            {
                auditMessage = $"user-approval timeout enforce pid={telemetryEvent.ProcessId}; default={(choice == EnforcementChoice.Terminate ? "terminate" : "ignore")}";
            }
            else
            {
                auditMessage = choice == EnforcementChoice.Terminate
                    ? $"user-approved enforce=terminate pid={telemetryEvent.ProcessId}"
                    : $"user-denied enforce=ignore pid={telemetryEvent.ProcessId}";
            }

            return choice;
        }
        catch (Exception ex)
        {
            auditMessage = $"user-approval failed enforce pid={telemetryEvent.ProcessId}: {ex.Message}";
            return EnforcementChoice.Ignore;
        }
    }

    public RollbackChoice RequestRollback(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        IReadOnlyList<string> rollbackPreview,
        int pendingRollbackEntries,
        out string auditMessage)
    {
        if (!Environment.UserInteractive)
        {
            auditMessage = $"user-approval skipped: non-interactive session; rollback pid={telemetryEvent.ProcessId}";
            return RollbackChoice.Skip;
        }

        try
        {
            var result = ShowOnStaThread(
                () => BuildRollbackForm(telemetryEvent, decision, rollbackPreview, pendingRollbackEntries),
                RollbackDialogTimeout,
                DialogResult.Cancel,
                out var timedOut);

            var choice = result == DialogResult.OK
                ? RollbackChoice.Rollback
                : RollbackChoice.Skip;

            if (timedOut)
            {
                auditMessage = $"user-approval timeout rollback pid={telemetryEvent.ProcessId}; default={(choice == RollbackChoice.Rollback ? "rollback" : "skip")}";
            }
            else
            {
                auditMessage = choice == RollbackChoice.Rollback
                    ? $"user-approved rollback pid={telemetryEvent.ProcessId} entries={pendingRollbackEntries}"
                    : $"user-denied rollback pid={telemetryEvent.ProcessId} entries={pendingRollbackEntries}";
            }

            return choice;
        }
        catch (Exception ex)
        {
            auditMessage = $"user-approval failed rollback pid={telemetryEvent.ProcessId}: {ex.Message}";
            return RollbackChoice.Skip;
        }
    }

    public void ShowRollbackResult(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        int requestedEntries,
        RollbackExecutionResult result)
    {
        if (!Environment.UserInteractive)
        {
            return;
        }

        try
        {
            ShowOnStaThreadNonBlocking(() => BuildRollbackResultForm(telemetryEvent, decision, requestedEntries, result));
        }
        catch
        {
            // result popup failure should never affect main flow
        }
    }

    public void ShowServiceReady(string detailContent)
    {
        if (!Environment.UserInteractive)
        {
            return;
        }

        try
        {
            ShowOnStaThreadNonBlocking(() => BuildServiceReadyForm(detailContent));
        }
        catch
        {
            // startup ready popup failure should never affect main flow
        }
    }

    private static DialogResult ShowOnStaThread(
        Func<Form> formFactory,
        TimeSpan timeout,
        DialogResult timeoutResult,
        out bool timedOut)
    {
        DialogResult result = timeoutResult;
        Exception? error = null;
        var timeoutTriggered = false;
        using var done = new ManualResetEventSlim(false);

        var thread = new Thread(() =>
        {
            System.Windows.Forms.Timer? timeoutTimer = null;
            try
            {
                if (Interlocked.Exchange(ref _visualStylesInitialized, 1) == 0)
                {
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                }

                using var form = formFactory();
                if (timeout > TimeSpan.Zero)
                {
                    var intervalMs = (int)Math.Clamp(timeout.TotalMilliseconds, 1, int.MaxValue);
                    timeoutTimer = new System.Windows.Forms.Timer { Interval = intervalMs };
                    timeoutTimer.Tick += (_, _) =>
                    {
                        timeoutTriggered = true;
                        timeoutTimer.Stop();
                        if (!form.IsDisposed)
                        {
                            form.DialogResult = timeoutResult;
                            form.Close();
                        }
                    };

                    form.Shown += (_, _) => timeoutTimer.Start();
                    form.FormClosed += (_, _) =>
                    {
                        if (timeoutTimer is null)
                        {
                            return;
                        }

                        timeoutTimer.Stop();
                        timeoutTimer.Dispose();
                        timeoutTimer = null;
                    };
                }

                result = form.ShowDialog();
            }
            catch (Exception ex)
            {
                error = ex;
            }
            finally
            {
                timeoutTimer?.Dispose();
                done.Set();
            }
        });

        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        done.Wait();
        timedOut = timeoutTriggered;
        if (error is not null)
        {
            throw new InvalidOperationException("approval dialog failed", error);
        }

        return result;
    }

    private static void ShowOnStaThreadNonBlocking(Func<Form> formFactory)
    {
        var thread = new Thread(() =>
        {
            try
            {
                if (Interlocked.Exchange(ref _visualStylesInitialized, 1) == 0)
                {
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                }

                using var form = formFactory();
                _ = form.ShowDialog();
            }
            catch
            {
                // ignore fire-and-forget popup failures
            }
        });

        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
    }

    private static Form BuildEnforcementForm(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        string containmentSummary,
        int pendingRollbackEntries)
    {
        var processPath = ResolveDisplayProcessPath(telemetryEvent);

        var targetPath = string.IsNullOrWhiteSpace(telemetryEvent.TargetPath)
            ? "(无目标路径)"
            : telemetryEvent.TargetPath;

        var processName = ResolveDisplayProcessName(processPath);

        var reasonLabel = BuildReasonLabel(decision, telemetryEvent);
        var content =
            $"PID: {telemetryEvent.ProcessId}\r\n" +
            $"进程名: {processName}\r\n" +
            $"进程路径: {processPath}\r\n" +
            $"目标: {targetPath}\r\n" +
            $"风险分: {decision.Score}\r\n" +
            $"Reason: {reasonLabel}\r\n" +
            $"待回滚条目: {pendingRollbackEntries}";

        var form = BuildBaseForm(
            "RollbackGuard - 风险处置",
            "检测到高风险行为，请按下方“当前控制状态”核对结果。",
            "请选择处理动作（只有确认“终止进程”后才会真正结束该进程）：",
            string.IsNullOrWhiteSpace(containmentSummary)
                ? content
                : content + "\r\n当前控制状态: " + containmentSummary,
            "终止进程",
            "忽略",
            mouseOnlyDecision: true);

        return form;
    }

    private static Form BuildRollbackForm(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        IReadOnlyList<string> rollbackPreview,
        int pendingRollbackEntries)
    {
        var processPath = ResolveDisplayProcessPath(telemetryEvent);
        var processName = ResolveDisplayProcessName(processPath);

        var reasonLabel = BuildReasonLabel(decision, telemetryEvent);
        var content =
            $"PID: {telemetryEvent.ProcessId}\r\n" +
            $"进程名: {processName}\r\n" +
            $"进程路径: {processPath}\r\n" +
            $"风险分: {decision.Score}\r\n" +
            $"Reason: {reasonLabel}\r\n" +
            $"回滚条目总数: {pendingRollbackEntries}";

        var form = BuildBaseForm(
            "RollbackGuard - 回滚确认",
            "进程已终止，是否执行回滚？",
            "以下是待回滚清单预览（详细规则请在主界面日志查看）：",
            content,
            "回滚",
            "不回滚",
            mouseOnlyDecision: true);

        var previewPanel = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(26, 0, 26, 12),
            BackColor = Color.White
        };

        var list = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Microsoft YaHei UI", 9.5F, FontStyle.Regular),
            BackColor = Color.FromArgb(248, 251, 255)
        };

        list.Columns.Add("序号", 72);
        list.Columns.Add("待回滚目标", 610);

        if (rollbackPreview.Count == 0)
        {
            var row = new ListViewItem("1");
            row.SubItems.Add("(当前没有可回滚条目)");
            list.Items.Add(row);
        }
        else
        {
            var index = 1;
            foreach (var entry in rollbackPreview)
            {
                var row = new ListViewItem(index.ToString());
                row.SubItems.Add(string.IsNullOrWhiteSpace(entry) ? "(空路径)" : entry);
                list.Items.Add(row);
                index++;
            }
        }

        previewPanel.Controls.Add(list);

        var host = form.Tag as TableLayoutPanel;
        if (host is not null)
        {
            host.RowStyles[2] = new RowStyle(SizeType.Percent, 100);
            host.Controls.Add(previewPanel, 0, 2);
        }

        return form;
    }

    private static Form BuildRollbackResultForm(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        int requestedEntries,
        RollbackExecutionResult result)
    {
        var processPath = ResolveDisplayProcessPath(telemetryEvent);
        var processName = ResolveDisplayProcessName(processPath);

        var successCount = result.SuccessItems.Count;
        var failedCount = result.FailedItems.Count;
        var reasonLabel = BuildReasonLabel(decision, telemetryEvent);

        var content =
            $"PID: {telemetryEvent.ProcessId}\r\n" +
            $"进程名: {processName}\r\n" +
            $"进程路径: {processPath}\r\n" +
            $"风险分: {decision.Score}\r\n" +
            $"Reason: {reasonLabel}\r\n" +
            $"请求回滚条目: {requestedEntries}\r\n" +
            $"回滚成功: {successCount}\r\n" +
            $"回滚失败: {failedCount}";

        var form = BuildBaseForm(
            "RollbackGuard - 回滚结果",
            "回滚执行完成",
            "以下是本次回滚成功/失败清单：",
            content,
            "关闭",
            "关闭");

        form.CancelButton = form.AcceptButton;

        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(26, 0, 26, 12),
            BackColor = Color.White
        };

        var tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Font = new Font("Microsoft YaHei UI", 9.5F, FontStyle.Regular)
        };

        var tabSuccess = new TabPage($"成功 ({successCount})")
        {
            BackColor = Color.White
        };
        var tabFailed = new TabPage($"失败 ({failedCount})")
        {
            BackColor = Color.White
        };

        var successList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Microsoft YaHei UI", 9.3F, FontStyle.Regular),
            BackColor = Color.FromArgb(248, 251, 255)
        };
        successList.Columns.Add("序号", 72);
        successList.Columns.Add("成功条目", 620);

        if (result.SuccessItems.Count == 0)
        {
            var row = new ListViewItem("1");
            row.SubItems.Add("(无)");
            successList.Items.Add(row);
        }
        else
        {
            var index = 1;
            foreach (var item in result.SuccessItems)
            {
                var row = new ListViewItem(index.ToString());
                row.SubItems.Add(string.IsNullOrWhiteSpace(item) ? "(空)" : item);
                successList.Items.Add(row);
                index++;
            }
        }

        var failedList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Microsoft YaHei UI", 9.3F, FontStyle.Regular),
            BackColor = Color.FromArgb(255, 249, 249)
        };
        failedList.Columns.Add("序号", 72);
        failedList.Columns.Add("失败条目", 620);

        if (result.FailedItems.Count == 0)
        {
            var row = new ListViewItem("1");
            row.SubItems.Add("(无)");
            failedList.Items.Add(row);
        }
        else
        {
            var index = 1;
            foreach (var item in result.FailedItems)
            {
                var row = new ListViewItem(index.ToString());
                row.SubItems.Add(string.IsNullOrWhiteSpace(item) ? "(空)" : item);
                failedList.Items.Add(row);
                index++;
            }
        }

        tabSuccess.Controls.Add(successList);
        tabFailed.Controls.Add(failedList);
        tabs.TabPages.Add(tabSuccess);
        tabs.TabPages.Add(tabFailed);

        panel.Controls.Add(tabs);

        var host = form.Tag as TableLayoutPanel;
        if (host is not null)
        {
            host.RowStyles[2] = new RowStyle(SizeType.Percent, 100);
            host.Controls.Add(panel, 0, 2);
        }

        return form;
    }

    private static Form BuildServiceReadyForm(string detailContent)
    {
        var form = BuildBaseForm(
            "RollbackGuard - 服务就绪",
            "服务初始化完成",
            "驱动、微过滤器、编排器和周期扫描器均已启动。",
            string.IsNullOrWhiteSpace(detailContent)
                ? "现在可以开始测试。"
                : detailContent,
            "开始测试",
            "关闭");

        form.CancelButton = form.AcceptButton;
        return form;
    }

    private static string BuildReasonLabel(ThreatDecision decision, TelemetryEvent telemetryEvent)
    {
        return ThreatLabelResolver.ResolveLabel(telemetryEvent.Kind, decision.Reason, telemetryEvent.TargetPath);
    }

    private static string ResolveDisplayProcessPath(TelemetryEvent telemetryEvent)
    {
        if (!string.IsNullOrWhiteSpace(telemetryEvent.ProcessPath))
        {
            return telemetryEvent.ProcessPath;
        }

        if (telemetryEvent.ProcessId <= 4)
        {
            return "(未知进程)";
        }

        var livePath = TryReadLiveProcessPath(telemetryEvent.ProcessId);
        return string.IsNullOrWhiteSpace(livePath) ? "(未知进程)" : livePath;
    }

    private static string ResolveDisplayProcessName(string processPath)
    {
        var processName = Path.GetFileName(processPath);
        return string.IsNullOrWhiteSpace(processName) ? "(未知)" : processName;
    }

    private static string TryReadLiveProcessPath(int pid)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            using var process = Process.GetProcessById(pid);

            string? mainModulePath = null;
            try
            {
                mainModulePath = process.MainModule?.FileName?.Trim();
            }
            catch
            {
                mainModulePath = null;
            }

            if (!string.IsNullOrWhiteSpace(mainModulePath))
            {
                return mainModulePath;
            }

            handle = OpenProcess(0x1000, false, (uint)pid);
            if (handle != IntPtr.Zero)
            {
                var buffer = new char[32768];
                var size = buffer.Length;
                if (QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0)
                {
                    return new string(buffer, 0, size);
                }
            }

            string? processName = null;
            try
            {
                processName = process.ProcessName?.Trim();
            }
            catch
            {
                processName = null;
            }

            if (string.IsNullOrWhiteSpace(processName))
            {
                return string.Empty;
            }

            return processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? processName
                : processName + ".exe";
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            if (handle != IntPtr.Zero)
            {
                _ = CloseHandle(handle);
            }
        }
    }

    private static void ForcePopupTopMost(Form form)
    {
        if (form.IsDisposed)
        {
            return;
        }

        var handle = form.Handle;
        if (handle == IntPtr.Zero)
        {
            return;
        }

        _ = ShowWindow(handle, SwShowNormal);
        _ = SetWindowPos(handle, HwndTopMost, 0, 0, 0, 0, SwpNoMove | SwpNoSize | SwpShowWindow);
        _ = BringWindowToTop(handle);
        _ = SetForegroundWindow(handle);
        form.BringToFront();
        form.Activate();
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr processHandle,
        uint flags,
        [Out] char[] exeName,
        ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static Form BuildBaseForm(
        string windowTitle,
        string title,
        string subtitle,
        string detailContent,
        string primaryButtonText,
        string secondaryButtonText,
        bool mouseOnlyDecision = false)
    {
        var form = new Form
        {
            Text = windowTitle,
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ControlBox = !mouseOnlyDecision,
            ShowInTaskbar = false,
            TopMost = true,
            Width = 820,
            Height = 620,
            BackColor = Color.White,
            KeyPreview = mouseOnlyDecision,
            Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular)
        };

        var allowCloseByDecision = false;
        form.Shown += (_, _) =>
        {
            try
            {
                ForcePopupTopMost(form);
            }
            catch
            {
                // ignore foreground policy failures
            }
        };
        if (mouseOnlyDecision)
        {
            form.KeyDown += (_, e) =>
            {
                e.SuppressKeyPress = true;
                e.Handled = true;
            };

            form.FormClosing += (_, e) =>
            {
                if (allowCloseByDecision)
                {
                    return;
                }

                if (e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                }
            };
        }

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            RowCount = 2,
            ColumnCount = 1,
            BackColor = Color.White
        };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));
        form.Controls.Add(root);

        var bodyHost = new TableLayoutPanel
        {
            Name = "BodyHost",
            Dock = DockStyle.Fill,
            RowCount = 3,
            ColumnCount = 1,
            BackColor = Color.White
        };
        bodyHost.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        bodyHost.RowStyles.Add(new RowStyle(SizeType.Absolute, 220));
        bodyHost.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
        root.Controls.Add(bodyHost, 0, 0);
        form.Tag = bodyHost;

        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 128,
            BackColor = Color.FromArgb(238, 246, 255),
            Padding = new Padding(26, 22, 26, 14)
        };

        var headerTitle = new Label
        {
            AutoSize = true,
            Text = title,
            Font = new Font("Microsoft YaHei UI", 14F, FontStyle.Bold),
            ForeColor = Color.FromArgb(22, 74, 141)
        };

        var headerSub = new Label
        {
            AutoSize = true,
            Top = 42,
            Text = subtitle,
            Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular),
            ForeColor = Color.FromArgb(66, 84, 102)
        };

        header.Controls.Add(headerTitle);
        header.Controls.Add(headerSub);
        bodyHost.Controls.Add(header, 0, 0);

        var details = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            Dock = DockStyle.Fill,
            Text = detailContent,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.FromArgb(248, 251, 255),
            ForeColor = Color.FromArgb(22, 29, 41),
            ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 10F, FontStyle.Regular),
            Margin = new Padding(26, 12, 26, 12)
        };
        bodyHost.Controls.Add(details, 0, 1);

        var footer = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(246, 248, 252),
            Padding = new Padding(26, 14, 26, 14)
        };

        var ignoreButton = new Button
        {
            Text = secondaryButtonText,
            DialogResult = DialogResult.Cancel,
            Width = 120,
            Height = 36,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = Color.FromArgb(54, 65, 78),
            TabStop = !mouseOnlyDecision,
            Anchor = AnchorStyles.Right | AnchorStyles.Top
        };
        ignoreButton.FlatAppearance.BorderColor = Color.FromArgb(186, 197, 211);
        ignoreButton.FlatAppearance.BorderSize = 1;

        var actionButton = new Button
        {
            Text = primaryButtonText,
            DialogResult = DialogResult.OK,
            Width = 140,
            Height = 36,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(22, 120, 198),
            ForeColor = Color.White,
            TabStop = !mouseOnlyDecision,
            Anchor = AnchorStyles.Right | AnchorStyles.Top
        };
        actionButton.FlatAppearance.BorderSize = 0;

        if (mouseOnlyDecision)
        {
            actionButton.Click += (_, _) => allowCloseByDecision = true;
            ignoreButton.Click += (_, _) => allowCloseByDecision = true;
            actionButton.KeyDown += (_, e) =>
            {
                e.SuppressKeyPress = true;
                e.Handled = true;
            };
            ignoreButton.KeyDown += (_, e) =>
            {
                e.SuppressKeyPress = true;
                e.Handled = true;
            };
        }

        var buttonFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(0)
        };

        buttonFlow.Controls.Add(actionButton);
        buttonFlow.Controls.Add(ignoreButton);

        footer.Controls.Add(buttonFlow);
        root.Controls.Add(footer, 0, 1);

        if (!mouseOnlyDecision)
        {
            form.AcceptButton = actionButton;
            form.CancelButton = ignoreButton;
        }

        return form;
    }
}


