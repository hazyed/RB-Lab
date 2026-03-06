using System.Windows;
using RollbackGuard.UI.ViewModels;

namespace RollbackGuard.UI;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private VerifiedProgramsWindow? _verifiedProgramsWindow;

    public MainWindow()
    {
        InitializeComponent();

        _viewModel = new MainViewModel();
        DataContext = _viewModel;

        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await _viewModel.RefreshAsync();
    }

    private async void OnRefreshClick(object sender, RoutedEventArgs e)
    {
        await _viewModel.RefreshAsync();
    }

    private void OnDeleteSelectedClick(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedIncident is null)
        {
            MessageBox.Show(this, "请先在左侧选择一条日志。", "RollbackGuard", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            this,
            "确认删除选中日志？此操作会改写 incidents.jsonl。",
            "RollbackGuard",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        var ok = _viewModel.DeleteSelectedIncident(out var message);
        MessageBox.Show(
            this,
            message,
            "RollbackGuard",
            MessageBoxButton.OK,
            ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void OnClearAllClick(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(
            this,
            "确认清空全部日志？此操作不可撤销。",
            "RollbackGuard",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        var ok = _viewModel.DeleteAllIncidents(out var message);
        MessageBox.Show(
            this,
            message,
            "RollbackGuard",
            MessageBoxButton.OK,
            ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void OnOpenVerifiedProgramsClick(object sender, RoutedEventArgs e)
    {
        _viewModel.Refresh();

        if (_verifiedProgramsWindow != null)
        {
            if (_verifiedProgramsWindow.IsVisible)
            {
                _verifiedProgramsWindow.Activate();
                return;
            }

            _verifiedProgramsWindow = null;
        }

        _verifiedProgramsWindow = new VerifiedProgramsWindow
        {
            Owner = this,
            DataContext = _viewModel
        };
        _verifiedProgramsWindow.Closed += (_, _) => _verifiedProgramsWindow = null;
        _verifiedProgramsWindow.Show();
    }
}
