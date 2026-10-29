using System.Windows;
using Forms = System.Windows.Forms;

namespace ResetExplode;

/// <summary>Segundo plano: ícone na bandeja (perto do relógio) e abrir com o Windows.</summary>
public partial class MainWindow
{
    private Forms.NotifyIcon? _tray;
    private bool _exiting;      // "Sair" de verdade (menu da bandeja), sem voltar para a bandeja
    private bool _trayHinted;   // aviso "continua rodando aqui" só na primeira vez
    private WindowState _restoreState = WindowState.Normal; // como a janela estava antes de minimizar
    private Task? _hardwareLoad;

    private Task LoadHardwareOnceAsync() => _hardwareLoad ??= LoadHardwareAsync();

    /// <summary>Aberto com o Windows (--tray): nada de janela, só o ícone; sensores e caixa-preta já começam.</summary>
    public void StartHidden()
    {
        new System.Windows.Interop.WindowInteropHelper(this).EnsureHandle(); // atalho do overlay e avisos de USB
        _trayHinted = true; // quem abriu com o Windows já sabe onde ele fica
        UpdateTrayIcon();
        _ = LoadHardwareOnceAsync();
    }

    public void PrepareExit() => _exiting = true;

    private void InitTray()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Abrir RESET EXPLODE", null, (_, _) => ShowFromTray());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Sair", null, (_, _) => ExitApp());

        System.Drawing.Icon icon;
        try
        {
            using var s = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/app.ico")).Stream;
            icon = new System.Drawing.Icon(s);
        }
        catch { icon = System.Drawing.SystemIcons.Application; }

        _tray = new Forms.NotifyIcon { Icon = icon, Text = "RESET EXPLODE", ContextMenuStrip = menu };
        _tray.MouseClick += (_, e) => { if (e.Button == Forms.MouseButtons.Left) ShowFromTray(); };
        UpdateTrayIcon();
        IsVisibleChanged += (_, _) => UpdateTrayIcon();

        ChkTray.IsChecked = _settings.KeepInTray;
        // Consultar o Agendador leva um instante: fora da thread da janela. Se a tarefa existe, regrava com o caminho
        // atual do .exe (o app pode ter sido movido ou atualizado).
        ChkAutoStart.IsEnabled = false;
        _ = Task.Run(() =>
        {
            bool on = false;
            try { on = AutoStart.IsEnabled(); if (on) AutoStart.Enable(); } catch { }
            Dispatcher.BeginInvoke(() => { ChkAutoStart.IsChecked = on; ChkAutoStart.IsEnabled = true; });
        });
    }

    /// <summary>O ícone fica visível com a opção ligada ou sempre que a janela estiver escondida.</summary>
    private void UpdateTrayIcon()
    {
        if (_tray != null) _tray.Visible = _settings.KeepInTray || !IsVisible;
    }

    /// <summary>Some da barra de tarefas; o app segue rodando (caixa-preta, overlay, atalhos).</summary>
    public void HideToTray()
    {
        Hide();
        UpdateTrayIcon();
        if (!_trayHinted && _tray != null)
        {
            _trayHinted = true;
            _tray.ShowBalloonTip(3000, "RESET EXPLODE", "Continua rodando aqui. Clique no ícone para abrir de novo.", Forms.ToolTipIcon.None);
        }
    }

    public void ShowFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = _restoreState;
        Activate();
        Topmost = true; Topmost = false; // garante que vem para a frente
        UpdateTrayIcon();
    }

    private void ExitApp()
    {
        PrepareExit();
        Close();
    }

    /// <summary>Com a opção ligada, fechar e minimizar só escondem a janela.</summary>
    private bool InterceptClose()
    {
        if (_exiting || !_settings.KeepInTray) return false;
        HideToTray();
        return true;
    }

    private void DisposeTray()
    {
        if (_tray == null) return;
        _tray.Visible = false;
        _tray.Dispose();
        _tray = null;
    }

    private void ChkTray_Click(object sender, RoutedEventArgs e)
    {
        _settings.KeepInTray = ChkTray.IsChecked == true;
        _settings.Save();
        UpdateTrayIcon();
        AutoStartResult.Text = _settings.KeepInTray
            ? "Ligado: fechar ou minimizar deixa o app na bandeja. Para sair de vez, clique com o botão direito no ícone > Sair."
            : "Desligado: fechar encerra o app.";
    }

    private async void ChkAutoStart_Click(object sender, RoutedEventArgs e)
    {
        bool turnOn = ChkAutoStart.IsChecked == true;
        ChkAutoStart.IsEnabled = false;
        try
        {
            await Task.Run(() => { if (turnOn) AutoStart.Enable(); else AutoStart.Disable(); });
            AutoStartResult.Text = turnOn
                ? "Ligado: ao entrar no Windows o RESET EXPLODE abre escondido na bandeja, sem aviso do UAC."
                : "Desligado: o app não abre mais com o Windows.";
        }
        catch (Exception ex)
        {
            ChkAutoStart.IsChecked = !turnOn;
            AutoStartResult.Text = $"Não foi possível alterar: {ex.Message}";
        }
        finally { ChkAutoStart.IsEnabled = true; }
    }
}
