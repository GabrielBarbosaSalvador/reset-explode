using System.Threading;
using System.Windows;

namespace ResetExplode;

public partial class App : Application
{
    // Uma única instância: abrir o RESET EXPLODE de novo só traz a janela que já está aberta para a frente
    // (também quando ela está escondida na bandeja). A segunda instância só sinaliza o evento e sai.
    private static Mutex? _single;
    private static EventWaitHandle? _showSignal;
    private const string ShowSignalName = @"Local\ResetExplode.Show";

    protected override void OnStartup(StartupEventArgs e)
    {
        bool first;
        try { _single = new Mutex(true, @"Local\ResetExplode.SingleInstance", out first); }
        catch (UnauthorizedAccessException) { first = false; } // criado por outra instância com outro nível de permissão

        if (!first)
        {
            try { if (EventWaitHandle.TryOpenExisting(ShowSignalName, out var ev)) using (ev) ev.Set(); }
            catch { }
            Shutdown();
            return;
        }
        base.OnStartup(e);

        var win = new MainWindow();
        MainWindow = win;
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
        ThreadPool.RegisterWaitForSingleObject(_showSignal,
            (_, _) => win.Dispatcher.BeginInvoke(win.ShowFromTray), null, Timeout.Infinite, executeOnlyOnce: false);
        // Na hora de desligar/sair do Windows, fechar encerra mesmo (sem voltar para a bandeja).
        SessionEnding += (_, _) => win.PrepareExit();

        if (e.Args.Contains(AutoStart.TrayArg, StringComparer.OrdinalIgnoreCase)) win.StartHidden();
        else win.Show();
    }
}
