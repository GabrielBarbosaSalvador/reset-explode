using System.Diagnostics;
using System.IO;
using System.Security;
using System.Text;

namespace ResetExplode;

/// <summary>
/// Abrir o RESET EXPLODE junto com o Windows. O app roda como administrador (app.manifest), e o Windows ignora
/// programas elevados na chave Run; por isso usa uma tarefa agendada "ao fazer logon" com privilégios mais altos,
/// que abre sem o aviso do UAC. O app abre com --tray: escondido, só o ícone perto do relógio.
/// </summary>
public static class AutoStart
{
    public const string TrayArg = "--tray";
    private const string TaskName = "RESET EXPLODE";

    public static bool IsEnabled() => Run("/Query", "/TN", TaskName).code == 0;

    public static void Enable()
    {
        string exe = Environment.ProcessPath ?? throw new InvalidOperationException("caminho do programa desconhecido");
        string user = $"{Environment.UserDomainName}\\{Environment.UserName}";
        // Sem limite de tempo (o padrão mataria o app após 72 h) e também na bateria.
        string xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>Abre o RESET EXPLODE na bandeja ao entrar no Windows.</Description></RegistrationInfo>
              <Triggers>
                <LogonTrigger><Enabled>true</Enabled><UserId>{SecurityElement.Escape(user)}</UserId><Delay>PT5S</Delay></LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author"><UserId>{SecurityElement.Escape(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec><Command>{SecurityElement.Escape(exe)}</Command><Arguments>{TrayArg}</Arguments><WorkingDirectory>{SecurityElement.Escape(Path.GetDirectoryName(exe))}</WorkingDirectory></Exec>
              </Actions>
            </Task>
            """;
        string file = Path.Combine(Path.GetTempPath(), $"resetexplode-task-{Guid.NewGuid():N}.xml");
        try
        {
            File.WriteAllText(file, xml, Encoding.Unicode);
            var (code, output) = Run("/Create", "/TN", TaskName, "/XML", file, "/F");
            if (code != 0) throw new InvalidOperationException(output.Trim());
        }
        finally { try { File.Delete(file); } catch { } }
    }

    public static void Disable()
    {
        var (code, output) = Run("/Delete", "/TN", TaskName, "/F");
        if (code != 0 && IsEnabled()) throw new InvalidOperationException(output.Trim());
    }

    private static (int code, string output) Run(params string[] args)
    {
        var psi = new ProcessStartInfo("schtasks.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        string text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, text);
    }
}
