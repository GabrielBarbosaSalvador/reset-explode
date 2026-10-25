using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace ResetExplode;

public enum EventSeverity { Critical, Error, Warning, Info }

/// <summary>Um evento do Visualizador de Eventos já traduzido (categoria e explicação em português).</summary>
public sealed record DiagEvent(DateTime Time, string Log, string Provider, int Id, EventSeverity Level,
                               string Category, string Title, string Explain, string Message)
{
    public string TimeText => Time.ToString("dd/MM HH:mm:ss");
    public string LevelText => Level switch
    {
        EventSeverity.Critical => "CRÍTICO",
        EventSeverity.Error => "ERRO",
        EventSeverity.Warning => "AVISO",
        _ => "INFO"
    };
    public string Source => $"{Provider} · ID {Id} · {Log}";
    public string Line => $"{TimeText}  {LevelText,-7} {Title} ({Provider} {Id})" + (Message.Length > 0 ? " · " + Message : "");
}

public enum ShutdownKind { Clean, Planned, BlueScreen, HardwareError, PowerButton, PowerLoss, Unexpected, Unknown }

public enum Suspect { Hardware, Ram, Gpu, Driver, Disk }

public sealed record BugcheckInfo(uint Code, string Name, string Explain, Suspect Suspect)
{
    public string CodeText => $"0x{Code:X}";
}

/// <summary>Um início do Windows e como terminou a sessão anterior.</summary>
public sealed class ShutdownRecord
{
    public DateTime Boot { get; init; }
    /// <summary>Hora aproximada da queda (último sinal de vida antes de religar).</summary>
    public DateTime? EndTime { get; set; }
    public ShutdownKind Kind { get; set; } = ShutdownKind.Unknown;
    public string Detail { get; set; } = "";
    public BugcheckInfo? Bugcheck { get; set; }
    public List<DiagEvent> Before { get; } = new();
    /// <summary>Erros fatais de hardware que o Windows só consegue gravar ao religar (WHEA 18/20 vindos da BIOS).</summary>
    public List<DiagEvent> AtBoot { get; } = new();
    public List<BlackBoxSample> BlackBox { get; set; } = new();
    public bool IsUnexpected => Kind is ShutdownKind.BlueScreen or ShutdownKind.HardwareError or ShutdownKind.PowerButton
                                     or ShutdownKind.PowerLoss or ShutdownKind.Unexpected;

    public string KindText => Kind switch
    {
        ShutdownKind.Clean => "Desligado normalmente",
        ShutdownKind.Planned => "Reinício / desligamento pedido",
        ShutdownKind.BlueScreen => "Tela azul" + (Bugcheck != null ? $" · {Bugcheck.CodeText} {Bugcheck.Name}" : ""),
        ShutdownKind.HardwareError => "Erro fatal de hardware (WHEA) derrubou o PC",
        ShutdownKind.PowerButton => "Travou e foi desligado no botão",
        ShutdownKind.PowerLoss => "Desligou sozinho (sem tela azul)",
        ShutdownKind.Unexpected => "Desligamento inesperado",
        _ => "Sem registro do desligamento"
    };
}

public sealed record DumpFile(string Path, DateTime Time, long Size)
{
    public string Text => $"{System.IO.Path.GetFileName(Path)} · {Time:dd/MM/yyyy HH:mm} · {Size / 1024.0:N0} KB";
}

public sealed record Verdict(DiskVerdict Level, string Title, string Summary, List<string> Why, List<string> Notes, List<string> Actions)
{
    /// <summary>Texto corrido do veredito (relatório exportado e Visão geral).</summary>
    public string Reasons
    {
        get
        {
            var sb = new StringBuilder(Summary);
            if (Why.Count > 0) { sb.Append("\n\nPor quê:\n"); foreach (var w in Why) sb.Append("• ").Append(w).Append('\n'); }
            foreach (var n in Notes) sb.Append('\n').Append(n).Append('\n');
            return sb.ToString().TrimEnd();
        }
    }
}

public sealed class DiagResult
{
    public DateTime Since { get; init; }
    public List<DiagEvent> Events { get; init; } = new();
    public List<ShutdownRecord> Timeline { get; init; } = new();
    public List<DumpFile> Dumps { get; init; } = new();
    public Verdict Verdict { get; set; } = new(DiskVerdict.Unknown, "", "", new(), new(), new());
    public bool Truncated { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Lê o registro de eventos do Windows (System e Application) para descobrir por que o PC reiniciou, desligou ou travou:
/// classifica cada desligamento, traduz telas azuis, agrupa os erros por categoria e aponta a causa mais provável.
/// </summary>
public static class EventDiagnostics
{
    private const int MaxPerLog = 4000;
    public const string CatShutdown = "Desligamentos";
    public const string CatBsod = "Telas azuis";
    public const string CatHardware = "Hardware (WHEA)";
    public const string CatGpu = "Vídeo";
    public const string CatDisk = "Disco";
    public const string CatPower = "Energia";
    public const string CatMemory = "Memória";
    public const string CatApps = "Programas";
    public const string CatServices = "Serviços e Windows Update";
    public const string CatOther = "Outros";

    public static readonly string[] Categories =
        { CatShutdown, CatBsod, CatHardware, CatGpu, CatDisk, CatPower, CatMemory, CatApps, CatServices, CatOther };

    private const string PKernelPower = "Microsoft-Windows-Kernel-Power";
    private const string PKernelGeneral = "Microsoft-Windows-Kernel-General";
    private const string PBugCheck = "Microsoft-Windows-WER-SystemErrorReporting";
    // textos acrescentados ao Kernel-Power 41 e usados para classificar a queda
    private const string MarkBsod = "Houve tela azul";
    private const string MarkButton = "O botão de energia foi segurado";

    // ---------------- leitura ----------------

    public static DiagResult Read(DateTime since, BlackBox? blackBox = null)
    {
        string t = since.ToUniversalTime().ToString("o");
        var events = new List<DiagEvent>();
        bool truncated = false;
        try
        {
            truncated |= ReadLog("System",
                $"*[System[(Level=1 or Level=2 or Level=3" +
                $" or (Provider[@Name='{PKernelGeneral}'] and (EventID=12 or EventID=13))" +
                $" or (Provider[@Name='User32'] and EventID=1074)" +
                $" or (Provider[@Name='EventLog'] and (EventID=6005 or EventID=6006 or EventID=6008))" +
                $" or (Provider[@Name='{PKernelPower}'] and (EventID=41 or EventID=42 or EventID=107 or EventID=109)))" +
                $" and TimeCreated[@SystemTime>='{t}']]]", events);
            truncated |= ReadLog("Application",
                $"*[System[(Level=1 or Level=2" +
                $" or (Provider[@Name='Windows Error Reporting'] and EventID=1001))" +
                $" and TimeCreated[@SystemTime>='{t}']]]", events);
        }
        catch (Exception ex)
        {
            return new DiagResult { Since = since, Error = ex.Message };
        }

        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        // o Windows Error Reporting envia relatórios acumulados de uma vez: um por título a cada minuto basta
        var lastWer = new Dictionary<string, DateTime>();
        events.RemoveAll(e =>
        {
            if (e.Provider != "Windows Error Reporting") return false;
            bool dup = lastWer.TryGetValue(e.Title, out var prev) && e.Time - prev < TimeSpan.FromMinutes(1);
            if (!dup) lastWer[e.Title] = e.Time;
            return dup;
        });
        var timeline = BuildTimeline(events, since, blackBox);
        var result = new DiagResult
        {
            Since = since,
            Events = events,
            Timeline = timeline,
            Dumps = ListDumps(),
            Truncated = truncated,
        };
        result.Verdict = Diagnose(result);
        return result;
    }

    /// <summary>Conta rapidamente os desligamentos inesperados (Kernel-Power 41 / EventLog 6008), para a Visão geral.</summary>
    public static int UnexpectedSince(DateTime since)
    {
        string t = since.ToUniversalTime().ToString("o");
        // 41 e 6008 costumam vir em par para a mesma queda: conta os 41 e só usa 6008 quando não houver nenhum 41
        int n41 = Count($"*[System[Provider[@Name='{PKernelPower}'] and EventID=41 and TimeCreated[@SystemTime>='{t}']]]");
        return n41 > 0 ? n41 : Count($"*[System[Provider[@Name='EventLog'] and EventID=6008 and TimeCreated[@SystemTime>='{t}']]]");
    }

    private static int Count(string xpath)
    {
        int n = 0;
        using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName, xpath));
        for (EventRecord? rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent()) { rec.Dispose(); n++; }
        return n;
    }

    /// <summary>Lê do mais novo para o mais antigo, até o limite. Retorna true se parou no limite.</summary>
    private static bool ReadLog(string log, string xpath, List<DiagEvent> into)
    {
        using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true });
        int n = 0;
        for (EventRecord? rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
        {
            using (rec)
            {
                if (++n > MaxPerLog) return true;
                into.Add(Translate(rec, log));
            }
        }
        return false;
    }

    private static DiagEvent Translate(EventRecord rec, string log)
    {
        string provider = rec.ProviderName ?? "";
        int id = rec.Id;
        var level = rec.Level switch
        {
            1 => EventSeverity.Critical,
            2 => EventSeverity.Error,
            3 => EventSeverity.Warning,
            _ => EventSeverity.Info
        };
        string msg;
        try { msg = rec.FormatDescription() ?? ""; } catch { msg = ""; }
        // no WHEA a primeira linha é genérica; o componente e o tipo do erro vêm nas seguintes
        msg = provider == "Microsoft-Windows-WHEA-Logger"
            ? string.Join(" · ", msg.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).Skip(1).Take(4))
            : FirstLine(msg);
        var (cat, title, explain) = Classify(provider, id, rec);

        // detalhes que o texto padrão não mostra
        if (provider == PKernelPower && id == 41)
        {
            var d = Data(rec);
            uint bc = ParseUInt(d.GetValueOrDefault("BugcheckCode"));
            long button = (long)ParseUInt(d.GetValueOrDefault("PowerButtonTimestamp"));
            if (bc != 0) explain += $" {MarkBsod} (código {Bugcheck(bc).CodeText} {Bugcheck(bc).Name}).";
            else if (button != 0) explain += $" {MarkButton}: o PC estava travado.";
            else explain += " Não houve tela azul nem botão: a energia foi cortada de repente.";
        }
        else if (IsBugcheckEvent(provider, id) && rec.Properties.Count > 0)
        {
            uint bc = ParseHex(rec.Properties[0].Value?.ToString());
            if (bc != 0)
            {
                var info = Bugcheck(bc);
                title = $"Tela azul {info.CodeText} {info.Name}";
                explain = info.Explain;
            }
        }
        else if (provider == "Windows Error Reporting" && id == 1001)
        {
            var props = rec.Properties.Select(p => p.Value?.ToString() ?? "").ToList();
            int lk = props.FindIndex(v => v.Equals("LiveKernelEvent", StringComparison.OrdinalIgnoreCase));
            if (lk >= 0)
            {
                // nome do evento, "assinatura", hash e então o código (P1)
                string code = lk + 3 < props.Count ? props[lk + 3].ToLowerInvariant() : "";
                (cat, explain) = code switch
                {
                    "141" or "117" or "1a1" or "1a8" => (CatGpu, "A placa de vídeo travou e o Windows reiniciou o driver sem tela azul. Driver, overclock da GPU, fonte ou a própria placa."),
                    "124" => (CatHardware, "Erro de hardware (WHEA) que o Windows conseguiu contornar sem tela azul: CPU, RAM ou PCIe instáveis."),
                    _ => (CatOther, "O kernel salvou um despejo ao vivo de uma falha sem chegar à tela azul."),
                };
                title = "Falha recuperada (LiveKernelEvent " + code + ")";
                msg = "Relatório enviado pelo Windows Error Reporting; a hora é a do envio, não a da falha.";
            }
            else
            {
                cat = CatApps;
                var app = rec.Properties.Count > 5 ? rec.Properties[5].Value?.ToString() : null;
                title = "Relatório de erro" + (string.IsNullOrWhiteSpace(app) ? "" : $" · {app}");
                explain = "O Windows registrou uma falha de programa (relatório de erro).";
                msg = "";
            }
        }
        else if (provider == "User32" && id == 1074 && rec.Properties.Count > 4)
        {
            string proc = Path.GetFileName(rec.Properties[0].Value?.ToString() ?? "");
            string reason = rec.Properties[2].Value?.ToString() ?? "";
            string type = rec.Properties[4].Value?.ToString() ?? "";
            msg = $"{type} pedido por {proc}" + (reason.Length > 0 ? $" · {reason}" : "");
        }
        else if ((provider == "Application Error" || provider == "Application Hang") && rec.Properties.Count > 0)
        {
            title += $" · {rec.Properties[0].Value}";
        }

        return new DiagEvent(rec.TimeCreated ?? DateTime.MinValue, log, provider, id, level, cat, title, explain, msg);
    }

    private static bool IsBugcheckEvent(string provider, int id) =>
        id == 1001 && (provider == PBugCheck || provider.Equals("BugCheck", StringComparison.OrdinalIgnoreCase));

    // ---------------- catálogo ----------------

    /// <summary>Categoria, título curto e explicação dos eventos que importam para travamentos e desligamentos.</summary>
    private static (string Cat, string Title, string Explain) Classify(string provider, int id, EventRecord rec)
    {
        string p = provider.ToLowerInvariant();
        switch (p)
        {
            case "microsoft-windows-kernel-power":
                return id switch
                {
                    41 => (CatShutdown, "Reinício sem desligamento correto", "O Windows voltou sem ter desligado direito (Kernel-Power 41)."),
                    42 => (CatPower, "Entrando em suspensão", "O PC foi colocado para dormir/hibernar."),
                    107 => (CatPower, "Voltou da suspensão", "O PC acordou da suspensão/hibernação."),
                    109 => (CatShutdown, "Desligamento iniciado pelo kernel", "Etapa normal de desligar/reiniciar."),
                    _ => (CatPower, "Energia", "Evento de energia do kernel.")
                };
            case "microsoft-windows-kernel-general":
                return id == 12 ? (CatShutdown, "Windows iniciado", "Início do sistema operacional.")
                     : id == 13 ? (CatShutdown, "Windows desligado", "Desligamento correto do sistema operacional.")
                     : (CatOther, "Kernel", "");
            case "eventlog":
                return id switch
                {
                    6005 => (CatShutdown, "Registro de eventos iniciado", "Marca o início do Windows."),
                    6006 => (CatShutdown, "Registro de eventos parado", "Marca um desligamento correto."),
                    6008 => (CatShutdown, "Desligamento inesperado", "O desligamento anterior não foi feito corretamente (queda, travamento ou tela azul)."),
                    _ => (CatOther, "Registro de eventos", "")
                };
            case "user32":
                return (CatShutdown, "Reinício/desligamento pedido", "Um programa ou usuário pediu para reiniciar ou desligar (ex.: Windows Update).");
            case "microsoft-windows-wer-systemerrorreporting":
            case "bugcheck":
                return (CatBsod, "Tela azul", "O Windows parou com tela azul e reiniciou.");
            case "volmgr":
                return id is 161 or 162 or 46
                    ? (CatBsod, "Despejo de memória não gravado", "Houve tela azul mas o arquivo de despejo (dump) não pôde ser salvo; verifique o arquivo de paginação.")
                    : (CatDisk, "Gerenciador de volumes", "Problema com volumes de disco.");
            case "microsoft-windows-whea-logger":
                return id switch
                {
                    17 => (CatHardware, "Erro de hardware corrigido (PCIe)", "Erro corrigido no barramento PCIe: placa de vídeo, SSD NVMe, slot, riser ou ASPM. Isolado não é grave, repetido indica instabilidade."),
                    18 => (CatHardware, "Erro fatal de hardware (CPU)", "Erro de máquina não corrigível no processador: costuma derrubar o PC. Overclock/undervolt (Curve Optimizer, PBO), XMP/EXPO, tensão ou CPU com defeito."),
                    19 => (CatHardware, "Erro de hardware corrigido (CPU/cache)", "A CPU corrigiu um erro sozinha. Repetido indica overclock/undervolt instável ou tensão no limite."),
                    20 => (CatHardware, "Erro fatal de hardware", "Erro de hardware não corrigível (barramento/memória)."),
                    46 or 47 => (CatHardware, "Erro de memória (RAM) corrigido", "Erro corrigido na memória: XMP/EXPO instável, pente com defeito ou mal encaixado."),
                    _ => (CatHardware, "Erro de hardware (WHEA)", "O Windows registrou um erro de hardware (CPU, RAM ou PCIe).")
                };
            case "display":
                return (CatGpu, "Driver de vídeo parou de responder", "A placa de vídeo travou e o Windows reiniciou o driver (tela preta/piscando). Driver, overclock da GPU, fonte ou a placa.");
            case "nvlddmkm":
                return (CatGpu, "Erro do driver NVIDIA", "O driver da NVIDIA registrou erro (13/153 = travamento/reset da GPU). Atualize/reinstale o driver, tire overclock da GPU e confira a fonte e os cabos PCIe.");
            case "amdkmdag":
            case "amdkmdap":
                return (CatGpu, "Erro do driver AMD", "O driver de vídeo da AMD registrou erro ou reset da GPU.");
            case "disk":
                return id switch
                {
                    7 => (CatDisk, "Bloco defeituoso no disco", "O disco tem setor ruim. Veja a aba Discos (S.M.A.R.T.) e faça backup."),
                    51 => (CatDisk, "Erro ao gravar/ler no disco", "Falha de E/S durante paginação: disco, cabo SATA ou porta."),
                    153 => (CatDisk, "Operação de disco repetida", "O disco demorou e o Windows repetiu a operação: cabo, porta, firmware ou disco falhando."),
                    154 => (CatDisk, "Falha de hardware no disco", "O disco relatou falha de hardware."),
                    _ => (CatDisk, "Disco", "O driver de disco registrou um problema.")
                };
            case "ntfs":
            case "microsoft-windows-ntfs":
                return (CatDisk, "Sistema de arquivos (NTFS)", "Problema no sistema de arquivos. Rode \"chkdsk /scan\" e veja a aba Discos.");
            case "stornvme":
            case "storahci":
            case "iastora":
            case "iastorac":
            case "iastorv":
            case "amd_sata":
                return id == 129
                    ? (CatDisk, "Disco parou de responder (reset)", "O controlador reiniciou o disco por falta de resposta: congela o PC por alguns segundos. Firmware do SSD, driver do controlador, cabo ou energia.")
                    : (CatDisk, "Controlador de disco", "O controlador de armazenamento registrou erro (" + provider + ").");
            case "volsnap":
                return (CatDisk, "Cópias de sombra", "Problema com pontos de restauração/cópias de sombra.");
            case "microsoft-windows-resource-exhaustion-detector":
                return (CatMemory, "Memória quase esgotada", "O Windows ficou sem memória virtual: algum programa consumiu toda a RAM (vazamento) ou o arquivo de paginação é pequeno.");
            case "application error":
                return (CatApps, "Programa fechou com erro", "Um programa travou e foi fechado.");
            case "application hang":
                return (CatApps, "Programa parou de responder", "Um programa congelou e foi fechado.");
            case "service control manager":
                // 7000/7009/7011... (serviço não iniciou/demorou) aparecem em todo PC e só poluem a análise
                return id is 7031 or 7034
                    ? (CatServices, "Serviço terminou inesperadamente", "Um serviço do Windows caiu.")
                    : (CatOther, "Serviço do Windows", "");
            case "microsoft-windows-windowsupdateclient":
                return (CatServices, "Windows Update", "Falha ao instalar atualização.");
            case "microsoft-windows-kernel-pnp":
                return (CatOther, "Dispositivo", "Um dispositivo ou driver não iniciou corretamente.");
            case "microsoft-windows-kernel-processor-power":
                return (CatPower, "Energia do processador", "A CPU foi limitada (temperatura ou firmware) ou o driver de energia relatou problema.");
        }
        if (p.Contains("whea")) return (CatHardware, "Erro de hardware", "");
        return (CatOther, provider, "");
    }

    /// <summary>Nome e explicação do código de tela azul.</summary>
    public static BugcheckInfo Bugcheck(uint code)
    {
        uint c = code & ~0x10000000u; // 0x1000007E = 0x7E com parâmetros estendidos
        var (name, text, s) = c switch
        {
            0x124 => ("WHEA_UNCORRECTABLE_ERROR", "Erro de hardware não corrigível (CPU, RAM, cache ou PCIe). Muito comum com overclock/undervolt, XMP/EXPO, tensão insuficiente, CPU com defeito ou fonte fraca.", Suspect.Hardware),
            0x101 => ("CLOCK_WATCHDOG_TIMEOUT", "Um núcleo da CPU parou de responder: overclock/undervolt instável, BIOS desatualizada ou CPU com defeito.", Suspect.Hardware),
            0x7F => ("UNEXPECTED_KERNEL_MODE_TRAP", "Exceção de hardware: CPU/RAM instáveis (overclock) ou com defeito.", Suspect.Hardware),
            0x1A => ("MEMORY_MANAGEMENT", "Corrupção de memória: quase sempre RAM (XMP/EXPO, pente com defeito) ou driver.", Suspect.Ram),
            0x50 => ("PAGE_FAULT_IN_NONPAGED_AREA", "Acesso a memória inválida: RAM ou driver com defeito.", Suspect.Ram),
            0x19 => ("BAD_POOL_HEADER", "Memória do kernel corrompida: driver ou RAM.", Suspect.Ram),
            0x139 => ("KERNEL_SECURITY_CHECK_FAILURE", "Estrutura do kernel corrompida: driver incompatível ou RAM.", Suspect.Ram),
            0x3B => ("SYSTEM_SERVICE_EXCEPTION", "Exceção em código do sistema: driver (muitas vezes o de vídeo) ou RAM.", Suspect.Driver),
            0x0A => ("IRQL_NOT_LESS_OR_EQUAL", "Driver acessou memória indevida: driver com defeito ou RAM.", Suspect.Driver),
            0xD1 => ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Driver com defeito (rede, Wi-Fi, áudio, vídeo, antivírus, VPN).", Suspect.Driver),
            0x9F => ("DRIVER_POWER_STATE_FAILURE", "Driver travou ao entrar ou sair da suspensão (USB, rede, vídeo).", Suspect.Driver),
            0x7E => ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Driver gerou exceção não tratada.", Suspect.Driver),
            0x1E => ("KMODE_EXCEPTION_NOT_HANDLED", "Exceção no kernel: driver ou RAM.", Suspect.Driver),
            0xC2 => ("BAD_POOL_CALLER", "Driver usou memória do kernel de forma errada.", Suspect.Driver),
            0xC5 => ("DRIVER_CORRUPTED_EXPOOL", "Driver corrompeu a memória do kernel.", Suspect.Driver),
            0x133 => ("DPC_WATCHDOG_VIOLATION", "Um driver travou por tempo demais: comum com driver SATA/NVMe, firmware do SSD, rede ou vídeo.", Suspect.Driver),
            0x116 => ("VIDEO_TDR_FAILURE", "A placa de vídeo travou e não se recuperou: driver, overclock da GPU, temperatura, fonte ou a placa.", Suspect.Gpu),
            0x117 => ("VIDEO_TDR_TIMEOUT_DETECTED", "A placa de vídeo parou de responder.", Suspect.Gpu),
            0x119 => ("VIDEO_SCHEDULER_INTERNAL_ERROR", "Erro no agendador de vídeo: driver ou placa de vídeo.", Suspect.Gpu),
            0x10E => ("VIDEO_MEMORY_MANAGEMENT_INTERNAL", "Erro de memória de vídeo: driver ou VRAM.", Suspect.Gpu),
            0x154 => ("UNEXPECTED_STORE_EXCEPTION", "Falha ao ler memória comprimida/paginada: SSD/HD, cabo ou RAM.", Suspect.Disk),
            0x7A => ("KERNEL_DATA_INPAGE_ERROR", "O disco não entregou dados ao sistema: SSD/HD falhando, cabo SATA ou RAM.", Suspect.Disk),
            0xF4 => ("CRITICAL_OBJECT_TERMINATION", "Processo essencial terminou: disco/cabo com problema ou arquivos corrompidos.", Suspect.Disk),
            0xEF => ("CRITICAL_PROCESS_DIED", "Processo essencial do Windows morreu: arquivos do sistema, disco ou driver.", Suspect.Disk),
            0x24 => ("NTFS_FILE_SYSTEM", "Erro no sistema de arquivos: disco ou corrupção.", Suspect.Disk),
            _ => ("", "Código de tela azul sem descrição no catálogo. Procure o código na internet junto com o modelo do PC.", Suspect.Driver)
        };
        return new BugcheckInfo(c, name, text, s);
    }

    // ---------------- linha do tempo ----------------

    private static List<ShutdownRecord> BuildTimeline(List<DiagEvent> events, DateTime since, BlackBox? blackBox)
    {
        var boots = events.Where(e => e.Provider == PKernelGeneral && e.Id == 12).Select(e => e.Time).ToList();
        var list = new List<ShutdownRecord>();
        for (int i = 0; i < boots.Count; i++)
        {
            DateTime boot = boots[i];
            DateTime prevBoot = i > 0 ? boots[i - 1] : since;
            // o que é gravado logo após religar fala do desligamento anterior
            DateTime afterEnd = i + 1 < boots.Count && boots[i + 1] < boot.AddMinutes(10) ? boots[i + 1] : boot.AddMinutes(10);
            var after = events.Where(e => e.Time >= boot && e.Time < afterEnd).ToList();
            var prior = events.Where(e => e.Time > prevBoot && e.Time < boot).ToList();

            var rec = new ShutdownRecord { Boot = boot };
            var kp41 = after.FirstOrDefault(e => e.Provider == PKernelPower && e.Id == 41);
            var bsod = after.FirstOrDefault(e => IsBugcheckEvent(e.Provider, e.Id));
            var ev6008 = after.FirstOrDefault(e => e.Provider == "EventLog" && e.Id == 6008);
            var planned = prior.LastOrDefault(e => e.Provider == "User32" && e.Id == 1074);
            var clean = prior.LastOrDefault(e => (e.Provider == PKernelGeneral && e.Id == 13) || (e.Provider == "EventLog" && e.Id == 6006));
            rec.AtBoot.AddRange(after.Where(e => e.Provider == "Microsoft-Windows-WHEA-Logger" && e.Level <= EventSeverity.Error));

            if (bsod != null || (kp41 != null && kp41.Explain.Contains(MarkBsod)))
            {
                rec.Kind = ShutdownKind.BlueScreen;
                var m = Regex.Match((bsod?.Title ?? "") + " " + (kp41?.Explain ?? ""), @"0x[0-9A-Fa-f]+");
                if (m.Success) rec.Bugcheck = Bugcheck(ParseHex(m.Value));
                rec.Detail = rec.Bugcheck?.Explain ?? "O Windows parou com tela azul.";
            }
            else if ((kp41 != null || ev6008 != null) && rec.AtBoot.Count > 0)
            {
                rec.Kind = ShutdownKind.HardwareError;
                rec.Detail = "O processador (ou memória/PCIe) teve um erro de hardware não corrigível e o PC reiniciou na hora, sem dar tempo " +
                             "de tela azul. Ao religar, a BIOS entregou o registro do erro ao Windows. Causa típica: overclock/undervolt " +
                             "(PBO, Curve Optimizer), XMP/EXPO, tensão insuficiente, BIOS desatualizada, fonte instável ou CPU com defeito.";
            }
            else if (kp41 != null && kp41.Explain.Contains(MarkButton))
            {
                rec.Kind = ShutdownKind.PowerButton;
                rec.Detail = "O PC congelou e o botão de energia foi segurado. Sem tela azul: costuma ser hardware (RAM/CPU instáveis, " +
                             "placa de vídeo, fonte) ou driver travando tudo.";
            }
            else if (kp41 != null)
            {
                rec.Kind = ShutdownKind.PowerLoss;
                rec.Detail = "A energia foi cortada sem aviso: fonte de alimentação (proteção desarmando ou falhando), queda/oscilação de energia, " +
                             "superaquecimento (desligamento de proteção), cabo/filtro de linha ou botão da caixa com defeito.";
            }
            else if (ev6008 != null)
            {
                rec.Kind = ShutdownKind.Unexpected;
                rec.Detail = "O Windows marcou o desligamento anterior como inesperado.";
            }
            else if (planned != null)
            {
                rec.Kind = ShutdownKind.Planned;
                rec.Detail = planned.Message;
            }
            else if (clean != null)
            {
                rec.Kind = ShutdownKind.Clean;
            }
            else if (i == 0)
            {
                continue; // a sessão anterior começou antes do período escolhido
            }

            if (rec.IsUnexpected)
            {
                rec.EndTime = LastActivityBefore(boot);
                if (blackBox != null)
                {
                    var samples = blackBox.SamplesBefore(boot, rec.EndTime);
                    rec.BlackBox = samples;
                    if (samples.Count > 0 && (rec.EndTime == null || samples[^1].Time > rec.EndTime)) rec.EndTime = samples[^1].Time;
                }
                DateTime end = rec.EndTime ?? boot;
                rec.Before.AddRange(events.Where(e => e.Time >= end.AddMinutes(-10) && e.Time <= end.AddSeconds(5)
                                                      && e.Level <= EventSeverity.Warning && e.Category != CatOther).TakeLast(15));
            }
            list.Add(rec);
        }
        list.Reverse(); // mais recente primeiro
        return list;
    }

    /// <summary>Hora do último evento gravado no System antes do boot: o melhor palpite de quando o PC caiu.</summary>
    private static DateTime? LastActivityBefore(DateTime boot)
    {
        try
        {
            string t = boot.AddSeconds(-1).ToUniversalTime().ToString("o");
            using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName,
                $"*[System[TimeCreated[@SystemTime<='{t}']]]") { ReverseDirection = true });
            using var rec = reader.ReadEvent();
            return rec?.TimeCreated;
        }
        catch { return null; }
    }

    private static List<DumpFile> ListDumps()
    {
        var list = new List<DumpFile>();
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        try
        {
            string dir = Path.Combine(win, "Minidump");
            if (Directory.Exists(dir))
                foreach (var f in new DirectoryInfo(dir).GetFiles("*.dmp"))
                    list.Add(new DumpFile(f.FullName, f.LastWriteTime, f.Length));
        }
        catch { }
        try
        {
            var full = new FileInfo(Path.Combine(win, "MEMORY.DMP"));
            if (full.Exists) list.Add(new DumpFile(full.FullName, full.LastWriteTime, full.Length));
        }
        catch { }
        return list.OrderByDescending(d => d.Time).ToList();
    }

    // ---------------- veredito ----------------

    private sealed class Score
    {
        public double Points;
        public readonly List<string> Why = new();
    }

    public static Verdict Diagnose(DiagResult r)
    {
        var crashes = r.Timeline.Where(s => s.IsUnexpected).ToList();
        int whea = r.Events.Count(e => e.Provider == "Microsoft-Windows-WHEA-Logger");
        int gpu = r.Events.Count(e => e.Category == CatGpu);
        int disk = r.Events.Count(e => e.Category == CatDisk && e.Level <= EventSeverity.Error);
        int memLow = r.Events.Count(e => e.Category == CatMemory);
        int bsod = crashes.Count(c => c.Kind == ShutdownKind.BlueScreen);
        int hwFatal = crashes.Count(c => c.Kind == ShutdownKind.HardwareError);
        int button = crashes.Count(c => c.Kind == ShutdownKind.PowerButton);
        int power = crashes.Count(c => c.Kind == ShutdownKind.PowerLoss);

        var scores = new Dictionary<string, Score>();
        Score S(string k) => scores.TryGetValue(k, out var s) ? s : scores[k] = new Score();
        const string KHw = "Instabilidade de CPU/RAM (overclock, XMP/EXPO, undervolt) ou peça com defeito";
        const string KRam = "Memória RAM";
        const string KGpu = "Placa de vídeo ou driver de vídeo";
        const string KDriver = "Driver com defeito";
        const string KDisk = "SSD/HD, cabo ou controlador de disco";
        const string KPsu = "Fonte de alimentação ou energia elétrica";
        const string KHeat = "Superaquecimento";
        const string KMem = "Falta de memória (programa consumindo toda a RAM)";

        if (whea > 0) { S(KHw).Points += Math.Min(whea, 10) * 0.6; S(KHw).Why.Add($"{whea} erros de hardware WHEA no período."); }
        foreach (var c in crashes)
        {
            bool wheaBefore = c.Before.Any(e => e.Category == CatHardware);
            bool gpuBefore = c.Before.Any(e => e.Category == CatGpu);
            bool diskBefore = c.Before.Any(e => e.Category == CatDisk);
            if (wheaBefore) { S(KHw).Points += 3; S(KHw).Why.Add($"Erro WHEA logo antes da queda de {c.Boot:dd/MM HH:mm}."); }
            if (c.AtBoot.Count > 0)
            {
                S(KHw).Points += 4;
                S(KHw).Why.Add($"Erro fatal de hardware registrado ao religar em {c.Boot:dd/MM HH:mm}: {c.AtBoot[0].Message}");
            }
            if (gpuBefore) { S(KGpu).Points += 3; S(KGpu).Why.Add($"Erro de vídeo logo antes da queda de {c.Boot:dd/MM HH:mm}."); }
            if (diskBefore) { S(KDisk).Points += 3; S(KDisk).Why.Add($"Erro de disco logo antes da queda de {c.Boot:dd/MM HH:mm}."); }

            double maxCpu = c.BlackBox.Select(b => b.CpuTemp ?? 0).DefaultIfEmpty(0).Max();
            double maxGpu = c.BlackBox.Select(b => b.GpuTemp ?? 0).DefaultIfEmpty(0).Max();
            if (maxCpu >= 95 || maxGpu >= 88)
            {
                S(KHeat).Points += 4;
                S(KHeat).Why.Add($"Caixa-preta: CPU {maxCpu:0} °C / GPU {maxGpu:0} °C antes da queda de {c.Boot:dd/MM HH:mm}.");
            }

            switch (c.Kind)
            {
                case ShutdownKind.BlueScreen when c.Bugcheck != null:
                    string k = c.Bugcheck.Suspect switch
                    {
                        Suspect.Hardware => KHw, Suspect.Ram => KRam, Suspect.Gpu => KGpu, Suspect.Disk => KDisk, _ => KDriver
                    };
                    S(k).Points += 3;
                    S(k).Why.Add($"Tela azul {c.Bugcheck.CodeText} {c.Bugcheck.Name} em {c.Boot:dd/MM HH:mm}.");
                    break;
                case ShutdownKind.PowerLoss:
                    bool hot = maxCpu >= 95 || maxGpu >= 88;
                    S(KPsu).Points += hot ? 1 : 2.5;
                    S(KPsu).Why.Add($"Desligou sozinho, sem tela azul, em {c.Boot:dd/MM HH:mm}.");
                    if (c.BlackBox.Count == 0) { S(KHeat).Points += 0.8; }
                    break;
                case ShutdownKind.PowerButton:
                    S(KHw).Points += 1.5; S(KGpu).Points += 1; S(KPsu).Points += 0.5;
                    S(KHw).Why.Add($"Travamento total (botão segurado) em {c.Boot:dd/MM HH:mm}.");
                    break;
            }
        }
        if (gpu > 0) { S(KGpu).Points += Math.Min(gpu, 10) * 0.7; S(KGpu).Why.Add($"{gpu} erros/resets do driver de vídeo no período."); }
        if (disk > 0) { S(KDisk).Points += Math.Min(disk, 10) * 0.5; S(KDisk).Why.Add($"{disk} erros de disco/armazenamento no período."); }
        if (memLow > 0) { S(KMem).Points += memLow * 1.5; S(KMem).Why.Add($"{memLow} avisos de memória quase esgotada."); }
        if (scores.TryGetValue(KRam, out var ram)) { S(KHw).Points += ram.Points * 0.3; }

        var ranked = scores.Where(kv => kv.Value.Points >= 1).OrderByDescending(kv => kv.Value.Points).ToList();

        string period = $"Desde {r.Since:dd/MM/yyyy HH:mm}: ";
        string summary;
        if (crashes.Count == 0)
            summary = period + "nenhum desligamento inesperado registrado.";
        else
        {
            int other = crashes.Count - bsod - hwFatal - power - button;
            summary = period + $"{crashes.Count} desligamentos inesperados — {bsod} com tela azul, {hwFatal} por erro fatal de hardware, " +
                      $"{power} sozinho sem aviso, {button} travado no botão" + (other > 0 ? $", {other} sem detalhe" : "") + ".";
        }

        if (ranked.Count == 0)
        {
            if (crashes.Count == 0)
                return new Verdict(DiskVerdict.Good, "Nenhum problema no registro do Windows", summary, new(),
                    new() { "Sem erros de hardware, de vídeo ou de disco relevantes no período. Se o PC travar sem deixar registro, deixe a caixa-preta ligada e volte aqui depois da próxima vez." },
                    new());
            return new Verdict(DiskVerdict.Warning, "Desligamentos sem pista clara", summary, new(),
                new() { "O Windows não registrou erros antes das quedas. Deixe a caixa-preta ligada para ver a temperatura e o consumo na próxima vez." },
                Actions(KPsu).Concat(Actions(KHeat)).ToList());
        }

        var top = ranked[0];
        var why = top.Value.Why.Distinct().Take(6).ToList();
        var notes = new List<string>();
        if (ranked.Count > 1)
            notes.Add("Também considere: " + string.Join("; ", ranked.Skip(1).Take(3).Select(kv => kv.Key)) + ".");
        if (bsod > 0 && r.Dumps.Count == 0)
            notes.Add("Houve tela azul mas nenhum arquivo de despejo foi salvo: em Configurações avançadas do sistema → " +
                      "Inicialização e Recuperação, escolha \"Despejo de memória automático\" e deixe o arquivo de paginação ligado no C:.");

        var level = crashes.Count > 0 ? DiskVerdict.Critical : DiskVerdict.Warning;
        return new Verdict(level, "Causa provável: " + top.Key, summary, why, notes, Actions(top.Key));

        static List<string> Actions(string key) => key switch
        {
            KHw => new()
            {
                "Volte a BIOS para o padrão (desligue XMP/EXPO, PBO/Curve Optimizer, overclock e undervolt) e use o PC alguns dias.",
                "Se parar de cair, religue um ajuste por vez. Rode o Stress test (CPU + RAM) e a verificação de estabilidade do RESET OC.",
                "Atualize a BIOS da placa-mãe. Persistindo com tudo no padrão: teste um pente de RAM por vez e, por fim, a CPU.",
            },
            KRam => new()
            {
                "Desligue o XMP/EXPO na BIOS e veja se as telas azuis param.",
                "Teste a RAM (Diagnóstico de Memória do Windows: mdsched, ou MemTest86) e teste um pente por vez.",
                "Confira se os pentes estão nos slots recomendados pelo manual (geralmente A2 e B2).",
            },
            KGpu => new()
            {
                "Reinstale o driver de vídeo do zero (DDU + driver novo pelo RESET DRIVER) e tire qualquer overclock/undervolt da GPU.",
                "Confira os cabos PCIe da fonte (um cabo por conector, sem adaptador frouxo) e a temperatura no Stress de GPU.",
                "Se cair sempre sob carga de jogo, a fonte pode não aguentar os picos da placa.",
            },
            KDriver => new()
            {
                "Atualize os drivers de chipset, rede/Wi-Fi, áudio e vídeo (RESET DRIVER) e a BIOS.",
                "Desinstale programas que instalam drivers (antivírus de terceiros, VPN, RGB, monitoramento) e teste.",
                "Abra o arquivo de despejo (Minidump) com o WinDbg ou BlueScreenView para ver o nome do driver culpado.",
            },
            KDisk => new()
            {
                "Veja a saúde do disco na aba Discos (S.M.A.R.T.) e faça backup já se houver setores ruins.",
                "Troque o cabo SATA/porta ou reencaixe o SSD NVMe; atualize o firmware do SSD e o driver do chipset/armazenamento.",
                "Rode \"chkdsk C: /scan\" e \"sfc /scannow\" como administrador.",
            },
            KPsu => new()
            {
                "Ligue o PC direto na tomada (sem filtro/régua) e, se possível, num nobreak; confira a tomada e o aterramento.",
                "Confira a fonte: potência suficiente para CPU + GPU, marca confiável, cabos bem encaixados (24 pinos, CPU 8 pinos, PCIe).",
                "Se desliga sob carga (jogo/Stress test), teste com outra fonte. Veja também as temperaturas (pode ser proteção térmica).",
            },
            KHeat => new()
            {
                "Acompanhe as temperaturas em Sensores durante o uso e rode o Stress test com limite de temperatura.",
                "Limpe a poeira, confira as ventoinhas e a bomba do water cooler e troque a pasta térmica se for antiga.",
                "Deixe a caixa-preta ligada: ela mostra a temperatura nos segundos antes de desligar.",
            },
            KMem => new()
            {
                "Veja no Gerenciador de Tarefas qual programa cresce sem parar em memória e atualize/desinstale.",
                "Deixe o arquivo de paginação gerenciado pelo sistema.",
            },
            _ => new()
        };
    }

    // ---------------- relatório em texto ----------------

    public static string ToText(DiagResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"RESET EXPLODE · Eventos e falhas · {Environment.MachineName} · {DateTime.Now:dd/MM/yyyy HH:mm}");
        sb.AppendLine($"Período: desde {r.Since:dd/MM/yyyy HH:mm}");
        sb.AppendLine();
        sb.AppendLine("== " + r.Verdict.Title + " ==");
        sb.AppendLine(r.Verdict.Reasons);
        if (r.Verdict.Actions.Count > 0)
        {
            sb.AppendLine("O que fazer:");
            foreach (var a in r.Verdict.Actions) sb.AppendLine("• " + a);
        }
        sb.AppendLine();
        sb.AppendLine("== Desligamentos e reinícios ==");
        if (r.Timeline.Count == 0) sb.AppendLine("Nenhum início do Windows no período.");
        foreach (var s in r.Timeline)
        {
            sb.AppendLine($"{s.Boot:dd/MM/yyyy HH:mm} · {s.KindText}" + (s.EndTime is DateTime e ? $" (último sinal {e:dd/MM HH:mm:ss})" : ""));
            if (s.Detail.Length > 0 && s.IsUnexpected) sb.AppendLine("   " + s.Detail);
            foreach (var b in s.Before) sb.AppendLine("   antes: " + b.Line);
            foreach (var b in s.AtBoot) sb.AppendLine("   ao religar: " + b.Line);
            if (s.BlackBox.Count > 0) sb.AppendLine("   caixa-preta: " + BlackBox.Summary(s.BlackBox));
        }
        sb.AppendLine();
        sb.AppendLine("== Eventos por categoria ==");
        foreach (var g in r.Events.Where(e => e.Category != CatOther).GroupBy(e => e.Category))
            sb.AppendLine($"{g.Key}: {g.Count()} · último {g.Last().TimeText} · {g.Last().Title}");
        if (r.Dumps.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("== Arquivos de despejo (tela azul) ==");
            foreach (var d in r.Dumps.Take(10)) sb.AppendLine(d.Text);
        }
        sb.AppendLine();
        sb.AppendLine("== Erros e avisos importantes (mais recentes) ==");
        foreach (var e in r.Events.Where(e => e.Category != CatOther && e.Level <= EventSeverity.Warning).Reverse().Take(40))
            sb.AppendLine(e.Line);
        return sb.ToString();
    }

    // ---------------- auxiliares ----------------

    private static Dictionary<string, string> Data(EventRecord rec)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var x = XDocument.Parse(rec.ToXml());
            foreach (var el in x.Descendants().Where(e => e.Name.LocalName == "Data"))
                if (el.Attribute("Name")?.Value is string n) d[n] = el.Value;
        }
        catch { }
        return d;
    }

    private static uint ParseUInt(string? s) =>
        s == null ? 0 : s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? ParseHex(s)
        : ulong.TryParse(s, out ulong v) ? (uint)Math.Min(v, uint.MaxValue) : 0;

    private static uint ParseHex(string? s)
    {
        if (s == null) return 0;
        var m = Regex.Match(s, @"0x([0-9A-Fa-f]{1,16})");
        return m.Success && ulong.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out ulong v) ? (uint)v : 0;
    }

    private static string FirstLine(string s)
    {
        s = s.Trim();
        int i = s.IndexOfAny(new[] { '\r', '\n' });
        if (i >= 0) s = s[..i].Trim();
        return s.Length > 220 ? s[..220] + "…" : s;
    }
}
