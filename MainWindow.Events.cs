using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ResetExplode;

/// <summary>Um número em destaque no cartão do veredito (ex.: "3" telas azuis).</summary>
public sealed record EvStat(string Key, string Value);
/// <summary>Uma recomendação numerada em "O que fazer".</summary>
public sealed record EvActionVm(string Num, string Text);
/// <summary>Um desligamento inesperado na linha do tempo, já com os textos prontos para a tela.</summary>
public sealed record EvShutdownVm(string Day, string Clock, string? LastSignal, string Kind, string Badge,
                                  bool Alert, string Detail, List<string> Before, bool HasBefore,
                                  List<EvStat> BlackBox, bool HasBlackBox);

/// <summary>Aba RESET EXPLODE · Eventos e falhas: por que o PC reiniciou, desligou ou travou, e a caixa-preta.</summary>
public partial class MainWindow
{
    private const int EvListMax = 300;
    private DiagResult? _evResult;
    private bool _evLoading;
    private int _evHours = 168;
    private string? _evCategory; // null = importantes (sem "Outros"), "*" = todos

    private void InitEvents()
    {
        ChkBlackBox.IsChecked = _settings.BlackBoxEnabled;
        UpdateBlackBoxInfo();
        if (_evResult == null) _ = ScanEventsAsync();
    }

    private async Task ScanEventsAsync()
    {
        if (_evLoading) return;
        _evLoading = true;
        BtnEvScan.IsEnabled = false;
        EvStatus.Text = "Lendo o registro de eventos do Windows…";
        try
        {
            var since = DateTime.Now.AddHours(-_evHours);
            var res = await Task.Run(() => EventDiagnostics.Read(since, _blackBox));
            _evResult = res;
            ShowEventLog(res);
        }
        finally
        {
            _evLoading = false;
            BtnEvScan.IsEnabled = true;
        }
    }

    private void ShowEventLog(DiagResult r)
    {
        BtnEvCopy.IsEnabled = r.Error == null;
        if (r.Error != null)
        {
            EvStatus.Text = $"Não foi possível ler o registro de eventos: {r.Error}";
            EvVerdictCard.Visibility = Visibility.Collapsed;
            EvTimeline.ItemsSource = null; EvList.ItemsSource = null;
            return;
        }
        EvVerdictCard.Visibility = Visibility.Visible;
        EvStatus.Text = $"{r.Events.Count} eventos lidos desde {r.Since:dd/MM/yyyy HH:mm} · atualizado {DateTime.Now:HH:mm:ss}" +
                        (r.Truncated ? " · período longo: só os mais recentes foram lidos" : "");

        ShowVerdict(r);
        var vms = TimelineVms(r);
        EvTimeline.ItemsSource = vms;

        var normal = r.Timeline.Where(s => !s.IsUnexpected).ToList();
        string normalText = normal.Count == 0 ? "" :
            $"{normal.Count} inícios normais no período. Mais recentes: " +
            string.Join(" · ", normal.Take(4).Select(s => $"{s.Boot:dd/MM HH:mm} {s.KindText}"));
        string text = vms.Count == 0
            ? "Nenhum desligamento inesperado no período." + (normalText.Length > 0 ? "\n" + normalText : "")
            : normalText;
        EvTimelineEmpty.Text = text;
        EvTimelineEmpty.Visibility = text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

        EvDumps.Text = r.Dumps.Count == 0
            ? "Nenhum arquivo de despejo encontrado."
            : string.Join("\n", r.Dumps.Take(10).Select(d => d.Text)) + (r.Dumps.Count > 10 ? $"\n… e mais {r.Dumps.Count - 10}" : "");

        BuildEventChips(r);
        ShowEventList();
    }

    private void ShowVerdict(DiagResult r)
    {
        var v = r.Verdict;
        EvVerdictBadge.Text = v.Level switch
        {
            DiskVerdict.Good => "TUDO CERTO",
            DiskVerdict.Critical => "PROBLEMA",
            DiskVerdict.Warning => "ATENÇÃO",
            _ => "—"
        };
        EvVerdictTitle.Text = v.Title;
        EvVerdictSummary.Text = v.Summary;
        EvStats.ItemsSource = VerdictStats(r);
        EvWhy.ItemsSource = v.Why;
        EvWhyCol.Visibility = v.Why.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        EvActions.ItemsSource = v.Actions.Select((a, i) => new EvActionVm((i + 1).ToString(), a)).ToList();
        EvActionsCol.Visibility = v.Actions.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        EvVerdictDetail.Visibility = v.Why.Count > 0 || v.Actions.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        EvVerdictNotes.Text = string.Join("\n\n", v.Notes);
        EvVerdictNotes.Visibility = v.Notes.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        EvVerdictCard.BorderBrush = (Brush)FindResource(v.Level == DiskVerdict.Critical ? "LineStrong" : "Line");
    }

    private static List<EvStat> VerdictStats(DiagResult r) => new()
    {
        new("Desligamentos\ninesperados", r.Timeline.Count(s => s.IsUnexpected).ToString()),
        new("Telas\nazuis", r.Timeline.Count(s => s.Kind == ShutdownKind.BlueScreen).ToString()),
        new("Erros de\nhardware (WHEA)", r.Events.Count(e => e.Provider == "Microsoft-Windows-WHEA-Logger").ToString()),
        new("Erros de\nvídeo", r.Events.Count(e => e.Category == EventDiagnostics.CatGpu).ToString()),
        new("Erros de\ndisco", r.Events.Count(e => e.Category == EventDiagnostics.CatDisk).ToString()),
    };

    private static List<EvShutdownVm> TimelineVms(DiagResult r)
    {
        var list = new List<EvShutdownVm>();
        foreach (var s in r.Timeline.Where(x => x.IsUnexpected))
        {
            var before = s.Before.Select(e => $"{e.TimeText} · {e.Title}" + (e.Explain.Length > 0 ? $" — {e.Explain}" : "")).ToList();
            foreach (var e in s.AtBoot) before.Add($"Ao religar · {e.Title} — {e.Message}");

            var bb = new List<EvStat>();
            if (s.BlackBox.Count > 0)
            {
                string Max(Func<BlackBoxSample, float?> f, string unit) =>
                    s.BlackBox.Select(f).Where(x => x != null).Select(x => x!.Value).DefaultIfEmpty(float.NaN).Max() is float x2 && !float.IsNaN(x2) ? $"{x2:0}{unit}" : "—";
                bb.Add(new("CPU temp.", Max(b => b.CpuTemp, " °C")));
                bb.Add(new("GPU temp.", Max(b => b.GpuTemp, " °C")));
                bb.Add(new("CPU carga", Max(b => b.CpuLoad, " %")));
                bb.Add(new("CPU consumo", Max(b => b.CpuPower, " W")));
                bb.Add(new("GPU consumo", Max(b => b.GpuPower, " W")));
                bb.Add(new("Último registro", s.BlackBox[^1].Time.ToString("HH:mm:ss")));
            }

            bool alert = s.Kind is ShutdownKind.BlueScreen or ShutdownKind.HardwareError;
            string badge = s.Kind switch
            {
                ShutdownKind.BlueScreen => "TELA AZUL",
                ShutdownKind.HardwareError => "HARDWARE",
                ShutdownKind.PowerButton => "TRAVOU",
                ShutdownKind.PowerLoss => "DESLIGOU",
                _ => "INESPERADO"
            };
            string title = s.Kind == ShutdownKind.BlueScreen && s.Bugcheck != null
                ? $"Tela azul {s.Bugcheck.CodeText} · {s.Bugcheck.Name}"
                : s.KindText;
            string? last = s.EndTime is DateTime e2 ? $"último sinal {e2:dd/MM HH:mm}"
                         : s.BlackBox.Count == 0 ? "sem caixa-preta" : null;
            list.Add(new EvShutdownVm(s.Boot.ToString("ddd dd/MM"), s.Boot.ToString("HH:mm"), last,
                                      title, badge, alert, s.Detail, before, before.Count > 0, bb, bb.Count > 0));
        }
        return list;
    }

    /// <summary>Cartão do veredito seguido de um cartão por desligamento inesperado (usado no relatório exportado).</summary>
    private static IEnumerable<DiskHealthCard> EventCards(DiagResult r)
    {
        var v = r.Verdict;
        var metrics = new List<KeyValuePair<string, string>>
        {
            new("Desligamentos inesperados", r.Timeline.Count(s => s.IsUnexpected).ToString()),
            new("Telas azuis", r.Timeline.Count(s => s.Kind == ShutdownKind.BlueScreen).ToString()),
        };
        foreach (var cat in new[] { EventDiagnostics.CatHardware, EventDiagnostics.CatGpu, EventDiagnostics.CatDisk, EventDiagnostics.CatMemory, EventDiagnostics.CatApps })
            metrics.Add(new(cat, r.Events.Count(e => e.Category == cat).ToString()));
        yield return new DiskHealthCard
        {
            Title = v.Title,
            Meta = $"Período: desde {r.Since:dd/MM/yyyy HH:mm} · {r.Dumps.Count} arquivos de despejo",
            Verdict = v.Level,
            Label = v.Level switch { DiskVerdict.Good => "TUDO CERTO", DiskVerdict.Critical => "PROBLEMA", _ => "ATENÇÃO" },
            Reasons = v.Reasons + (v.Actions.Count > 0 ? "\n\nO que fazer:\n" + string.Join("\n", v.Actions.Select(a => "• " + a)) : ""),
            Metrics = metrics,
        };

        foreach (var s in r.Timeline.Where(s => s.IsUnexpected))
        {
            string reasons = s.Detail;
            reasons += s.Before.Count > 0
                ? "\n\nNos 10 minutos antes:\n" + string.Join("\n", s.Before.Select(e => $"• {e.TimeText} · {e.Title}" + (e.Explain.Length > 0 ? $" — {e.Explain}" : "")))
                : "\n\nNenhum erro registrado nos 10 minutos antes (comum em queda de energia ou travamento total).";
            if (s.AtBoot.Count > 0)
                reasons += "\n\nAo religar, o Windows registrou:\n" + string.Join("\n", s.AtBoot.Select(e => $"• {e.TimeText} · {e.Title} — {e.Message}"));
            var m = new List<KeyValuePair<string, string>>();
            if (s.BlackBox.Count > 0)
            {
                string Max(Func<BlackBoxSample, float?> f, string unit) =>
                    s.BlackBox.Select(f).Where(x => x != null).Select(x => x!.Value).DefaultIfEmpty(float.NaN).Max() is float x2 && !float.IsNaN(x2) ? $"{x2:0}{unit}" : "—";
                m.Add(new("CPU · temperatura máx.", Max(b => b.CpuTemp, " °C")));
                m.Add(new("GPU · temperatura máx.", Max(b => b.GpuTemp, " °C")));
                m.Add(new("CPU · carga / consumo máx.", $"{Max(b => b.CpuLoad, " %")} / {Max(b => b.CpuPower, " W")}"));
                m.Add(new("GPU · carga / consumo máx.", $"{Max(b => b.GpuLoad, " %")} / {Max(b => b.GpuPower, " W")}"));
                m.Add(new("Caixa-preta · último registro", $"{s.BlackBox[^1].Time:dd/MM HH:mm:ss}"));
            }
            yield return new DiskHealthCard
            {
                Title = s.KindText,
                Meta = $"Religou em {s.Boot:dd/MM/yyyy HH:mm:ss}" + (s.EndTime is DateTime e ? $" · último sinal {e:dd/MM HH:mm:ss}" : "") +
                       (s.BlackBox.Count == 0 ? " · sem caixa-preta" : ""),
                Verdict = DiskVerdict.Critical,
                Label = s.Kind switch
                {
                    ShutdownKind.BlueScreen => "TELA AZUL",
                    ShutdownKind.HardwareError => "ERRO DE HARDWARE",
                    ShutdownKind.PowerButton => "TRAVOU",
                    ShutdownKind.PowerLoss => "DESLIGOU",
                    _ => "INESPERADO"
                },
                Reasons = reasons,
                Metrics = m,
            };
        }
    }

    private void BuildEventChips(DiagResult r)
    {
        EvCats.Children.Clear();
        void Chip(string text, string? tag)
        {
            var rb = new RadioButton
            {
                Style = (Style)FindResource("Chip"), GroupName = "EvCat", Content = text, Tag = tag,
                IsChecked = tag == _evCategory,
            };
            rb.Checked += (_, _) => { _evCategory = (string?)rb.Tag; ShowEventList(); };
            EvCats.Children.Add(rb);
        }
        Chip("IMPORTANTES", null);
        foreach (var cat in EventDiagnostics.Categories)
        {
            int n = r.Events.Count(e => e.Category == cat);
            if (n > 0) Chip($"{cat.ToUpperInvariant()} ({n})", cat);
        }
        Chip($"TODOS ({r.Events.Count})", "*");
    }

    private void ShowEventList()
    {
        if (_evResult == null) return;
        var all = _evResult.Events.AsEnumerable().Reverse();
        var filtered = (_evCategory switch
        {
            null => all.Where(e => e.Category != EventDiagnostics.CatOther),
            "*" => all,
            var c => all.Where(e => e.Category == c),
        }).ToList();
        EvList.ItemsSource = filtered.Take(EvListMax).ToList();
        EvSummary.Text = $"EVENTOS · {filtered.Count}";
        EvListMore.Text = filtered.Count > EvListMax
            ? $"Mostrando os {EvListMax} mais recentes de {filtered.Count}. Use COPIAR RELATÓRIO ou o Visualizador de Eventos (eventvwr) para ver tudo."
            : filtered.Count == 0 ? "Nenhum evento nesta categoria." : "";
    }

    private void UpdateBlackBoxInfo()
    {
        string files = "";
        try
        {
            if (Directory.Exists(BlackBox.Folder))
            {
                var f = new DirectoryInfo(BlackBox.Folder).GetFiles("*.csv");
                files = $" · {f.Length} arquivos, {f.Sum(x => x.Length) / 1024.0:N0} KB";
            }
        }
        catch { }
        EvBlackBoxInfo.Text = !_blackBox.Enabled ? "Desligada." + files
            : (_blackBox.LastSample is DateTime t ? $"Gravando · último registro {t:HH:mm:ss}" : "Gravando · primeiro registro em instantes") + files;
    }

    private void EvRange_Checked(object sender, RoutedEventArgs e)
    {
        if (EvStatus == null || sender is not FrameworkElement { Tag: string tag }) return; // durante InitializeComponent
        _evHours = int.Parse(tag);
        if (PageEvents.IsVisible) _ = ScanEventsAsync();
        else _evResult = null;
    }

    private void BtnEvScan_Click(object sender, RoutedEventArgs e)
    {
        UpdateBlackBoxInfo();
        _ = ScanEventsAsync();
    }

    private void BtnEvCopy_Click(object sender, RoutedEventArgs e)
    {
        if (_evResult == null) return;
        try
        {
            Clipboard.SetText(EventDiagnostics.ToText(_evResult));
            EvStatus.Text = "Relatório copiado. Cole em um fórum, no suporte técnico ou numa conversa para pedir ajuda.";
        }
        catch (Exception ex) { EvStatus.Text = $"Não foi possível copiar: {ex.Message}"; }
    }

    private void BtnEvDumps_Click(object sender, RoutedEventArgs e)
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump");
        if (!Directory.Exists(dir)) { EvStatus.Text = "A pasta Minidump não existe: o Windows ainda não salvou nenhuma tela azul."; return; }
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true }); } catch { }
    }

    private void BtnEvBlackBoxFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(BlackBox.Folder);
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{BlackBox.Folder}\"") { UseShellExecute = true }); } catch { }
    }

    private void ChkBlackBox_Click(object sender, RoutedEventArgs e)
    {
        bool on = ChkBlackBox.IsChecked == true;
        _blackBox.SetEnabled(on);
        _settings.BlackBoxEnabled = on;
        _settings.Save();
        UpdateBlackBoxInfo();
    }
}
