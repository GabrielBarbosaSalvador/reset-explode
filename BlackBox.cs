using System.Globalization;
using System.IO;
using System.Text;

namespace ResetExplode;

public sealed record BlackBoxSample(DateTime Time, float? CpuTemp, float? CpuLoad, float? CpuPower,
                                    float? GpuTemp, float? GpuLoad, float? GpuPower);

/// <summary>
/// Caixa-preta: enquanto o app está aberto, grava temperatura, carga e consumo de CPU e GPU a cada 5 s em
/// %AppData%\ResetExplode\caixa-preta\AAAA-MM-DD.csv, gravando direto no disco para sobreviver a uma queda de energia.
/// Depois de um desligamento inesperado mostra os últimos valores antes de o PC cair.
/// </summary>
public sealed class BlackBox : IDisposable
{
    public const int IntervalSeconds = 5;
    private const int KeepDays = 7;
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Folder { get; } = Path.Combine(AppSettings.Folder, "caixa-preta");

    private FileStream? _fs;
    private StreamWriter? _w;
    private DateTime _fileDay;
    private int _ticks;
    public bool Enabled { get; private set; }
    public DateTime? LastSample { get; private set; }

    public void SetEnabled(bool on)
    {
        if (on == Enabled) return;
        Enabled = on;
        if (on) { Cleanup(); Write("#start;" + DateTime.Now.ToString("s", Inv)); }
        else Stop();
    }

    /// <summary>Chamado a cada segundo pelo timer de sensores; grava uma linha a cada <see cref="IntervalSeconds"/>.</summary>
    public void Tick(float? cpuTemp, float? cpuLoad, float? cpuPower, float? gpuTemp, float? gpuLoad, float? gpuPower)
    {
        if (!Enabled || ++_ticks % IntervalSeconds != 0) return;
        var now = DateTime.Now;
        Write(string.Join(';', now.ToString("s", Inv), F(cpuTemp), F(cpuLoad), F(cpuPower), F(gpuTemp), F(gpuLoad), F(gpuPower)));
        LastSample = now;
    }

    /// <summary>Marca que o app foi fechado normalmente (o fim da gravação não é uma queda).</summary>
    public void Stop()
    {
        if (_w != null) Write("#stop;" + DateTime.Now.ToString("s", Inv));
        _w?.Dispose(); _w = null; _fs = null;
    }

    public void Dispose() => Stop();

    private void Write(string line)
    {
        try
        {
            var day = DateTime.Today;
            if (_w == null || day != _fileDay)
            {
                _w?.Dispose();
                Directory.CreateDirectory(Folder);
                _fs = new FileStream(Path.Combine(Folder, $"{day:yyyy-MM-dd}.csv"), FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                _w = new StreamWriter(_fs, new UTF8Encoding(false));
                if (_fs.Length == 0) _w.WriteLine("hora;cpu_temp;cpu_carga;cpu_w;gpu_temp;gpu_carga;gpu_w");
                _fileDay = day;
            }
            _w.WriteLine(line);
            _w.Flush();
            _fs!.Flush(flushToDisk: true);
        }
        catch { }
    }

    private static void Cleanup()
    {
        try
        {
            if (!Directory.Exists(Folder)) return;
            foreach (var f in new DirectoryInfo(Folder).GetFiles("*.csv"))
                if (f.LastWriteTime < DateTime.Now.AddDays(-KeepDays)) f.Delete();
        }
        catch { }
    }

    /// <summary>
    /// Últimos ~60 s gravados antes do boot. Vazio se o app foi fechado normalmente antes da queda
    /// ou se não estava aberto perto da hora do último evento do Windows.
    /// </summary>
    public List<BlackBoxSample> SamplesBefore(DateTime boot, DateTime? lastActivity)
    {
        var samples = new List<BlackBoxSample>();
        bool stoppedAfterLast = false;
        for (int back = 2; back >= 0; back--)
        {
            string path = Path.Combine(Folder, $"{boot.Date.AddDays(-back):yyyy-MM-dd}.csv");
            if (!File.Exists(path)) continue;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var r = new StreamReader(fs);
                for (string? line = r.ReadLine(); line != null; line = r.ReadLine())
                {
                    var p = line.Split(';');
                    if (p.Length < 2) continue;
                    if (p[0] == "#stop" || p[0] == "#start")
                    {
                        if (DateTime.TryParse(p[1], Inv, DateTimeStyles.None, out var mt) && mt < boot)
                            stoppedAfterLast = p[0] == "#stop";
                        continue;
                    }
                    if (p.Length < 7 || !DateTime.TryParse(p[0], Inv, DateTimeStyles.None, out var t) || t >= boot) continue;
                    samples.Add(new BlackBoxSample(t, P(p[1]), P(p[2]), P(p[3]), P(p[4]), P(p[5]), P(p[6])));
                    stoppedAfterLast = false;
                }
            }
            catch { }
        }
        if (samples.Count == 0 || stoppedAfterLast) return new();
        var last = samples[^1].Time;
        if (boot - last > TimeSpan.FromDays(1)) return new();
        if (lastActivity is DateTime la && last < la.AddMinutes(-2)) return new();
        return samples.Where(s => s.Time >= last.AddSeconds(-60)).ToList();
    }

    /// <summary>Resumo de uma janela de amostras: máximos e o último valor.</summary>
    public static string Summary(List<BlackBoxSample> s)
    {
        if (s.Count == 0) return "";
        var l = s[^1];
        string Max(Func<BlackBoxSample, float?> f, string unit) =>
            s.Select(f).Where(v => v != null).Select(v => v!.Value).DefaultIfEmpty(float.NaN).Max() is float m && !float.IsNaN(m) ? $"{m:0}{unit}" : "—";
        return $"último registro {l.Time:HH:mm:ss} · CPU máx. {Max(x => x.CpuTemp, " °C")}, {Max(x => x.CpuLoad, " %")}, {Max(x => x.CpuPower, " W")}" +
               $" · GPU máx. {Max(x => x.GpuTemp, " °C")}, {Max(x => x.GpuLoad, " %")}, {Max(x => x.GpuPower, " W")}";
    }

    private static string F(float? v) => v is float f && !float.IsNaN(f) ? f.ToString("0.#", Inv) : "";
    private static float? P(string s) => float.TryParse(s, NumberStyles.Float, Inv, out var v) ? v : null;
}
