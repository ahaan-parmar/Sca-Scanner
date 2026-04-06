import { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft, RefreshCw, ShieldCheck, Copy, Check,
  ChevronDown, ChevronUp, AlertTriangle, Loader2, Clock,
  Download, Search, FileDown,
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";

const API = "http://localhost:3001";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type FilterLevel = "ALL" | RiskLevel;

interface CveFinding {
  id: string;
  severity: string;
  cvssScore: number;
  summary: string;
  url: string;
  fixedIn: string | null;
}

interface ScanResult {
  package: string;
  version: string;
  risk: { level: RiskLevel; score: number };
  findings: {
    cve?: CveFinding[];
    scripts?: { type: string; detail: string }[];
    typosquat?: { match: string; distance: number }[];
    maintainer?: string[];
    license?: { type: string; detail: string }[];
  };
  popularity?: { data?: { weeklyDownloads?: number } };
}

interface Scan {
  id: number;
  scanned_at: string;
  summary: { total: number; errors: number; byLevel: Record<RiskLevel, number> };
  results: ScanResult[];
}

interface Project {
  id: number;
  name: string;
  github_url: string | null;
  created_at: string;
  last_scanned_at: string | null;
  latestScan: Scan | null;
}

interface HistoryEntry {
  id: number;
  scanned_at: string;
  summary: { total: number; byLevel: Record<RiskLevel, number> };
}

const RISK_COLORS: Record<RiskLevel, string> = {
  LOW:      "text-green-400  border-green-800  bg-green-950/30",
  MEDIUM:   "text-yellow-400 border-yellow-800 bg-yellow-950/30",
  HIGH:     "text-orange-400 border-orange-800 bg-orange-950/30",
  CRITICAL: "text-red-400    border-red-800    bg-red-950/30",
};
const RISK_DOT: Record<RiskLevel, string> = {
  LOW: "bg-green-400", MEDIUM: "bg-yellow-400", HIGH: "bg-orange-400", CRITICAL: "bg-red-400",
};

function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${RISK_COLORS[level]}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${RISK_DOT[level]}`} />
      {level}
    </span>
  );
}

function ResultRow({ result, idx }: { result: ScanResult; idx: number }) {
  const [open, setOpen] = useState(false);
  const cves        = result.findings?.cve ?? [];
  const cveCount    = cves.length;
  const scriptCount = result.findings?.scripts?.length ?? 0;
  const downloads   = result.popularity?.data?.weeklyDownloads;
  const fixable     = cves.filter((c) => c.fixedIn).length;

  return (
    <div className={`rounded-lg border border-border bg-card transition-all ${open ? "ring-1 ring-primary/30" : ""}`}>
      <button className="flex w-full items-center gap-3 px-4 py-3 text-left" onClick={() => setOpen(!open)}>
        <span className="w-6 text-xs text-muted-foreground tabular-nums">{idx + 1}</span>
        <span className="flex-1 font-mono text-sm font-medium text-foreground truncate">
          {result.package}
          <span className="ml-1.5 text-xs text-muted-foreground">v{result.version}</span>
        </span>
        <div className="flex items-center gap-3">
          {cveCount > 0    && <span className="text-xs text-orange-400">{cveCount} CVE{cveCount > 1 ? "s" : ""}</span>}
          {fixable > 0     && <span className="text-xs text-green-400">↑ {fixable} fixable</span>}
          {scriptCount > 0 && <span className="text-xs text-yellow-400">{scriptCount} script flag{scriptCount > 1 ? "s" : ""}</span>}
          <RiskBadge level={result.risk.level} />
          <span className="w-8 text-right text-xs text-muted-foreground tabular-nums">{result.risk.score}</span>
          {open ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
        </div>
      </button>

      {open && (
        <div className="border-t border-border px-4 py-3 text-xs text-muted-foreground space-y-2">
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-3">
            <div>
              <span className="uppercase tracking-wide font-semibold">Risk Score</span>
              <p className="mt-0.5 text-foreground">{result.risk.score} / 100</p>
            </div>
            {(result.findings?.license ?? []).length > 0 && (
              <div>
                <span className="uppercase tracking-wide font-semibold">License</span>
                <p className="mt-0.5 text-foreground">{result.findings!.license![0]?.detail || "—"}</p>
              </div>
            )}
            {downloads != null && (
              <div>
                <span className="uppercase tracking-wide font-semibold">Weekly Downloads</span>
                <p className="mt-0.5 text-foreground">{downloads.toLocaleString()}</p>
              </div>
            )}
            {(result.findings?.typosquat ?? []).length > 0 && (
              <div>
                <span className="uppercase tracking-wide font-semibold">Typosquat</span>
                <p className="mt-0.5 text-orange-400">Similar to: {result.findings!.typosquat![0].match}</p>
              </div>
            )}
          </div>

          {cveCount > 0 && (
            <div>
              <span className="uppercase tracking-wide font-semibold">CVEs</span>
              <div className="mt-1 space-y-1.5">
                {cves.slice(0, 8).map((cve) => (
                  <div key={cve.id} className="flex items-start gap-2 rounded bg-orange-950/30 px-2 py-1.5">
                    <a
                      href={cve.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-orange-400 hover:underline shrink-0"
                    >
                      {cve.id}
                    </a>
                    <span className="flex-1 text-muted-foreground">{cve.summary}</span>
                    {cve.fixedIn && (
                      <span className="shrink-0 rounded bg-green-950/50 px-1.5 py-0.5 text-green-400 font-mono">
                        fix: {cve.fixedIn}
                      </span>
                    )}
                  </div>
                ))}
                {cves.length > 8 && (
                  <p className="text-muted-foreground">+{cves.length - 8} more CVEs</p>
                )}
              </div>
            </div>
          )}

          {scriptCount > 0 && (
            <div>
              <span className="uppercase tracking-wide font-semibold">Script Flags</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {result.findings!.scripts!.map((s, i) => (
                  <span key={i} className="rounded bg-yellow-950/40 px-1.5 py-0.5 text-yellow-400 font-mono">{s.type}</span>
                ))}
              </div>
            </div>
          )}

          {(result.findings?.maintainer ?? []).length > 0 && (
            <div>
              <span className="uppercase tracking-wide font-semibold">Maintainer Flags</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {result.findings!.maintainer!.map((f, i) => (
                  <span key={i} className="rounded bg-secondary px-1.5 py-0.5 text-foreground">{f}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function formatDate(dateStr: string): string {
  return new Date(dateStr + "Z").toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const [project, setProject]       = useState<Project | null>(null);
  const [history, setHistory]       = useState<HistoryEntry[]>([]);
  const [loading, setLoading]       = useState(true);
  const [scanning, setScanning]     = useState(false);
  const [progress, setProgress]     = useState(0);
  const [currentPkg, setCurrentPkg] = useState("");
  const [scanError, setScanError]   = useState("");
  const [copied, setCopied]         = useState(false);
  const [filterLevel, setFilterLevel] = useState<FilterLevel>("ALL");
  const [search, setSearch]         = useState("");

  async function load() {
    const [pRes, hRes] = await Promise.all([
      fetch(`${API}/api/projects/${id}`),
      fetch(`${API}/api/projects/${id}/history`),
    ]);
    setProject(await pRes.json());
    setHistory(await hRes.json());
    setLoading(false);
  }

  useEffect(() => { load(); }, [id]);

  const triggerScan = useCallback(async () => {
    setScanError("");
    setScanning(true);
    setProgress(0);
    setCurrentPkg("");

    try {
      const resp = await fetch(`${API}/api/projects/${id}/scan`, { method: "POST" });
      if (!resp.ok || !resp.body) {
        const { error } = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
        setScanError(error || "Scan failed");
        setScanning(false);
        return;
      }

      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() ?? "";

        for (const chunk of lines) {
          const dataLine = chunk.split("\n").find((l) => l.startsWith("data: "));
          if (!dataLine) continue;
          try {
            const event = JSON.parse(dataLine.slice(6));
            if (event.type === "scanning") {
              setCurrentPkg(event.package);
              setProgress(Math.round(((event.index - 1) / event.total) * 100));
            } else if (event.type === "done") {
              setProgress(100);
            }
          } catch { /* skip */ }
        }
      }

      await load();
    } catch (err: unknown) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanning(false);
      setCurrentPkg("");
    }
  }, [id]);

  function copyBadge() {
    const md = `[![safe-npm](${API}/api/badge/${id})](http://localhost:8080/projects/${id})`;
    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function downloadExport(format: "json" | "csv") {
    window.open(`${API}/api/projects/${id}/export?format=${format}`, "_blank");
  }

  function downloadSBOM() {
    window.open(`${API}/api/projects/${id}/sbom`, "_blank");
  }

  if (loading) {
    return (
      <div className="container mx-auto px-4 py-10">
        <div className="text-sm text-muted-foreground">Loading…</div>
      </div>
    );
  }

  if (!project || (project as unknown as { error: string }).error) {
    return (
      <div className="container mx-auto px-4 py-10">
        <p className="text-muted-foreground">Project not found.</p>
        <Link to="/projects" className="mt-4 inline-flex items-center gap-1 text-sm text-primary">
          <ArrowLeft className="h-4 w-4" /> Back to Projects
        </Link>
      </div>
    );
  }

  const scan    = project.latestScan;
  const byLevel = scan?.summary.byLevel;
  const sorted  = scan ? [...scan.results].sort((a, b) => b.risk.score - a.risk.score) : [];
  const LEVELS: FilterLevel[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

  const filtered = sorted.filter((r) => {
    const matchesLevel = filterLevel === "ALL" || r.risk.level === filterLevel;
    const matchesSearch = search === "" || r.package.toLowerCase().includes(search.toLowerCase());
    return matchesLevel && matchesSearch;
  });

  const chartData = history.map((h) => ({
    date:     formatDate(h.scanned_at),
    Critical: h.summary.byLevel.CRITICAL,
    High:     h.summary.byLevel.HIGH,
    Medium:   h.summary.byLevel.MEDIUM,
    Low:      h.summary.byLevel.LOW,
  }));

  return (
    <div className="container mx-auto max-w-5xl px-4 py-10 space-y-8">
      {/* Header */}
      <div>
        <Link to="/projects" className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" /> Projects
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-foreground">{project.name}</h1>
            {project.github_url && (
              <a href={project.github_url} target="_blank" rel="noopener noreferrer"
                className="mt-1 flex items-center gap-1 text-sm text-muted-foreground hover:text-primary">
                {project.github_url}
              </a>
            )}
            {project.last_scanned_at && (
              <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                <Clock className="h-3 w-3" />
                Last scanned {new Date(project.last_scanned_at + "Z").toLocaleString()}
              </p>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {scan && (
              <>
                <button
                  onClick={() => downloadExport("json")}
                  className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground transition-colors hover:text-foreground"
                >
                  <Download className="h-3.5 w-3.5" /> JSON
                </button>
                <button
                  onClick={() => downloadExport("csv")}
                  className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground transition-colors hover:text-foreground"
                >
                  <Download className="h-3.5 w-3.5" /> CSV
                </button>
                <button
                  onClick={downloadSBOM}
                  className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground transition-colors hover:text-foreground"
                  title="Download CycloneDX SBOM"
                >
                  <FileDown className="h-3.5 w-3.5" /> SBOM
                </button>
              </>
            )}
            <button
              onClick={copyBadge}
              className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground transition-colors hover:text-foreground"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? "Copied!" : "Copy Badge"}
            </button>
            <button
              onClick={triggerScan}
              disabled={scanning}
              className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-50"
            >
              {scanning
                ? <><Loader2 className="h-4 w-4 animate-spin" /> Scanning…</>
                : <><RefreshCw className="h-4 w-4" /> Rescan</>}
            </button>
          </div>
        </div>
      </div>

      {/* Scan progress */}
      {scanning && (
        <div>
          <div className="flex justify-between text-xs text-muted-foreground mb-1.5">
            <span className="truncate">Scanning {currentPkg || "…"}</span>
            <span className="tabular-nums">{progress}%</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
            <div className="h-full rounded-full bg-primary transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {scanError && (
        <div className="flex items-start gap-2 rounded-lg border border-orange-800 bg-orange-950/30 px-4 py-3 text-sm text-orange-400">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" /> {scanError}
        </div>
      )}

      {/* Summary cards */}
      {byLevel && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as RiskLevel[]).map((lvl) => (
            <div key={lvl} className={`rounded-lg border px-4 py-3 ${RISK_COLORS[lvl]}`}>
              <p className="text-2xl font-bold tabular-nums">{byLevel[lvl] ?? 0}</p>
              <p className="mt-0.5 text-xs font-semibold uppercase tracking-wide">{lvl}</p>
            </div>
          ))}
          <div className="rounded-lg border border-border bg-card px-4 py-3">
            <p className="text-2xl font-bold tabular-nums text-foreground">{scan!.summary.total}</p>
            <p className="mt-0.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Total</p>
          </div>
        </div>
      )}

      {!scan && !scanning && (
        <div className="flex flex-col items-center gap-4 rounded-xl border border-dashed border-border py-16 text-center">
          <ShieldCheck className="h-10 w-10 text-muted-foreground/30" />
          <p className="text-muted-foreground">No scans yet.</p>
          <button
            onClick={triggerScan}
            className="rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground hover:bg-primary/90"
          >
            Run First Scan
          </button>
        </div>
      )}

      {/* Risk trend chart */}
      {chartData.length > 1 && (
        <div>
          <h2 className="mb-4 text-lg font-semibold text-foreground">Risk Trend</h2>
          <div className="rounded-xl border border-border bg-card p-4">
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: "#6b7280" }} />
                <YAxis tick={{ fontSize: 11, fill: "#6b7280" }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#111827", border: "1px solid #1f2937", borderRadius: "8px", fontSize: "12px" }}
                  labelStyle={{ color: "#f9fafb" }}
                />
                <Legend wrapperStyle={{ fontSize: "12px" }} />
                <Line type="monotone" dataKey="Critical" stroke="#dc2626" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="High"     stroke="#ea580c" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="Medium"   stroke="#d97706" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="Low"      stroke="#16a34a" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Results list */}
      {sorted.length > 0 && (
        <div>
          <h2 className="mb-3 text-lg font-semibold text-foreground">Packages</h2>

          {/* Filter bar */}
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[160px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search packages…"
                className="w-full rounded-lg border border-border bg-background pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="flex items-center gap-1">
              {LEVELS.map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setFilterLevel(lvl)}
                  className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                    filterLevel === lvl
                      ? "bg-primary text-primary-foreground"
                      : "border border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {lvl === "ALL" ? `All (${sorted.length})` : `${lvl} (${byLevel?.[lvl] ?? 0})`}
                </button>
              ))}
            </div>
          </div>

          {filtered.length > 0 ? (
            <div className="space-y-2">
              {filtered.map((r, i) => (
                <ResultRow key={`${r.package}@${r.version}`} result={r} idx={i} />
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No packages match the current filter.</p>
          )}
        </div>
      )}
    </div>
  );
}
