import { useCallback, useRef, useState } from "react";
import { Upload, FileJson, X, ShieldCheck, AlertTriangle, Loader2, ChevronDown, ChevronUp, Download, Search } from "lucide-react";

const API_BASE = "http://localhost:3001";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

interface CveFinding {
  id: string;
  osvId: string;
  severity: string;
  score: number;
  cvssScore: number;
  summary: string;
  aliases: string[];
  url: string;
  published: string;
  fixedIn: string | null;
}

interface ScanResult {
  package: string;
  version: string;
  risk: { level: RiskLevel; score: number };
  findings: {
    cve?: CveFinding[];
    scripts?: { type: string; detail: string; severity: string }[];
    typosquat?: { match: string; distance: number }[];
    maintainer?: string[];
    license?: { type: string; detail: string; severity: string }[];
  };
  popularity?: { data?: { weeklyDownloads?: number } };
}

interface ScanError {
  package: string;
  error: string;
}

interface Summary {
  total: number;
  errors: number;
  byLevel: Record<RiskLevel, number>;
}

const RISK_COLORS: Record<RiskLevel, string> = {
  LOW:      "text-risk-low border-[hsl(var(--risk-low))] bg-[hsl(var(--risk-low-bg))]",
  MEDIUM:   "text-risk-medium border-[hsl(var(--risk-medium))] bg-[hsl(var(--risk-medium-bg))]",
  HIGH:     "text-risk-high border-[hsl(var(--risk-high))] bg-[hsl(var(--risk-high-bg))]",
  CRITICAL: "text-risk-critical border-[hsl(var(--risk-critical))] bg-[hsl(var(--risk-critical-bg))]",
};

const RISK_DOT: Record<RiskLevel, string> = {
  LOW:      "bg-[hsl(var(--risk-low))]",
  MEDIUM:   "bg-[hsl(var(--risk-medium))]",
  HIGH:     "bg-[hsl(var(--risk-high))]",
  CRITICAL: "bg-[hsl(var(--risk-critical))]",
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
      <button
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
        onClick={() => setOpen(!open)}
      >
        <span className="w-6 text-xs text-muted-foreground tabular-nums">{idx + 1}</span>
        <span className="flex-1 font-mono text-sm font-medium text-foreground truncate">
          {result.package}
          <span className="ml-1.5 text-xs text-muted-foreground">v{result.version}</span>
        </span>
        <div className="flex items-center gap-3">
          {cveCount > 0 && (
            <span className="text-xs text-risk-high">{cveCount} CVE{cveCount > 1 ? "s" : ""}</span>
          )}
          {fixable > 0 && (
            <span className="text-xs text-green-400">↑ {fixable} fixable</span>
          )}
          {scriptCount > 0 && (
            <span className="text-xs text-risk-medium">{scriptCount} script flag{scriptCount > 1 ? "s" : ""}</span>
          )}
          <RiskBadge level={result.risk.level} />
          <span className="text-xs text-muted-foreground tabular-nums w-8 text-right">
            {result.risk.score}
          </span>
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
            {result.findings?.license && result.findings.license.length > 0 && (
              <div>
                <span className="uppercase tracking-wide font-semibold">License</span>
                <p className="mt-0.5 text-foreground">{result.findings.license[0]?.detail || "—"}</p>
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
                <p className="mt-0.5 text-risk-high">Similar to: {result.findings!.typosquat![0].match}</p>
              </div>
            )}
          </div>

          {cveCount > 0 && (
            <div>
              <span className="uppercase tracking-wide font-semibold">CVEs</span>
              <div className="mt-1 space-y-1.5">
                {cves.slice(0, 8).map((cve) => (
                  <div key={cve.id} className="flex items-start gap-2 rounded bg-[hsl(var(--risk-high-bg))] px-2 py-1.5">
                    <a
                      href={cve.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-risk-high hover:underline shrink-0"
                    >
                      {cve.id}
                    </a>
                    <span className="text-muted-foreground flex-1">{cve.summary}</span>
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
                  <span key={i} className="rounded bg-[hsl(var(--risk-medium-bg))] px-1.5 py-0.5 text-risk-medium font-mono">{s.type}</span>
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

type Phase = "idle" | "preview" | "scanning" | "done";
type FilterLevel = "ALL" | RiskLevel;

function exportJSON(results: ScanResult[], summary: Summary | null, pkgName: string) {
  const data = { project: pkgName, scannedAt: new Date().toISOString(), summary, results };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `scan-${pkgName}.json`;
  a.click();
}

function exportCSV(results: ScanResult[], pkgName: string) {
  const header = "package,version,risk_level,risk_score,cve_count,fixable_cves,license,typosquat";
  const rows = results.map((r) => {
    const cves = r.findings?.cve ?? [];
    const fixable = cves.filter((c) => c.fixedIn).length;
    const license = r.findings?.license?.[0]?.detail ?? "";
    const typosquat = (r.findings?.typosquat ?? []).length > 0 ? "yes" : "no";
    return [r.package, r.version, r.risk.level, r.risk.score, cves.length, fixable, license, typosquat].join(",");
  });
  const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `scan-${pkgName}.csv`;
  a.click();
}

export default function ScanPage() {
  const [phase, setPhase]               = useState<Phase>("idle");
  const [dragging, setDragging]         = useState(false);
  const [pkgJson, setPkgJson]           = useState<Record<string, unknown> | null>(null);
  const [pkgName, setPkgName]           = useState("");
  const [depCount, setDepCount]         = useState(0);
  const [results, setResults]           = useState<ScanResult[]>([]);
  const [errors, setErrors]             = useState<ScanError[]>([]);
  const [summary, setSummary]           = useState<Summary | null>(null);
  const [current, setCurrent]           = useState<{ name: string; index: number; total: number } | null>(null);
  const [parseError, setParseError]     = useState("");
  const [apiError, setApiError]         = useState("");
  const [filterLevel, setFilterLevel]   = useState<FilterLevel>("ALL");
  const [search, setSearch]             = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadFile = (file: File) => {
    setParseError("");
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target?.result as string);
        const deps = { ...parsed.dependencies, ...parsed.devDependencies };
        setPkgJson(parsed);
        setPkgName(parsed.name || "project");
        setDepCount(Object.keys(deps).length);
        setPhase("preview");
      } catch {
        setParseError("Could not parse file — make sure it's a valid package.json.");
      }
    };
    reader.readAsText(file);
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file);
  }, []);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) loadFile(file);
  };

  const startScan = async () => {
    if (!pkgJson) return;
    setPhase("scanning");
    setResults([]);
    setErrors([]);
    setSummary(null);
    setApiError("");

    try {
      const resp = await fetch(`${API_BASE}/api/scan/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pkgJson }),
      });

      if (!resp.ok || !resp.body) {
        setApiError(`API returned ${resp.status}. Is the server running on port 3001?`);
        setPhase("preview");
        return;
      }

      const reader = resp.body.getReader();
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
              setCurrent({ name: event.package, index: event.index, total: event.total });
            } else if (event.type === "result") {
              setResults((prev) => [...prev, event.result]);
            } else if (event.type === "error") {
              setErrors((prev) => [...prev, { package: event.package, error: event.error }]);
            } else if (event.type === "done") {
              setSummary(event.summary);
              setCurrent(null);
              setPhase("done");
            }
          } catch { /* skip malformed event */ }
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setApiError(`Could not connect to API server. Is it running? (${msg})`);
      setPhase("preview");
    }
  };

  const reset = () => {
    setPhase("idle");
    setPkgJson(null);
    setPkgName("");
    setDepCount(0);
    setResults([]);
    setErrors([]);
    setSummary(null);
    setCurrent(null);
    setApiError("");
    setParseError("");
    setSearch("");
    setFilterLevel("ALL");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const sortedResults = [...results].sort((a, b) => b.risk.score - a.risk.score);
  const filteredResults = sortedResults.filter((r) => {
    const matchesLevel = filterLevel === "ALL" || r.risk.level === filterLevel;
    const matchesSearch = search === "" || r.package.toLowerCase().includes(search.toLowerCase());
    return matchesLevel && matchesSearch;
  });
  const progress = current ? Math.round(((current.index - 1) / current.total) * 100) : (phase === "done" ? 100 : 0);
  const LEVELS: FilterLevel[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <div className="container mx-auto max-w-4xl px-4 py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">Live Package Scanner</h1>
        <p className="mt-2 text-muted-foreground">
          Drop a <code className="rounded bg-secondary px-1 py-0.5 text-xs">package.json</code> to scan all dependencies for CVEs, malicious scripts, typosquatting, and more.
        </p>
      </div>

      {/* ── Drop Zone ─────────────────────────────────────────────── */}
      {(phase === "idle" || phase === "preview") && (
        <div
          className={`relative rounded-2xl border-2 border-dashed transition-all cursor-pointer ${
            dragging
              ? "border-primary bg-primary/5 scale-[1.01]"
              : "border-border hover:border-primary/50 hover:bg-secondary/30"
          }`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={onFileChange}
          />
          <div className="flex flex-col items-center justify-center py-14 text-center">
            {phase === "idle" ? (
              <>
                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-secondary">
                  <Upload className="h-6 w-6 text-primary" />
                </div>
                <p className="text-base font-medium text-foreground">Drop your package.json here</p>
                <p className="mt-1 text-sm text-muted-foreground">or click to browse</p>
              </>
            ) : (
              <>
                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-secondary">
                  <FileJson className="h-6 w-6 text-primary" />
                </div>
                <p className="text-base font-medium text-foreground">{pkgName}</p>
                <p className="mt-1 text-sm text-muted-foreground">{depCount} dependenc{depCount === 1 ? "y" : "ies"} found</p>
                <p className="mt-0.5 text-xs text-muted-foreground/60">Click to change file</p>
              </>
            )}
          </div>
        </div>
      )}

      {parseError && (
        <p className="mt-3 text-sm text-risk-high">{parseError}</p>
      )}

      {/* ── Preview actions ───────────────────────────────────────── */}
      {phase === "preview" && (
        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={(e) => { e.stopPropagation(); startScan(); }}
            className="flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
          >
            <ShieldCheck className="h-4 w-4" />
            Scan {depCount} package{depCount !== 1 ? "s" : ""}
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); reset(); }}
            className="flex items-center gap-1.5 rounded-lg border border-border px-4 py-2.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            <X className="h-4 w-4" />
            Clear
          </button>
        </div>
      )}

      {apiError && (
        <div className="mt-4 rounded-lg border border-[hsl(var(--risk-high))] bg-[hsl(var(--risk-high-bg))] px-4 py-3 text-sm text-risk-high flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
          {apiError}
        </div>
      )}

      {/* ── Scanning progress ────────────────────────────────────── */}
      {(phase === "scanning" || phase === "done") && (
        <div className="mt-8 space-y-6">
          {/* Progress bar */}
          <div>
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-muted-foreground">
                {phase === "scanning" ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Scanning {current?.name ?? "…"}
                    <span className="text-xs text-muted-foreground/60">({current?.index}/{current?.total})</span>
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-risk-low">
                    <ShieldCheck className="h-4 w-4" />
                    Scan complete
                  </span>
                )}
              </span>
              <span className="tabular-nums text-muted-foreground">{progress}%</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-primary transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>

          {/* Summary cards */}
          {summary && (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as RiskLevel[]).map((lvl) => (
                <div key={lvl} className={`rounded-lg border px-4 py-3 ${RISK_COLORS[lvl]}`}>
                  <p className="text-2xl font-bold tabular-nums">{summary.byLevel[lvl] ?? 0}</p>
                  <p className="text-xs font-semibold uppercase tracking-wide mt-0.5">{lvl}</p>
                </div>
              ))}
              <div className="rounded-lg border border-border bg-card px-4 py-3">
                <p className="text-2xl font-bold tabular-nums text-foreground">{summary.total}</p>
                <p className="text-xs font-semibold uppercase tracking-wide mt-0.5 text-muted-foreground">Total</p>
              </div>
            </div>
          )}

          {/* Filter bar + Export */}
          {sortedResults.length > 0 && phase === "done" && (
            <div className="flex flex-wrap items-center gap-2">
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
                    {lvl === "ALL" ? `All (${sortedResults.length})` : `${lvl} (${summary?.byLevel[lvl] ?? 0})`}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-1 ml-auto">
                <button
                  onClick={() => exportJSON(sortedResults, summary, pkgName)}
                  className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  <Download className="h-3.5 w-3.5" /> JSON
                </button>
                <button
                  onClick={() => exportCSV(sortedResults, pkgName)}
                  className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  <Download className="h-3.5 w-3.5" /> CSV
                </button>
              </div>
            </div>
          )}

          {/* Results list */}
          {filteredResults.length > 0 && (
            <div>
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-base font-semibold text-foreground">
                  Results
                  {filteredResults.length !== sortedResults.length && (
                    <span className="ml-2 text-sm font-normal text-muted-foreground">
                      {filteredResults.length} of {sortedResults.length}
                    </span>
                  )}
                </h2>
                <span className="text-xs text-muted-foreground">sorted by risk score</span>
              </div>
              <div className="space-y-2">
                {filteredResults.map((r, i) => (
                  <ResultRow key={`${r.package}@${r.version}`} result={r} idx={i} />
                ))}
              </div>
            </div>
          )}

          {filteredResults.length === 0 && sortedResults.length > 0 && (
            <p className="text-sm text-muted-foreground">No packages match the current filter.</p>
          )}

          {/* Errors */}
          {errors.length > 0 && (
            <div>
              <h2 className="mb-3 text-base font-semibold text-foreground">
                Failed ({errors.length})
              </h2>
              <div className="space-y-1.5">
                {errors.map((e) => (
                  <div key={e.package} className="rounded-lg border border-border bg-card px-4 py-2.5 text-sm">
                    <span className="font-mono text-foreground">{e.package}</span>
                    <span className="ml-3 text-muted-foreground">{e.error}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan again */}
          {phase === "done" && (
            <button
              onClick={reset}
              className="mt-2 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              Scan another file
            </button>
          )}
        </div>
      )}
    </div>
  );
}
