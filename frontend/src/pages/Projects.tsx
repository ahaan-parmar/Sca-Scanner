import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Trash2, ExternalLink, Clock, ShieldCheck, ShieldAlert, X, Github, FileJson } from "lucide-react";

const API = "http://localhost:3001";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

interface Project {
  id: number;
  name: string;
  github_url: string | null;
  created_at: string;
  last_scanned_at: string | null;
  summary: { total: number; byLevel: Record<RiskLevel, number> } | null;
}

const LEVEL_COLORS: Record<RiskLevel, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-green-400",
};

function topRisk(byLevel: Record<RiskLevel, number>): { level: RiskLevel; count: number } | null {
  for (const level of ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as RiskLevel[]) {
    if (byLevel[level] > 0) return { level, count: byLevel[level] };
  }
  return null;
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr + "Z").getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)   return "just now";
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading]   = useState(true);
  const [showForm, setShowForm] = useState(false);

  const [name, setName]             = useState("");
  const [githubUrl, setGithubUrl]   = useState("");
  const [pkgText, setPkgText]       = useState("");
  const [inputMode, setInputMode]   = useState<"github" | "paste">("github");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError]   = useState("");

  async function loadProjects() {
    try {
      const r = await fetch(`${API}/api/projects`);
      setProjects(await r.json());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadProjects(); }, []);

  async function createProject() {
    setFormError("");
    if (!name.trim()) { setFormError("Project name is required."); return; }

    let pkgJson: object | undefined;
    if (inputMode === "paste") {
      if (!pkgText.trim()) { setFormError("Paste a package.json or switch to GitHub URL."); return; }
      try { pkgJson = JSON.parse(pkgText); }
      catch { setFormError("Invalid JSON — check your package.json."); return; }
    } else if (!githubUrl.trim()) {
      setFormError("Enter a GitHub URL or switch to paste mode.");
      return;
    }

    setSubmitting(true);
    try {
      const r = await fetch(`${API}/api/projects`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim(), githubUrl: githubUrl.trim() || undefined, pkgJson }),
      });
      if (!r.ok) {
        const { error } = await r.json();
        setFormError(error || "Failed to create project.");
        return;
      }
      setShowForm(false);
      setName(""); setGithubUrl(""); setPkgText("");
      loadProjects();
    } finally {
      setSubmitting(false);
    }
  }

  async function deleteProject(id: number) {
    if (!confirm("Delete this project and all its scan history?")) return;
    await fetch(`${API}/api/projects/${id}`, { method: "DELETE" });
    setProjects((prev) => prev.filter((p) => p.id !== id));
  }

  return (
    <div className="container mx-auto px-4 py-10">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Projects</h1>
          <p className="mt-1 text-muted-foreground">
            Track your npm projects — auto-rescanned nightly for new vulnerabilities.
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-all hover:bg-primary/90 hover:scale-105"
        >
          <Plus className="h-4 w-4" /> Add Project
        </button>
      </div>

      {/* Add project form */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-border bg-card p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-foreground">Add Project</h2>
              <button onClick={() => { setShowForm(false); setFormError(""); }} className="text-muted-foreground hover:text-foreground">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-muted-foreground uppercase tracking-wide">Project Name</label>
                <input
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
                  placeholder="my-app"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => setInputMode("github")}
                  className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${inputMode === "github" ? "border-primary/50 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"}`}
                >
                  <Github className="h-3.5 w-3.5" /> GitHub URL
                </button>
                <button
                  onClick={() => setInputMode("paste")}
                  className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${inputMode === "paste" ? "border-primary/50 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"}`}
                >
                  <FileJson className="h-3.5 w-3.5" /> Paste package.json
                </button>
              </div>

              {inputMode === "github" ? (
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-muted-foreground uppercase tracking-wide">GitHub URL</label>
                  <input
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
                    placeholder="https://github.com/owner/repo"
                    value={githubUrl}
                    onChange={(e) => setGithubUrl(e.target.value)}
                  />
                  <p className="mt-1 text-xs text-muted-foreground">We'll fetch the package.json automatically.</p>
                </div>
              ) : (
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-muted-foreground uppercase tracking-wide">package.json</label>
                  <textarea
                    rows={6}
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30 resize-none"
                    placeholder={'{\n  "dependencies": { ... }\n}'}
                    value={pkgText}
                    onChange={(e) => setPkgText(e.target.value)}
                  />
                </div>
              )}

              {formError && (
                <p className="text-sm text-red-400">{formError}</p>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  onClick={createProject}
                  disabled={submitting}
                  className="flex-1 rounded-lg bg-primary py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
                >
                  {submitting ? "Adding…" : "Add Project"}
                </button>
                <button
                  onClick={() => { setShowForm(false); setFormError(""); }}
                  className="rounded-lg border border-border px-4 py-2.5 text-sm text-muted-foreground hover:text-foreground"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Project grid */}
      <div className="mt-8">
        {loading ? (
          <div className="mt-16 text-center text-muted-foreground text-sm">Loading…</div>
        ) : projects.length === 0 ? (
          <div className="mt-16 flex flex-col items-center gap-4 text-center">
            <ShieldCheck className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">No projects yet. Add one to start tracking vulnerabilities.</p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {projects.map((p) => {
              const risk = p.summary ? topRisk(p.summary.byLevel) : null;
              return (
                <div key={p.id} className="group relative rounded-xl border border-border bg-card p-5 transition-all hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5">
                  <div className="flex items-start justify-between">
                    <div className="min-w-0">
                      <h3 className="truncate font-semibold text-foreground">{p.name}</h3>
                      {p.github_url && (
                        <a
                          href={p.github_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground hover:text-primary truncate"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <Github className="h-3 w-3 shrink-0" />
                          <span className="truncate">{p.github_url.replace("https://github.com/", "")}</span>
                          <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                        </a>
                      )}
                    </div>
                    <button
                      onClick={() => deleteProject(p.id)}
                      className="ml-2 shrink-0 rounded p-1 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-red-400"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>

                  <div className="mt-4">
                    {p.summary ? (
                      <div className="flex items-center gap-3">
                        {risk ? (
                          <span className={`text-sm font-semibold ${LEVEL_COLORS[risk.level]}`}>
                            {risk.count} {risk.level}
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-sm font-semibold text-green-400">
                            <ShieldCheck className="h-4 w-4" /> Secure
                          </span>
                        )}
                        <span className="text-xs text-muted-foreground">· {p.summary.total} packages</span>
                      </div>
                    ) : (
                      <span className="flex items-center gap-1 text-xs text-muted-foreground">
                        <ShieldAlert className="h-3.5 w-3.5" /> Not yet scanned
                      </span>
                    )}
                  </div>

                  <div className="mt-4 flex items-center justify-between">
                    {p.last_scanned_at ? (
                      <span className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" /> {timeAgo(p.last_scanned_at)}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">Never scanned</span>
                    )}
                    <Link
                      to={`/projects/${p.id}`}
                      className="rounded-md border border-border px-3 py-1 text-xs font-medium text-foreground transition-colors hover:border-primary/50 hover:bg-primary/5"
                    >
                      View →
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
