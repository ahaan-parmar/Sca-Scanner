import { Shield, FileText, Terminal } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

const weightData = [
  { name: "CVE Check", value: 45 },
  { name: "Script Analysis", value: 20 },
  { name: "Typosquat Detection", value: 15 },
  { name: "Maintainer Risk", value: 10 },
  { name: "License Risk", value: 10 },
];

// Fix: distinct color per segment (was all gray before)
const COLORS = ["#ef4444", "#f59e0b", "#a78bfa", "#60a5fa", "#34d399"];

const stats = [
  { label: "Packages Indexed", value: "10M+" },
  { label: "Risk Vectors", value: "5" },
  { label: "CVE Database", value: "Live" },
  { label: "License", value: "MIT" },
];

const features = [
  {
    icon: Shield,
    title: "Multi-Vector Scanning",
    description:
      "CVE lookup, malicious script analysis, typosquatting detection, maintainer risk, and license compliance — all in one run.",
  },
  {
    icon: FileText,
    title: "HTML Dashboard Reports",
    description:
      "Generate browser-based reports with charts, CVE tables, and full findings breakdown via --report --open.",
  },
  {
    icon: Terminal,
    title: "CI/CD Ready",
    description:
      "JSON output mode, configurable --fail-on thresholds, and --strict mode to block high-risk installs in pipelines.",
  },
];

const Index = () => (
  <div>
    {/* ── Hero ─────────────────────────────────────────────────────── */}
    <section className="border-b border-border bg-gradient-to-b from-[#0d1224] to-background">
      <div className="container mx-auto px-4 py-24 text-center">
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground">
          <span className="h-2 w-2 rounded-full bg-risk-low animate-pulse" />
          Open-source · Free forever · No account required
        </div>

        <h1 className="hero-gradient mt-4 text-5xl font-extrabold tracking-tight sm:text-6xl">
          Scan Before You Install
        </h1>

        <p className="mx-auto mt-5 max-w-2xl text-lg text-muted-foreground leading-relaxed">
          The open-source SCA scanner that checks npm packages for CVEs,
          typosquatting, malicious scripts, and supply chain risks —{" "}
          <span className="text-foreground font-medium">before they hit your codebase.</span>
        </p>

        <div className="mt-8 flex flex-wrap justify-center gap-4">
          <a
            href="https://github.com/safe-npm/safe-npm"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-6 py-3 text-sm font-semibold text-foreground transition-all hover:border-primary/50 hover:scale-105"
          >
            Try safe-npm on GitHub
          </a>
        </div>

        {/* Stats */}
        <div className="mt-14 grid grid-cols-2 gap-4 sm:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label} className="rounded-xl border border-border bg-card p-4">
              <div className="text-2xl font-bold text-foreground">{s.value}</div>
              <div className="mt-1 text-xs text-muted-foreground">{s.label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* ── Features ─────────────────────────────────────────────────── */}
    <section className="border-b border-border">
      <div className="container mx-auto px-4 py-20">
        <h2 className="text-center text-3xl font-bold text-foreground">Why safe-npm?</h2>
        <p className="mt-2 text-center text-muted-foreground">
          More than just a CVE checker — full supply chain security analysis.
        </p>
        <div className="mt-12 grid gap-6 md:grid-cols-3">
          {features.map((f) => (
            <div
              key={f.title}
              className="rounded-xl border border-border bg-card p-6 transition-all duration-200 hover:-translate-y-1 hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <f.icon className="h-5 w-5 text-primary" />
              </div>
              <h3 className="mt-4 text-lg font-semibold text-foreground">{f.title}</h3>
              <p className="mt-2 text-sm text-muted-foreground leading-relaxed">{f.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* ── Risk Score Explainer ──────────────────────────────────────── */}
    <section className="border-b border-border">
      <div className="container mx-auto px-4 py-20">
        <h2 className="text-center text-3xl font-bold text-foreground">Risk Score Weights</h2>
        <p className="mt-2 text-center text-sm text-muted-foreground">
          How safe-npm calculates the composite 0–10 risk score
        </p>

        <div className="mt-12 flex flex-col items-center gap-10 md:flex-row md:justify-center">
          <div className="h-64 w-64 shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={weightData}
                  cx="50%"
                  cy="50%"
                  innerRadius={64}
                  outerRadius={105}
                  dataKey="value"
                  stroke="none"
                  paddingAngle={2}
                >
                  {weightData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#111827",
                    border: "1px solid #1f2937",
                    borderRadius: "8px",
                    color: "#f9fafb",
                    fontSize: "13px",
                  }}
                  formatter={(value: number) => [`${value}%`, "Weight"]}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="flex flex-col gap-3">
            {weightData.map((item, i) => (
              <div key={item.name} className="flex items-center gap-3">
                <div className="h-3 w-3 rounded-sm shrink-0" style={{ backgroundColor: COLORS[i] }} />
                <span className="w-44 text-sm text-foreground">{item.name}</span>
                <span className="w-10 text-right text-sm font-semibold text-muted-foreground">
                  {item.value}%
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>

  </div>
);

export default Index;
