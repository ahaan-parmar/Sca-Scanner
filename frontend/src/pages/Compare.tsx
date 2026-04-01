import { Link } from "react-router-dom";
import { Check, X, Minus } from "lucide-react";
import { tools } from "@/data/tools";

// Features to compare across all tools
const COMPARE_ROWS = [
  { label: "CVE Scanning",           key: (f: string[]) => f.some(x => /CVE|vulnerabilit/i.test(x)) },
  { label: "License Compliance",     key: (f: string[]) => f.some(x => /licens/i.test(x)) },
  { label: "Supply Chain Detection", key: (f: string[]) => f.some(x => /supply chain|malicious/i.test(x)) },
  { label: "Typosquatting Detection",key: (f: string[]) => f.some(x => /typosquat/i.test(x)) },
  { label: "Script Analysis",        key: (f: string[]) => f.some(x => /script/i.test(x)) },
  { label: "Maintainer Risk",        key: (f: string[]) => f.some(x => /maintainer/i.test(x)) },
  { label: "HTML Reports",           key: (f: string[]) => f.some(x => /html|report/i.test(x)) },
  { label: "JSON / CI-CD Output",    key: (f: string[]) => f.some(x => /json|ci|cd|pipeline/i.test(x)) },
  { label: "SBOM Generation",        key: (f: string[]) => f.some(x => /sbom/i.test(x)) },
  { label: "IDE Integration",        key: (f: string[]) => f.some(x => /ide|plugin/i.test(x)) },
  { label: "Open Source",            key: (_: string[], openSource: boolean) => openSource },
  { label: "Free to Use",            key: (_: string[], __: boolean, pricing: string) => pricing === "Free" || pricing === "Open Source" },
];

type RowDef = {
  label: string;
  key: (features: string[], openSource: boolean, pricing: string) => boolean;
};

function CoverageCell({ score }: { score: number }) {
  const pct = score;
  const color =
    pct >= 80 ? "text-risk-low" :
    pct >= 50 ? "text-risk-medium" :
    pct >= 20 ? "text-risk-high" :
    "text-muted-foreground";
  return (
    <span className={`text-sm font-semibold tabular-nums ${color}`}>
      {pct > 0 ? `${pct}%` : "—"}
    </span>
  );
}

const vectors = ["CVEs", "License", "Supply Chain", "Typosquat", "Scripts", "Maintainer"];

const Compare = () => (
  <div className="container mx-auto px-4 py-10">
    <h1 className="text-3xl font-bold text-foreground">SCA Tool Comparison</h1>
    <p className="mt-2 text-muted-foreground">
      Side-by-side feature and risk coverage comparison.
    </p>

    {/* ── Feature Matrix ──────────────────────────────────────────── */}
    <h2 className="mt-12 text-xl font-semibold text-foreground">Feature Matrix</h2>
    <p className="mt-1 text-sm text-muted-foreground">Which tool covers which security capability.</p>

    <div className="mt-6 overflow-x-auto rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-card/80">
            <th className="py-3 pl-4 pr-6 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground w-44">
              Feature
            </th>
            {tools.map((t) => (
              <th key={t.slug} className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-muted-foreground min-w-[110px]">
                <Link to={`/tools/${t.slug}`} className="hover:text-primary transition-colors">
                  {t.name}
                </Link>
                {t.featured && (
                  <span className="ml-1.5 rounded bg-featured-badge-bg px-1 py-0.5 text-[10px] font-medium text-featured-badge-text">
                    ★
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {(COMPARE_ROWS as RowDef[]).map((row, i) => (
            <tr key={row.label} className={`border-b border-border ${i % 2 === 0 ? "" : "bg-card/30"}`}>
              <td className="py-3 pl-4 pr-6 font-medium text-foreground whitespace-nowrap">
                {row.label}
              </td>
              {tools.map((t) => {
                const has = row.key(t.features, t.openSource, t.pricing);
                return (
                  <td key={t.slug} className="px-4 py-3 text-center">
                    {has ? (
                      <Check className="mx-auto h-4 w-4 text-risk-low" />
                    ) : (
                      <X className="mx-auto h-4 w-4 text-muted-foreground/40" />
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>

    {/* ── Risk Coverage Heatmap ───────────────────────────────────── */}
    <h2 className="mt-16 text-xl font-semibold text-foreground">Risk Coverage Heatmap</h2>
    <p className="mt-1 text-sm text-muted-foreground">
      How well each tool covers each risk vector (0–100%).{" "}
      <span className="text-risk-low">Green</span> = strong,{" "}
      <span className="text-risk-medium">amber</span> = partial,{" "}
      <span className="text-risk-high">red</span> = weak.
    </p>

    <div className="mt-6 overflow-x-auto rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-card/80">
            <th className="py-3 pl-4 pr-6 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground w-44">
              Vector
            </th>
            {tools.map((t) => (
              <th key={t.slug} className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-muted-foreground min-w-[110px]">
                {t.name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {vectors.map((vec, i) => (
            <tr key={vec} className={`border-b border-border ${i % 2 === 0 ? "" : "bg-card/30"}`}>
              <td className="py-3 pl-4 pr-6 font-medium text-foreground">{vec}</td>
              {tools.map((t) => {
                const entry = t.riskCoverage.find((r) => r.vector === vec);
                return (
                  <td key={t.slug} className="px-4 py-3 text-center">
                    <CoverageCell score={entry?.score ?? 0} />
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>

    {/* ── Pricing & Type ──────────────────────────────────────────── */}
    <h2 className="mt-16 text-xl font-semibold text-foreground">Pricing & Deployment</h2>
    <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {tools.map((t) => (
        <Link
          key={t.slug}
          to={`/tools/${t.slug}`}
          className={`rounded-xl border p-4 bg-card transition-all hover:-translate-y-0.5 hover:border-primary/40 ${t.featured ? "border-featured-border" : "border-border"}`}
        >
          <div className="flex items-start justify-between">
            <span className="font-semibold text-foreground">{t.name}</span>
            {t.featured && <span className="text-xs text-primary">★ Featured</span>}
          </div>
          <div className="mt-2 flex gap-2 flex-wrap">
            <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${
              t.pricing === "Free" || t.pricing === "Open Source"
                ? "bg-risk-low-bg text-risk-low-text"
                : t.pricing === "Freemium"
                ? "bg-risk-medium-bg text-risk-medium-text"
                : "bg-risk-high-bg text-risk-high-text"
            }`}>
              {t.pricing}
            </span>
            <span className="rounded bg-tag-bg px-1.5 py-0.5 text-xs text-tag-text">
              {t.type}
            </span>
          </div>
        </Link>
      ))}
    </div>
  </div>
);

export default Compare;
