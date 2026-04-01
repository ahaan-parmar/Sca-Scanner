import { useParams, Link } from "react-router-dom";
import { Check, X, ExternalLink, ArrowLeft } from "lucide-react";
import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { tools } from "@/data/tools";
import CodeBlock from "@/components/CodeBlock";

// Color bar by score: red=low coverage, green=high coverage
function coverageColor(score: number) {
  if (score >= 80) return "#10b981";
  if (score >= 50) return "#f59e0b";
  if (score >= 20) return "#ef4444";
  return "#374151";
}

const ToolDetail = () => {
  const { slug } = useParams<{ slug: string }>();
  const tool = tools.find((t) => t.slug === slug);

  if (!tool) {
    return (
      <div className="container mx-auto px-4 py-20 text-center">
        <h1 className="text-2xl font-bold text-foreground">Tool not found</h1>
        <Link to="/tools" className="mt-4 inline-block text-primary">
          ← Back to directory
        </Link>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-10">
      <Link
        to="/tools"
        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to directory
      </Link>

      <div className="mt-6 flex flex-wrap items-start gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold text-foreground">{tool.name}</h1>
            {tool.featured && (
              <span className="rounded-md bg-featured-badge-bg px-2 py-1 text-xs font-medium text-featured-badge-text">
                Featured
              </span>
            )}
          </div>
          <p className="mt-2 max-w-2xl text-muted-foreground leading-relaxed">
            {tool.description}
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {tool.tags.map((tag) => (
              <span
                key={tag}
                className="rounded-md bg-tag-bg px-2 py-1 text-xs text-tag-text"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Links */}
      <div className="mt-6 flex gap-4">
        {tool.website && (
          <a
            href={tool.website}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-primary"
          >
            <ExternalLink className="h-4 w-4" /> Website
          </a>
        )}
        {tool.github && (
          <a
            href={tool.github}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-primary"
          >
            <ExternalLink className="h-4 w-4" /> GitHub
          </a>
        )}
      </div>

      {/* Features */}
      <section className="mt-10">
        <h2 className="text-xl font-semibold text-foreground">Features</h2>
        <ul className="mt-4 grid gap-2 sm:grid-cols-2">
          {tool.features.map((f) => (
            <li key={f} className="flex items-center gap-2 text-sm text-muted-foreground">
              <Check className="h-4 w-4 text-risk-low shrink-0" />
              {f}
            </li>
          ))}
        </ul>
      </section>

      {/* Pros & Cons */}
      <section className="mt-10 grid gap-6 md:grid-cols-2">
        <div>
          <h2 className="text-xl font-semibold text-foreground">Pros</h2>
          <ul className="mt-4 space-y-2">
            {tool.pros.map((p) => (
              <li key={p} className="flex items-center gap-2 text-sm text-muted-foreground">
                <Check className="h-4 w-4 text-risk-low shrink-0" />
                {p}
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h2 className="text-xl font-semibold text-foreground">Cons</h2>
          <ul className="mt-4 space-y-2">
            {tool.cons.map((c) => (
              <li key={c} className="flex items-center gap-2 text-sm text-muted-foreground">
                <X className="h-4 w-4 text-risk-high shrink-0" />
                {c}
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Risk Coverage Chart */}
      <section className="mt-10">
        <h2 className="text-xl font-semibold text-foreground">Risk Coverage</h2>
        <div className="mt-4 h-64 w-full max-w-xl">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={tool.riskCoverage} layout="vertical">
              <XAxis type="number" domain={[0, 100]} tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <YAxis
                dataKey="vector"
                type="category"
                tick={{ fill: "#9ca3af", fontSize: 12 }}
                width={100}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#111827",
                  border: "1px solid #1f2937",
                  borderRadius: "8px",
                  color: "#f9fafb",
                  fontSize: "13px",
                }}
              />
              <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                {tool.riskCoverage.map((entry) => (
                  <Cell key={entry.vector} fill={coverageColor(entry.score)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      {/* CLI Examples */}
      {tool.cliExamples && tool.cliExamples.length > 0 && (
        <section className="mt-10">
          <h2 className="text-xl font-semibold text-foreground">CLI Usage</h2>
          <div className="mt-4 max-w-2xl">
            <CodeBlock lines={tool.cliExamples} />
          </div>
        </section>
      )}
    </div>
  );
};

export default ToolDetail;
