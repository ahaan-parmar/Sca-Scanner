import { Terminal, Download, Search, Calculator, FileText } from "lucide-react";

const steps = [
  {
    icon: Terminal,
    title: "Input",
    description: "Run safe-npm scan <package> or point it at your package.json.",
  },
  {
    icon: Download,
    title: "Fetch",
    description:
      "Pulls data from the npm registry, OSV.dev vulnerability database, GitHub API, and npm downloads API.",
  },
  {
    icon: Search,
    title: "Analyze",
    description:
      "Runs 5 parallel checks: CVE lookup, install script analysis, typosquatting detection, maintainer risk assessment, and license compliance.",
  },
  {
    icon: Calculator,
    title: "Score",
    description:
      "A weighted risk engine produces a 0–10 composite score. Levels: LOW / MEDIUM / HIGH / CRITICAL.",
  },
  {
    icon: FileText,
    title: "Report",
    description:
      "Outputs findings to the terminal. Use --report --open to generate an interactive HTML dashboard.",
  },
];

const HowItWorks = () => (
  <div className="container mx-auto px-4 py-10">
    <h1 className="text-3xl font-bold text-foreground">How It Works</h1>
    <p className="mt-2 text-muted-foreground">
      From scan command to actionable security report in seconds.
    </p>

    <div className="relative mt-12 ml-6 border-l border-border">
      {steps.map((step, i) => (
        <div key={step.title} className="relative mb-12 pl-10 last:mb-0">
          <div className="absolute -left-5 flex h-10 w-10 items-center justify-center rounded-full border border-border bg-card">
            <step.icon className="h-5 w-5 text-primary" />
          </div>
          <div>
            <span className="text-xs font-medium text-muted-foreground">
              Step {i + 1}
            </span>
            <h3 className="text-lg font-semibold text-foreground">
              {step.title}
            </h3>
            <p className="mt-1 text-sm text-muted-foreground leading-relaxed max-w-lg">
              {step.description}
            </p>
          </div>
        </div>
      ))}
    </div>
  </div>
);

export default HowItWorks;
