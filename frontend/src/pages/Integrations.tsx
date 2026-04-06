import { useState } from "react";
import { Copy, Check, Terminal, Github, Shield, Zap } from "lucide-react";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <button
      onClick={copy}
      className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function CodeBlock({ code, language = "yaml" }: { code: string; language?: string }) {
  return (
    <div className="relative rounded-lg border border-border bg-[#0d1117] overflow-hidden">
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <span className="text-xs text-muted-foreground font-mono">{language}</span>
        <CopyButton text={code} />
      </div>
      <pre className="overflow-x-auto p-4 text-xs leading-relaxed text-[#e6edf3] font-mono">
        <code>{code}</code>
      </pre>
    </div>
  );
}

const GH_WORKFLOW = `name: safe-npm Security Scan

on:
  push:
    paths:
      - 'package.json'
      - 'package-lock.json'
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'
  schedule:
    - cron: '0 6 * * 1'   # Every Monday at 6am

jobs:
  scan:
    name: Dependency Security Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run safe-npm policy check
        id: scan
        run: |
          RESULT=$(curl -s -X POST \\
            -H "Content-Type: application/json" \\
            -d "{
              \\"pkgJson\\": $(cat package.json),
              \\"policy\\": { \\"failOn\\": \\"HIGH\\", \\"warnOn\\": \\"MEDIUM\\" }
            }" \\
            $\{{ secrets.SAFE_NPM_URL \}}/api/scan/policy)

          echo "result=$RESULT" >> $GITHUB_OUTPUT

          PASS=$(echo $RESULT | jq -r '.pass')
          VIOLATIONS=$(echo $RESULT | jq -r '.violations | length')
          WARNINGS=$(echo $RESULT | jq -r '.warnings | length')

          echo "### safe-npm Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "| Metric | Value |" >> $GITHUB_STEP_SUMMARY
          echo "|--------|-------|" >> $GITHUB_STEP_SUMMARY
          echo "| Status | $([ \\"$PASS\\" = \\"true\\" ] && echo '✅ Pass' || echo '❌ Fail') |" >> $GITHUB_STEP_SUMMARY
          echo "| Violations | $VIOLATIONS |" >> $GITHUB_STEP_SUMMARY
          echo "| Warnings | $WARNINGS |" >> $GITHUB_STEP_SUMMARY

          if [ "$PASS" != "true" ]; then
            echo "::error::safe-npm found $VIOLATIONS high/critical vulnerability violations"
            exit 1
          fi

          if [ "$WARNINGS" -gt "0" ]; then
            echo "::warning::safe-npm found $WARNINGS medium-severity packages"
          fi`;

const POLICY_EXAMPLE = `{
  "pkgJson": {
    "name": "my-app",
    "dependencies": {
      "express": "^4.18.0",
      "lodash": "^4.17.21"
    }
  },
  "policy": {
    "failOn": "HIGH",
    "warnOn": "MEDIUM"
  }
}`;

const POLICY_RESPONSE = `{
  "pass": false,
  "policy": { "failOn": "HIGH", "warnOn": "MEDIUM" },
  "violations": [
    {
      "package": "lodash",
      "version": "4.17.21",
      "level": "HIGH",
      "score": 75
    }
  ],
  "warnings": [],
  "summary": {
    "total": 2,
    "errors": 0,
    "byLevel": { "LOW": 1, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0 }
  }
}`;

const BADGE_MD = `[![safe-npm](https://your-safe-npm-url/api/badge/PROJECT_ID)](https://your-safe-npm-url/projects/PROJECT_ID)`;

const CURL_SCAN = `curl -X POST http://localhost:3001/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"package": "lodash@4.17.21"}'`;

const CURL_SBOM = `curl http://localhost:3001/api/projects/1/sbom \\
  -o my-project-sbom.cdx.json`;

export default function IntegrationsPage() {
  return (
    <div className="container mx-auto max-w-4xl px-4 py-10">
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-foreground">Integrations</h1>
        <p className="mt-2 text-muted-foreground">
          Block vulnerable dependencies in CI/CD, export SBOMs, and embed risk badges in your README.
        </p>
      </div>

      {/* Cards overview */}
      <div className="grid gap-4 sm:grid-cols-3 mb-10">
        {[
          { icon: Github,  label: "GitHub Actions", desc: "Block PRs with high/critical vulnerabilities automatically." },
          { icon: Shield,  label: "Policy API",      desc: "Configurable fail thresholds for any CI system." },
          { icon: Zap,     label: "SBOM Export",     desc: "CycloneDX 1.5 format — required for enterprise & compliance." },
        ].map(({ icon: Icon, label, desc }) => (
          <div key={label} className="rounded-xl border border-border bg-card p-5">
            <Icon className="mb-3 h-5 w-5 text-primary" />
            <p className="font-semibold text-foreground text-sm">{label}</p>
            <p className="mt-1 text-xs text-muted-foreground">{desc}</p>
          </div>
        ))}
      </div>

      {/* ── GitHub Actions ── */}
      <section className="mb-10">
        <div className="mb-4 flex items-center gap-2">
          <Github className="h-5 w-5 text-foreground" />
          <h2 className="text-xl font-semibold text-foreground">GitHub Actions Workflow</h2>
        </div>
        <p className="mb-4 text-sm text-muted-foreground">
          Add this workflow to <code className="rounded bg-secondary px-1 py-0.5 text-xs">.github/workflows/safe-npm.yml</code>.
          Set <code className="rounded bg-secondary px-1 py-0.5 text-xs">SAFE_NPM_URL</code> as a repository secret pointing to your deployed safe-npm API.
        </p>
        <CodeBlock code={GH_WORKFLOW} language="yaml — .github/workflows/safe-npm.yml" />
      </section>

      {/* ── Policy API ── */}
      <section className="mb-10">
        <div className="mb-4 flex items-center gap-2">
          <Terminal className="h-5 w-5 text-foreground" />
          <h2 className="text-xl font-semibold text-foreground">Policy Enforcement API</h2>
        </div>
        <p className="mb-2 text-sm text-muted-foreground">
          <code className="rounded bg-secondary px-1 py-0.5 text-xs">POST /api/scan/policy</code> — accepts a{" "}
          <code className="rounded bg-secondary px-1 py-0.5 text-xs">package.json</code> and returns a pass/fail result with violation details.
        </p>
        <div className="mb-4">
          <p className="mb-2 text-xs text-muted-foreground font-semibold uppercase tracking-wide">Request</p>
          <CodeBlock code={POLICY_EXAMPLE} language="json — request body" />
        </div>
        <div>
          <p className="mb-2 text-xs text-muted-foreground font-semibold uppercase tracking-wide">Response</p>
          <CodeBlock code={POLICY_RESPONSE} language="json — response" />
        </div>

        <div className="mt-4 rounded-lg border border-border bg-card p-4 text-sm">
          <p className="font-semibold text-foreground mb-2">Policy levels</p>
          <table className="w-full text-xs text-muted-foreground">
            <thead>
              <tr className="text-left border-b border-border">
                <th className="pb-2 font-semibold">failOn</th>
                <th className="pb-2 font-semibold">Behaviour</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["CRITICAL", "Only fail on CVSS 9.0+ vulnerabilities"],
                ["HIGH",     "Fail on HIGH and CRITICAL (recommended)"],
                ["MEDIUM",   "Fail on MEDIUM, HIGH, and CRITICAL"],
                ["LOW",      "Fail on any detected risk (strictest)"],
              ].map(([level, desc]) => (
                <tr key={level} className="border-b border-border/50">
                  <td className="py-2 pr-4 font-mono text-foreground">{level}</td>
                  <td className="py-2">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── SBOM ── */}
      <section className="mb-10">
        <div className="mb-4 flex items-center gap-2">
          <Shield className="h-5 w-5 text-foreground" />
          <h2 className="text-xl font-semibold text-foreground">SBOM Export (CycloneDX)</h2>
        </div>
        <p className="mb-4 text-sm text-muted-foreground">
          Generate a Software Bill of Materials in{" "}
          <a href="https://cyclonedx.org" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">CycloneDX 1.5</a>{" "}
          format. Includes all components, their PURL identifiers, risk levels, and linked CVE vulnerabilities with fix recommendations.
        </p>
        <CodeBlock code={CURL_SBOM} language="bash" />
        <p className="mt-3 text-xs text-muted-foreground">
          The output file is compatible with tools like Dependency-Track, OWASP CycloneDX tools, and enterprise procurement intake portals.
        </p>
      </section>

      {/* ── REST API Quick Reference ── */}
      <section className="mb-10">
        <div className="mb-4 flex items-center gap-2">
          <Terminal className="h-5 w-5 text-foreground" />
          <h2 className="text-xl font-semibold text-foreground">REST API Quick Reference</h2>
        </div>
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-secondary">
              <tr>
                <th className="px-4 py-2.5 text-left font-semibold text-muted-foreground uppercase tracking-wide">Method</th>
                <th className="px-4 py-2.5 text-left font-semibold text-muted-foreground uppercase tracking-wide">Endpoint</th>
                <th className="px-4 py-2.5 text-left font-semibold text-muted-foreground uppercase tracking-wide">Description</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["POST", "/api/scan",                   "Single package scan"],
                ["POST", "/api/scan/batch",             "Batch scan from package.json (SSE stream)"],
                ["POST", "/api/scan/policy",            "Policy gate — returns pass/fail for CI"],
                ["GET",  "/api/projects",               "List all tracked projects"],
                ["POST", "/api/projects",               "Create project (GitHub URL or paste)"],
                ["GET",  "/api/projects/:id",           "Get project + latest scan"],
                ["POST", "/api/projects/:id/scan",      "Trigger rescan (SSE stream)"],
                ["GET",  "/api/projects/:id/history",   "Scan history"],
                ["GET",  "/api/projects/:id/export",    "Download results (JSON or CSV)"],
                ["GET",  "/api/projects/:id/sbom",      "Download CycloneDX SBOM"],
                ["GET",  "/api/badge/:id",              "SVG risk badge for README"],
              ].map(([method, path, desc]) => (
                <tr key={path} className="border-t border-border hover:bg-secondary/30 transition-colors">
                  <td className="px-4 py-2.5">
                    <span className={`rounded px-1.5 py-0.5 font-mono font-semibold ${method === "POST" ? "bg-blue-950/50 text-blue-400" : "bg-green-950/50 text-green-400"}`}>
                      {method}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-foreground">{path}</td>
                  <td className="px-4 py-2.5 text-muted-foreground">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4">
          <CodeBlock code={CURL_SCAN} language="bash — single package scan" />
        </div>
      </section>

      {/* ── Badge ── */}
      <section>
        <div className="mb-4 flex items-center gap-2">
          <Shield className="h-5 w-5 text-foreground" />
          <h2 className="text-xl font-semibold text-foreground">README Badge</h2>
        </div>
        <p className="mb-4 text-sm text-muted-foreground">
          Embed a live risk badge in your README. Get the badge URL from the project detail page, or use the pattern below.
        </p>
        <CodeBlock code={BADGE_MD} language="markdown" />
      </section>
    </div>
  );
}
