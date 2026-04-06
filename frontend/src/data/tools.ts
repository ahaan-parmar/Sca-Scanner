export interface Tool {
  slug: string;
  name: string;
  description: string;
  tags: string[];
  featured?: boolean;
  stars?: number;
  lastUpdated?: string;
  pricing: "Free" | "Freemium" | "Paid" | "Open Source";
  type: "CLI" | "SaaS" | "Both";
  openSource: boolean;
  features: string[];
  pros: string[];
  cons: string[];
  riskCoverage: { vector: string; score: number }[];
  cliExamples?: string[];
  website?: string;
  github?: string;
}

export const tools: Tool[] = [
  {
    slug: "safe-npm",
    name: "safe-npm",
    description: "Open-source CLI SCA scanner for npm with pre-install scanning, CVE lookup via OSV.dev, typosquatting detection, HTML reports, and CI/CD integration.",
    tags: ["Open Source", "CLI", "npm", "Free"],
    featured: true,
    stars: 1200,
    lastUpdated: "2024-12-01",
    pricing: "Free",
    type: "CLI",
    openSource: true,
    features: [
      "Pre-install vulnerability scanning",
      "CVE lookup via OSV.dev API",
      "Typosquatting detection",
      "Malicious script analysis",
      "Maintainer risk assessment",
      "License compliance checking",
      "HTML dashboard reports",
      "JSON output for CI/CD",
      "Configurable failure thresholds",
      "--strict mode for blocking installs",
    ],
    pros: [
      "Free and open source",
      "Multi-vector risk analysis",
      "Beautiful HTML reports",
      "Easy CI/CD integration",
      "No account required",
    ],
    cons: [
      "npm ecosystem only",
      "No IDE integration yet",
      "Community-driven support",
    ],
    riskCoverage: [
      { vector: "CVEs", score: 95 },
      { vector: "License", score: 85 },
      { vector: "Supply Chain", score: 90 },
      { vector: "Typosquat", score: 88 },
      { vector: "Scripts", score: 92 },
      { vector: "Maintainer", score: 75 },
    ],
    cliExamples: [
      "safe-npm scan axios@0.21.1",
      "safe-npm scan package.json --fail-on MEDIUM",
      "safe-npm install lodash --strict",
      "safe-npm scan express --report --open",
    ],
    github: "https://github.com/safe-npm/safe-npm",
    website: "https://safe-npm.dev",
  },
];
