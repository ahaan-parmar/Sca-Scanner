# safe-npm

> Secure npm install wrapper — scans packages for supply chain risks **before** installation.

```
safe-npm install axios@0.21.1
```

```
╔══════════════════════════════════════════════════════════╗
║  safe-npm  —  Security Scan: axios@0.21.1                ║
╚══════════════════════════════════════════════════════════╝

Package : axios@0.21.1
Risk    : [HIGH] (score: 5.20/10)

  Vulnerabilities:
    [CRITICAL] CVE-2021-3749 — axios Inefficient Regular Expression Complexity
    [HIGH]     CVE-2025-27152 — Possible SSRF and Credential Leakage
    [MEDIUM]   CVE-2023-45857 — Cross-Site Request Forgery Vulnerability

  ✘  Risk Level: HIGH
  Significant risks detected. Installation blocked in --strict mode.
```

---

## Installation

```bash
git clone <repo>
cd safe-npm
npm install
npm link          # makes `safe-npm` available globally
```

Or run directly:

```bash
node cli.js install axios
```

**Requirements:** Node.js ≥ 16

---

## Usage

### Install with pre-scan

```bash
safe-npm install axios
safe-npm install express@4.18.2
safe-npm install --strict lodash          # blocks on HIGH/CRITICAL
safe-npm install axios --save-dev         # extra npm flags pass through
```

### Scan only (no install)

```bash
safe-npm scan axios
safe-npm scan axios@0.21.1
safe-npm scan axois                        # catches typosquatting
safe-npm scan axios --json                 # machine-readable output
safe-npm scan axios --strict               # exit 2 on HIGH/CRITICAL
```

### CI/CD: scan a package.json

```bash
safe-npm scan package.json
safe-npm scan package.json --fail-on HIGH     # exit 2 if any package is HIGH+
safe-npm scan package.json --fail-on MEDIUM   # stricter threshold
safe-npm scan package.json --json             # JSON output for pipelines
```

### Cache management

```bash
safe-npm cache status
safe-npm cache clear
```

### Debug

```bash
safe-npm scan axios --debug     # verbose logging
```

---

## Flags

| Flag | Description |
|---|---|
| `--strict` | Block installation if risk is HIGH or CRITICAL |
| `--json` | Output results as JSON (suppresses prompts) |
| `--fail-on <level>` | CI/CD: exit 2 if any package meets the level |
| `--no-diff` | Skip version-diff script analysis |
| `--debug` | Verbose debug logging |

---

## Architecture

```
safe-npm/
│
├── cli.js                  Entry point — Commander.js routing
│
├── core/
│   ├── fetcher.js          npm registry API + file-based cache (TTL: 1h)
│   ├── scanner.js          Orchestrates all checks, returns unified result
│   ├── risk_engine.js      Weighted score → LOW/MEDIUM/HIGH/CRITICAL
│   └── installer.js        Spawns `npm install` with full I/O passthrough
│
├── checks/
│   ├── cve_check.js        OSV.dev API — CVE lookup with severity parsing
│   ├── typosquat_check.js  Levenshtein distance (self-impl) vs top-package list
│   ├── script_check.js     Static analysis of preinstall/postinstall scripts
│   └── maintainer_check.js Package age, maintainer count, version spikes
│
├── data/
│   └── top_packages.json   ~250 popular npm packages (typosquat baseline)
│
├── utils/
│   └── logger.js           Chalk-colored output, risk badges, scan report renderer
│
└── config.json             Risk weights, API endpoints, thresholds
```

### Risk Scoring Formula

```
score = (cve_score × 0.5) + (script_score × 0.2) + (typosquat_score × 0.2) + (maintainer_score × 0.1)
```

| Range | Level |
|---|---|
| 0.0 – 2.49 | LOW |
| 2.5 – 4.99 | MEDIUM |
| 5.0 – 7.49 | HIGH |
| 7.5 – 10.0 | CRITICAL |

### What each check detects

**CVE Check** (`checks/cve_check.js`)
- Queries `api.osv.dev/v1/query` with `{ package: { name, ecosystem: "npm" }, version }`
- Normalizes severity from CVSS v3 vectors, numeric scores, and GitHub Advisory string labels
- Sorts by severity descending, returns CVE IDs, summaries, OSV links

**Typosquatting** (`checks/typosquat_check.js`)
- Self-implemented Levenshtein distance (Wagner–Fischer DP, O(n) space)
- Strips `node-`, `-js`, `-npm` prefixes/suffixes before comparison
- Applies homoglyph normalization (`0→o`, `1→l`, `3→e`, `4→a`, `5→s`)
- Flags packages within edit distance 2 of any known-popular package

**Script Analysis** (`checks/script_check.js`)
- Checks `preinstall`, `postinstall`, `install` lifecycle hooks
- Detects: `curl`/`wget`/`fetch` network calls, `exec()`/`spawn()` shell execution, base64 obfuscation, env var exfiltration, `eval()`/`new Function()`

**Maintainer Risk** (`checks/maintainer_check.js`)
- Package age < 30 days → flagged
- Single maintainer → flagged
- ≥5 versions published in 30 days → version spike
- > 2 years inactivity then new publish → possible account takeover
- Suspicious name patterns (e.g., `express-official`, `real-lodash`)

---

## Sample Output — Malicious package

```bash
safe-npm scan axois    # typosquat of "axios"
```

```
Risk    : [HIGH] (score: 6.20/10)

  Vulnerabilities:
    [CRITICAL] GHSA-wpfc-3w63-g4hm — Malicious Package in axois

  Possible Typosquatting:
    ⚠ Similar to "axios" (edit distance: 2)
```

## Sample Output — CI/CD

```bash
safe-npm scan package.json --fail-on MEDIUM
```

```
  Batch Scan Results
  [HIGH]   axios@0.21.1      ✘
  [LOW]    lodash@4.17.21
  [MEDIUM] express@4.18.2    ✘

  Summary: 3 scanned
    LOW: 1  MEDIUM: 1  HIGH: 1  CRITICAL: 0

Exit code: 2  ← pipeline fails
```

---

## Caching

Metadata is cached in `~/.safe-npm-cache/` with a 1-hour TTL.
Each entry is a JSON file keyed by `npm_meta_<name>`, `osv_<name>_<version>`, etc.
Run `safe-npm cache clear` to force fresh data.

---

## Comparison

| Feature | safe-npm | Snyk | npm audit |
|---|---|---|---|
| Pre-install scan | ✅ | ✅ | ❌ |
| Typosquatting | ✅ | ✅ | ❌ |
| Script analysis | ✅ | ✅ | ❌ |
| Maintainer risk | ✅ | partial | ❌ |
| OSV.dev (free API) | ✅ | ❌ | ❌ |
| No account needed | ✅ | ❌ | ✅ |
| JSON output | ✅ | ✅ | ✅ |
| CI/CD mode | ✅ | ✅ | ✅ |
| Offline / cache | ✅ | ❌ | ❌ |

---

## License

MIT
