const Footer = () => (
  <footer className="border-t border-border bg-background">
    <div className="container mx-auto px-4 py-8">
      <div className="flex flex-col items-center gap-4 text-center">
        <p className="text-sm text-muted-foreground">
          Built with{" "}
          <a
            href="https://github.com/safe-npm/safe-npm"
            target="_blank"
            rel="noopener noreferrer"
            className="text-foreground underline"
          >
            safe-npm
          </a>{" "}
          — open source SCA scanning for the npm ecosystem
        </p>
        <div className="flex gap-6">
          <a
            href="https://github.com/safe-npm/safe-npm"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground"
          >
            GitHub
          </a>
          <a
            href="https://github.com/safe-npm/safe-npm/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground"
          >
            Report an Issue
          </a>
          <a
            href="https://github.com/safe-npm/safe-npm#readme"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground"
          >
            Documentation
          </a>
        </div>
        <p className="text-xs text-muted-foreground">
          Data sourced from OSV.dev, npm Registry, GitHub API
        </p>
      </div>
    </div>
  </footer>
);

export default Footer;
