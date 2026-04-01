import { Copy, Check } from "lucide-react";
import { useState } from "react";

const CodeBlock = ({ lines }: { lines: string[] }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(lines.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative rounded-lg bg-code-bg border border-border">
      <button
        onClick={handleCopy}
        className="absolute right-3 top-3 text-muted-foreground"
      >
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </button>
      <pre className="overflow-x-auto p-4 text-sm font-mono text-foreground">
        {lines.map((line, i) => (
          <div key={i} className="flex">
            <span className="mr-4 inline-block w-6 text-right text-muted-foreground select-none">
              {i + 1}
            </span>
            <span>{line}</span>
          </div>
        ))}
      </pre>
    </div>
  );
};

export default CodeBlock;
