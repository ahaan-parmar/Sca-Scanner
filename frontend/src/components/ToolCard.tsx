import { Link } from "react-router-dom";
import { Star } from "lucide-react";
import type { Tool } from "@/data/tools";

const pricingStyle: Record<string, string> = {
  Free:          "bg-risk-low-bg text-risk-low-text",
  "Open Source": "bg-risk-low-bg text-risk-low-text",
  Freemium:      "bg-risk-medium-bg text-risk-medium-text",
  Paid:          "bg-risk-high-bg text-risk-high-text",
};

const ToolCard = ({ tool }: { tool: Tool }) => (
  <div
    className={`group flex flex-col rounded-xl border p-6 bg-card transition-all duration-200 hover:-translate-y-1 hover:shadow-xl ${
      tool.featured
        ? "border-featured-border shadow-md shadow-primary/10"
        : "border-border hover:border-border-hover hover:shadow-primary/5"
    }`}
  >
    {/* Header */}
    <div className="flex items-start justify-between gap-2">
      <h3 className="text-lg font-semibold text-foreground leading-tight">{tool.name}</h3>
      <div className="flex shrink-0 flex-col items-end gap-1">
        {tool.featured && (
          <span className="rounded-md bg-featured-badge-bg px-2 py-0.5 text-xs font-medium text-featured-badge-text">
            Featured
          </span>
        )}
        <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${pricingStyle[tool.pricing] ?? "bg-tag-bg text-tag-text"}`}>
          {tool.pricing}
        </span>
      </div>
    </div>

    {/* Description */}
    <p className="mt-3 flex-1 text-sm text-muted-foreground leading-relaxed">
      {tool.description}
    </p>

    {/* Tags */}
    <div className="mt-4 flex flex-wrap gap-1.5">
      {tool.tags.map((tag) => (
        <span key={tag} className="rounded-md bg-tag-bg px-2 py-0.5 text-xs text-tag-text">
          {tag}
        </span>
      ))}
    </div>

    {/* Footer */}
    <div className="mt-5 flex items-center justify-between border-t border-border pt-4">
      {tool.stars !== undefined ? (
        <div className="flex items-center gap-1 text-sm text-muted-foreground">
          <Star className="h-3.5 w-3.5 fill-yellow-400 text-yellow-400" />
          <span>{tool.stars.toLocaleString()}</span>
        </div>
      ) : (
        <span className="text-xs text-muted-foreground">{tool.type}</span>
      )}
      <Link
        to={`/tools/${tool.slug}`}
        className="text-sm font-medium text-primary transition-colors group-hover:underline"
      >
        View Details →
      </Link>
    </div>
  </div>
);

export default ToolCard;
