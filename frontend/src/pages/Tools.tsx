import { useState, useMemo } from "react";
import { Search } from "lucide-react";
import { tools } from "@/data/tools";
import ToolCard from "@/components/ToolCard";

type SortKey = "name" | "stars" | "lastUpdated";

const ToolsPage = () => {
  const [query, setQuery] = useState<string>("");
  const [pricing, setPricing] = useState<string>("All");
  const [type, setType] = useState<string>("All");
  const [openSource, setOpenSource] = useState<boolean | null>(null);
  const [sort, setSort] = useState<SortKey>("name");

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    let result = tools.filter((t) => {
      if (q && !t.name.toLowerCase().includes(q) && !t.description.toLowerCase().includes(q) && !t.tags.some(tag => tag.toLowerCase().includes(q))) return false;
      if (pricing !== "All" && t.pricing !== pricing) return false;
      if (type !== "All" && t.type !== type) return false;
      if (openSource === true && !t.openSource) return false;
      return true;
    });

    result.sort((a, b) => {
      if (sort === "name") return a.name.localeCompare(b.name);
      if (sort === "stars") return (b.stars ?? 0) - (a.stars ?? 0);
      if (sort === "lastUpdated")
        return (b.lastUpdated ?? "").localeCompare(a.lastUpdated ?? "");
      return 0;
    });

    return result;
  }, [pricing, type, openSource, sort]);

  const selectClass =
    "rounded-md border border-border bg-card px-3 py-2 text-sm text-foreground";

  return (
    <div className="container mx-auto px-4 py-10">
      <h1 className="text-3xl font-bold text-foreground">SCA Tools Directory</h1>
      <p className="mt-2 text-muted-foreground">
        Compare software composition analysis tools for npm and JavaScript ecosystems.
      </p>

      {/* Search */}
      <div className="relative mt-8 max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          type="text"
          placeholder="Search tools…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full rounded-lg border border-border bg-card py-2 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
        />
      </div>

      <div className="mt-4 flex flex-wrap gap-3">
        <select
          className={selectClass}
          value={pricing}
          onChange={(e) => setPricing(e.target.value)}
        >
          <option value="All">All Pricing</option>
          <option value="Free">Free</option>
          <option value="Freemium">Freemium</option>
          <option value="Paid">Paid</option>
        </select>

        <select
          className={selectClass}
          value={type}
          onChange={(e) => setType(e.target.value)}
        >
          <option value="All">All Types</option>
          <option value="CLI">CLI</option>
          <option value="SaaS">SaaS</option>
          <option value="Both">CLI + SaaS</option>
        </select>

        <label className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm text-foreground">
          <input
            type="checkbox"
            checked={openSource === true}
            onChange={(e) =>
              setOpenSource(e.target.checked ? true : null)
            }
            className="accent-primary"
          />
          Open Source
        </label>

        <select
          className={selectClass}
          value={sort}
          onChange={(e) => setSort(e.target.value as SortKey)}
        >
          <option value="name">Sort: Name</option>
          <option value="stars">Sort: Stars</option>
          <option value="lastUpdated">Sort: Last Updated</option>
        </select>
      </div>

      <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {filtered.map((tool) => (
          <ToolCard key={tool.slug} tool={tool} />
        ))}
      </div>

      {filtered.length === 0 && (
        <p className="mt-12 text-center text-muted-foreground">
          No tools match the selected filters.
        </p>
      )}
    </div>
  );
};

export default ToolsPage;
