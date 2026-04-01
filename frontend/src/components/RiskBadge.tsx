type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

const styles: Record<RiskLevel, string> = {
  LOW: "bg-risk-low-bg text-risk-low-text",
  MEDIUM: "bg-risk-medium-bg text-risk-medium-text",
  HIGH: "bg-risk-high-bg text-risk-high-text",
  CRITICAL: "bg-risk-critical-bg text-risk-critical-text",
};

const RiskBadge = ({ level }: { level: RiskLevel }) => (
  <span className={`inline-block rounded-full px-3 py-1 text-xs font-medium ${styles[level]}`}>
    {level}
  </span>
);

export default RiskBadge;
