interface SeverityBadgeProps {
  severity: string;
  size?: "sm" | "md";
}

const configs: Record<string, { label: string; cls: string }> = {
  critical: { label: "CRITICAL", cls: "bg-red-500/20 text-red-400 border-red-500/40" },
  high:     { label: "HIGH",     cls: "bg-orange-500/20 text-orange-400 border-orange-500/40" },
  medium:   { label: "MEDIUM",   cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40" },
  low:      { label: "LOW",      cls: "bg-blue-500/20 text-blue-400 border-blue-500/40" },
  info:     { label: "INFO",     cls: "bg-gray-500/20 text-gray-400 border-gray-500/40" },
};

export default function SeverityBadge({ severity, size = "sm" }: SeverityBadgeProps) {
  const cfg = configs[severity] ?? configs["info"];
  const sizeClass = size === "sm" ? "px-2 py-0.5 text-xs" : "px-3 py-1 text-sm";
  return (
    <span className={`inline-flex items-center rounded border font-bold tracking-wide ${cfg.cls} ${sizeClass}`}>
      {cfg.label}
    </span>
  );
}
