import { clsx } from "clsx";

type BadgeVariant = "cyan" | "emerald" | "red" | "orange" | "yellow" | "blue" | "gray";

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

const variantClasses: Record<BadgeVariant, string> = {
  cyan:    "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  emerald: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  red:     "bg-red-500/20 text-red-400 border-red-500/30",
  orange:  "bg-orange-500/20 text-orange-400 border-orange-500/30",
  yellow:  "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  blue:    "bg-blue-500/20 text-blue-400 border-blue-500/30",
  gray:    "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function Badge({ children, variant = "gray", className }: BadgeProps) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium",
        variantClasses[variant],
        className
      )}
    >
      {children}
    </span>
  );
}
