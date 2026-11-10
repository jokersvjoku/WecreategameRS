import { clsx } from "clsx";
import { ReactNode } from "react";

interface CardProps {
  children: ReactNode;
  className?: string;
  glow?: "cyan" | "emerald" | "red" | "none";
  padding?: "sm" | "md" | "lg";
}

const glowClasses = {
  cyan:    "glow-cyan border-cyan-500/30",
  emerald: "glow-emerald border-emerald-500/30",
  red:     "glow-red border-red-500/30",
  none:    "border-gray-800",
};

const paddingClasses = {
  sm: "p-4",
  md: "p-6",
  lg: "p-8",
};

export default function Card({ children, className, glow = "none", padding = "md" }: CardProps) {
  return (
    <div
      className={clsx(
        "rounded-xl bg-gray-900 border transition-all duration-200",
        glowClasses[glow],
        paddingClasses[padding],
        className,
      )}
    >
      {children}
    </div>
  );
}
