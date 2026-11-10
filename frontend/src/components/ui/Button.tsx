import { clsx } from "clsx";
import { Loader2 } from "lucide-react";
import { ReactNode, ButtonHTMLAttributes } from "react";

type Variant = "primary" | "success" | "danger" | "ghost" | "outline";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: ReactNode;
  children: ReactNode;
}

const variantClasses: Record<Variant, string> = {
  primary:  "bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold glow-cyan",
  success:  "bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold glow-emerald",
  danger:   "bg-red-500 hover:bg-red-400 text-white font-bold glow-red",
  ghost:    "text-gray-400 hover:text-white hover:bg-gray-800",
  outline:  "border border-gray-700 hover:border-gray-600 text-gray-300 hover:text-white",
};

const sizeClasses: Record<Size, string> = {
  sm: "px-3 py-1.5 text-sm",
  md: "px-5 py-2.5 text-sm",
  lg: "px-8 py-4 text-base",
};

export default function Button({
  variant = "primary",
  size = "md",
  loading = false,
  icon,
  children,
  disabled,
  className,
  ...props
}: ButtonProps) {
  return (
    <button
      disabled={disabled || loading}
      className={clsx(
        "inline-flex items-center gap-2 rounded-lg transition-all duration-200",
        "disabled:opacity-50 disabled:cursor-not-allowed",
        variantClasses[variant],
        sizeClasses[size],
        className,
      )}
      {...props}
    >
      {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : icon}
      {children}
    </button>
  );
}
