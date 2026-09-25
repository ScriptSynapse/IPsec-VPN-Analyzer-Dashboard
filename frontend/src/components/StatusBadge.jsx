const VARIANTS = {
  success: "bg-emerald-50 text-emerald-700 border-emerald-200",
  danger: "bg-red-50 text-red-700 border-red-200",
  warning: "bg-amber-50 text-amber-700 border-amber-200",
  neutral: "bg-slate-100 text-slate-600 border-slate-200",
};

export function StatusBadge({ children, variant = "neutral" }) {
  return (
    <span
      className={`inline-flex px-1.5 py-0.5 rounded text-[11px] font-semibold border ${VARIANTS[variant]}`}
    >
      {children}
    </span>
  );
}
