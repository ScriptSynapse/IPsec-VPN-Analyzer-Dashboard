export function MetricBar({ label, score, warning = false }) {
  const pct = Math.max(0, Math.min(100, score));
  return (
    <div className="mb-4 last:mb-0">
      <div className="flex justify-between items-baseline mb-1">
        <span className="text-sm font-medium text-slate-700">{label}</span>
        <span className={`text-sm font-semibold ${warning ? "text-amber-600" : "text-slate-900"}`}>
          {score.toFixed(1)}%
        </span>
      </div>
      <div className="w-full bg-slate-100 rounded-sm h-1.5 overflow-hidden">
        <div
          className={`${warning ? "bg-amber-400" : "bg-slate-800"} h-1.5 transition-all`}
          style={{ width: `${pct}%` }}
        ></div>
      </div>
    </div>
  );
}
