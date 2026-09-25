export function Card({ title, badge, children, className = "" }) {
  return (
    <div className={`dashboard-card overflow-hidden ${className}`}>
      {title && (
        <div className="border-b border-apple-border px-5 py-3.5 bg-slate-50 flex items-center justify-between">
          <h3 className="font-semibold text-slate-800 text-sm">{title}</h3>
          {badge}
        </div>
      )}
      {children}
    </div>
  );
}
