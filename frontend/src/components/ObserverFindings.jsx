function CategoryLabel({ category }) {
  return <span>{category.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</span>;
}

export function ObserverFindingsList({ findings }) {
  if (!findings || findings.length === 0) {
    return <div className="p-5 text-sm text-slate-400">No observer findings.</div>;
  }

  return (
    <ul className="divide-y divide-slate-100">
      {findings.map((f, i) => {
        if (f.category === "insufficient_history") {
          return (
            <li key={i} className="p-4 text-sm text-slate-500">
              Multi-session correlation needs {f.sessions_needed} sessions sharing a tunnel_id; this tunnel
              currently has {f.sessions_have}.
            </li>
          );
        }
        return (
          <li key={i} className="p-4">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] uppercase font-bold text-slate-500 tracking-wider">
                <CategoryLabel category={f.category} />
              </span>
              <span className="text-[11px] font-bold rounded px-1.5 py-0.5 bg-slate-100 text-slate-600">
                {(f.confidence * 100).toFixed(0)}% confidence
              </span>
            </div>
            <p className="text-sm text-slate-800">{f.description}</p>
            {f.mitigation && <p className="text-xs text-slate-500 mt-1">Mitigation: {f.mitigation}</p>}
          </li>
        );
      })}
    </ul>
  );
}
