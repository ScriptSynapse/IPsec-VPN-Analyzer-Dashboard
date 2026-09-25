export function LoadingBlock({ label = "Loading..." }) {
  return <div className="text-sm text-slate-400 py-8 text-center">{label}</div>;
}

export function ErrorBlock({ error, onRetry }) {
  return (
    <div className="dashboard-card p-5 border-red-200">
      <p className="text-sm font-medium text-red-700 mb-2">{error?.message || String(error)}</p>
      {onRetry && (
        <button onClick={onRetry} className="apple-button-secondary px-3 py-1 text-xs">
          Retry
        </button>
      )}
    </div>
  );
}
