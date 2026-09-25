export function RingScore({ score, label = "Overall" }) {
  const deg = Math.max(0, Math.min(100, score)) * 3.6;
  return (
    <div
      className="relative flex items-center justify-center w-28 h-28 rounded-full shrink-0"
      style={{ background: `conic-gradient(#1d1d1f ${deg}deg, #e5e5ea 0deg)` }}
    >
      <div className="absolute inset-1.5 bg-white rounded-full flex items-center justify-center">
        <div className="text-center">
          <div className="text-4xl font-bold tracking-tight text-slate-900 leading-none">{Math.round(score)}</div>
          <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider mt-1">{label}</div>
        </div>
      </div>
    </div>
  );
}
