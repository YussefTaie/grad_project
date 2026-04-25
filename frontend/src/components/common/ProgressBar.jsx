function ProgressBar({ label, value, toneClass }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="font-medium text-slate-200">{label}</span>
        <span className="text-slate-400">{value}%</span>
      </div>
      <div className="h-3 rounded-full bg-slate-900">
        <div className={`h-3 rounded-full transition-all duration-700 ${toneClass}`} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

export default ProgressBar;
