const toneMap = {
  danger: "bg-red-500/15 text-red-300 ring-1 ring-red-500/20",
  warning: "bg-yellow-500/15 text-yellow-300 ring-1 ring-yellow-500/20",
  success: "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/20",
  info: "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/20",
  neutral: "bg-slate-700/60 text-slate-200 ring-1 ring-slate-600",
};

function StatusBadge({ label, tone = "neutral" }) {
  return (
    <span className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${toneMap[tone] || toneMap.neutral}`}>
      {label}
    </span>
  );
}

export default StatusBadge;
