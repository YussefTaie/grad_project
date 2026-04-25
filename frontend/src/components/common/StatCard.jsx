import StatusBadge from "./StatusBadge";

function StatCard({ label, value, caption, status, tone }) {
  return (
    <article className="rounded-2xl border border-slate-800 bg-panel p-4 transition-all duration-500 ease-in-out hover:scale-[1.03] hover:shadow-glow">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">{label}</p>
          <p className="mt-4 text-3xl font-semibold tracking-tight text-white">{value}</p>
        </div>
        <StatusBadge label={status} tone={tone} />
      </div>
      <p className="mt-5 text-xs uppercase tracking-[0.2em] text-slate-500">{caption}</p>
    </article>
  );
}

export default StatCard;
