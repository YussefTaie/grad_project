import StatusBadge from "../common/StatusBadge";

function HeaderBar({ title, subtitle, loading, lastUpdatedLabel, newAlertsCount }) {
  return (
    <header className="mb-6 flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-950/60 p-5 backdrop-blur md:flex-row md:items-center md:justify-between">
      <div>
        <p className="text-sm uppercase tracking-[0.24em] text-slate-500">Security Operations Center</p>
        <h2 className="mt-2 text-3xl font-semibold tracking-tight text-white">{title}</h2>
        <p className="mt-2 text-sm text-slate-400">{subtitle}</p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge label={loading ? "Refreshing" : "Live"} tone={loading ? "warning" : "success"} />
        {newAlertsCount > 0 ? <StatusBadge label={`${newAlertsCount} new alerts`} tone="danger" /> : null}
        <div className="rounded-full border border-slate-700 bg-slate-900/80 px-4 py-2 text-xs text-slate-400">
          Last update: {lastUpdatedLabel}
        </div>
      </div>
    </header>
  );
}

export default HeaderBar;
