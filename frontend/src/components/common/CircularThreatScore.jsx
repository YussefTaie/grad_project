function CircularThreatScore({ value, label, tone }) {
  const angle = Math.min(100, Math.max(0, value)) * 3.6;
  const toneClass =
    tone === "danger"
      ? "from-red-500 via-red-400 to-red-300"
      : tone === "warning"
        ? "from-yellow-500 via-yellow-400 to-amber-300"
        : "from-emerald-500 via-emerald-400 to-green-300";

  return (
    <div className="flex flex-col items-center justify-center gap-4">
      <div
        className="grid h-44 w-44 place-items-center rounded-full"
        style={{
          background: `conic-gradient(from 0deg, rgba(15,23,42,0.1) 0deg ${360 - angle}deg, rgba(15,23,42,0.1) ${360 - angle}deg 360deg), conic-gradient(from 0deg, #0f172a 0deg, #0f172a 360deg)`,
        }}
      >
        <div
          className={`grid h-36 w-36 place-items-center rounded-full bg-gradient-to-br ${toneClass}`}
          style={{ boxShadow: "0 18px 48px rgba(2, 6, 23, 0.42)" }}
        >
          <div className="grid h-28 w-28 place-items-center rounded-full bg-slate-950 text-center">
            <div>
              <div className="text-4xl font-semibold text-white">{value}%</div>
              <div className="mt-1 text-[11px] uppercase tracking-[0.2em] text-slate-400">Threat</div>
            </div>
          </div>
        </div>
      </div>
      <p className="text-base font-medium text-slate-200">{label}</p>
    </div>
  );
}

export default CircularThreatScore;
