function MetricTile({ label, value, helper, valueClassName = "" }) {
  return (
    <div className="min-w-0 rounded-2xl bg-slate-900/70 p-4 transition-all duration-500 ease-in-out hover:scale-[1.03]">
      <p className="text-sm text-slate-400">{label}</p>
      <p
        className={`mt-3 max-w-full break-words text-lg font-semibold leading-tight text-white sm:text-xl xl:text-[1.7rem] ${valueClassName}`}
      >
        {value}
      </p>
      {helper ? <p className="mt-2 text-sm leading-6 text-slate-500">{helper}</p> : null}
    </div>
  );
}

export default MetricTile;
