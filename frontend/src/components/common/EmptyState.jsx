function EmptyState({ title, description }) {
  return (
    <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-950/45 px-6 py-10 text-center">
      <p className="text-base font-semibold text-white">{title}</p>
      <p className="mt-2 text-sm text-slate-400">{description}</p>
    </div>
  );
}

export default EmptyState;
