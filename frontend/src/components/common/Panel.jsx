function Panel({ title, subtitle, rightSlot, children, className = "" }) {
  return (
    <section className={`rounded-2xl border border-slate-800 bg-panel p-5 shadow-[0_14px_34px_rgba(2,6,23,0.35)] transition-all duration-500 ease-in-out hover:shadow-glow ${className}`}>
      {(title || subtitle || rightSlot) && (
        <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            {subtitle ? (
              <p className="text-xs uppercase tracking-[0.24em] text-slate-500">{subtitle}</p>
            ) : null}
            {title ? <h3 className="mt-2 text-xl font-semibold text-white">{title}</h3> : null}
          </div>
          {rightSlot}
        </div>
      )}
      {children}
    </section>
  );
}

export default Panel;
