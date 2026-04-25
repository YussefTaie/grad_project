import Panel from "../components/common/Panel";
import StatusBadge from "../components/common/StatusBadge";

function IncidentsScreen({ soc }) {
  return (
    <div className="space-y-6">
      {soc.incidents.map((incident) => (
        <Panel
          key={incident.id}
          title={incident.ip}
          subtitle="Incident"
          rightSlot={<StatusBadge label={incident.severity} tone={incident.severity === "ATTACK" ? "danger" : "warning"} />}
        >
          <div className="grid gap-6 xl:grid-cols-[0.7fr_0.3fr]">
            <div>
              <p className="mb-4 text-sm text-slate-400">Timeline</p>
              <div className="space-y-4 border-l border-slate-800 pl-4">
                {incident.timeline.map((step) => (
                  <div key={step} className="relative">
                    <span className="absolute -left-[22px] top-1.5 h-3 w-3 rounded-full bg-sky-400" />
                    <p className="text-sm text-slate-300">{step}</p>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <p className="mb-4 text-sm text-slate-400">Notes</p>
              <textarea
                className="min-h-[180px] w-full rounded-2xl border border-slate-700 bg-slate-950/80 p-4 text-sm text-slate-200 outline-none"
                defaultValue={incident.note}
              />
            </div>
          </div>
        </Panel>
      ))}
    </div>
  );
}

export default IncidentsScreen;
