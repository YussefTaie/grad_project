import Panel from "../components/common/Panel";
import MetricTile from "../components/common/MetricTile";
import StatusBadge from "../components/common/StatusBadge";

function SystemStatusScreen({ soc }) {
  const apiTone = soc.apiStatus.health === "live" ? "success" : "warning";

  return (
    <div className="space-y-6">
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="AI Status" value="Running" helper="Model pipeline active." />
        <MetricTile label="API Status" value={soc.health.status} helper="Health endpoint summary." />
        <MetricTile label="Latency" value="120ms" helper="Current average API latency." />
        <MetricTile label="Uptime" value="3h 20m" helper="Session uptime snapshot." />
      </section>

      <Panel title="Service health" subtitle="System Status">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <div className="rounded-2xl bg-slate-900/75 p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-300">Health API</span>
              <StatusBadge label={soc.apiStatus.health} tone={apiTone} />
            </div>
            <p className="mt-3 text-sm text-slate-500">Backend status, model mode, and database reachability.</p>
          </div>
          <div className="rounded-2xl bg-slate-900/75 p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-300">Alerts endpoint</span>
              <StatusBadge label={soc.apiStatus.alerts} tone={soc.apiStatus.alerts === "live" ? "success" : "warning"} />
            </div>
            <p className="mt-3 text-sm text-slate-500">Latest alert ingestion and read acknowledgment channel.</p>
          </div>
          <div className="rounded-2xl bg-slate-900/75 p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-300">Flows endpoint</span>
              <StatusBadge label={soc.apiStatus.flows} tone={soc.apiStatus.flows === "live" ? "success" : "warning"} />
            </div>
            <p className="mt-3 text-sm text-slate-500">Telemetry stream endpoint readiness for live monitoring.</p>
          </div>
        </div>
      </Panel>
    </div>
  );
}

export default SystemStatusScreen;
