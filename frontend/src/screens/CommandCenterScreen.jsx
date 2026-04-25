import Panel from "../components/common/Panel";
import StatCard from "../components/common/StatCard";
import DataTable from "../components/common/DataTable";
import CircularThreatScore from "../components/common/CircularThreatScore";
import MetricTile from "../components/common/MetricTile";
import StatusBadge from "../components/common/StatusBadge";
import AttackDistributionChart from "../components/charts/AttackDistributionChart";
import SkeletonBlock from "../components/common/SkeletonBlock";

function CommandCenterScreen({ soc, onNavigate, onSelectIp }) {
  const topVector =
    soc.distribution.reduce(
      (top, current) => (current.value > top.value ? current : top),
      soc.distribution[0] || { label: "--", value: 0 },
    )?.label || "--";

  const stats = [
    {
      label: "Active Attacks",
      value: soc.detections.filter((item) => item.result === "ATTACK").length,
      status: "High",
      tone: "danger",
      caption: "Immediate response recommended",
    },
    {
      label: "Suspicious Cases",
      value: soc.detections.filter((item) => item.result === "SUSPICIOUS").length,
      status: "Medium",
      tone: "warning",
      caption: "Awaiting analyst validation",
    },
    {
      label: "Blocked IPs",
      value: soc.blockedIps.length,
      status: "Good",
      tone: "info",
      caption: "Containment actions active",
    },
    {
      label: "Isolated Devices",
      value: soc.hosts.filter((item) => item.status === "ISOLATED").length,
      status: "Stable",
      tone: "success",
      caption: "Device segmentation enforced",
    },
  ];

  return (
    <div className="space-y-6">
      <section className="grid gap-6 xl:grid-cols-[0.82fr_1.18fr]">
        <Panel className="bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
          {soc.loading ? (
            <div className="grid gap-4 md:grid-cols-2">
              <SkeletonBlock className="h-44 w-full" />
              <SkeletonBlock className="h-44 w-full" />
              <SkeletonBlock className="h-32 w-full" />
              <SkeletonBlock className="h-32 w-full" />
            </div>
          ) : (
            <div className="flex flex-col items-center gap-6 lg:flex-row lg:justify-between">
              <CircularThreatScore
                value={soc.threatState.percent}
                label={soc.threatState.label}
                tone={soc.threatState.tone}
              />
              <div className="grid min-w-0 flex-1 gap-4 md:grid-cols-2">
                <MetricTile
                  label="Open Alerts"
                  value={soc.alerts.filter((item) => !item.is_read).length}
                  helper="Unread alerts requiring acknowledgment."
                />
                <MetricTile
                  label="Top Attack Vector"
                  value={topVector}
                  helper="Highest distribution inside the current sample."
                  valueClassName="text-xl uppercase tracking-wide sm:text-2xl"
                />
                <MetricTile
                  label="Most Active Host"
                  value={soc.hosts[0]?.ip || "--"}
                  helper="Highest incident concentration across recent flows."
                  valueClassName="break-all text-base sm:text-lg xl:text-xl"
                />
                <MetricTile
                  label="API / DB"
                  value={`${soc.health.status} / ${soc.health.db_status}`}
                  helper="Backend platform health snapshot."
                  valueClassName="text-base sm:text-lg xl:text-xl"
                />
              </div>
            </div>
          )}
        </Panel>

        <Panel title="Attack Distribution" subtitle="Threat mix">
          {soc.loading ? <SkeletonBlock className="h-[280px] w-full" /> : <AttackDistributionChart data={soc.distribution} />}
        </Panel>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {stats.map((item) => (
          <StatCard key={item.label} {...item} />
        ))}
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <Panel
          title="Recent Alerts"
          subtitle="Max 5 rows"
          rightSlot={<button type="button" className="text-sm text-sky-300" onClick={() => onNavigate("alerts")}>View all alerts</button>}
        >
          <DataTable
            columns={[
              { key: "ip", header: "IP" },
              { key: "type", header: "Type" },
              {
                key: "status",
                header: "Status",
                render: (row) => (
                  <StatusBadge
                    label={row.statusLabel}
                    tone={row.is_read ? "success" : row.type === "SUSPICIOUS" ? "warning" : "danger"}
                  />
                ),
              },
              { key: "timeLabel", header: "Time" },
            ]}
            rows={soc.alerts.slice(0, 5)}
            loading={soc.loading}
            emptyMessage="Recent alerts will appear here once the alerts endpoint starts returning records."
            onRowClick={(row) => {
              onSelectIp(row.ip);
              onNavigate("hosts");
            }}
          />
        </Panel>

        <Panel title="Analyst Priorities" subtitle="Briefing">
          <div className="space-y-4">
            <div className="rounded-2xl bg-slate-900/75 p-4">
              <p className="text-sm text-slate-400">Suspicious queue</p>
              <p className="mt-3 text-2xl font-semibold text-white">
                {soc.detections.filter((item) => item.result !== "NORMAL").length}
              </p>
              <p className="mt-2 text-sm text-slate-500">Detections waiting for analyst action.</p>
            </div>
            <div className="rounded-2xl bg-slate-900/75 p-4">
              <p className="text-sm text-slate-400">Firewall activity</p>
              <p className="mt-3 text-2xl font-semibold text-white">{soc.actions.length}</p>
              <p className="mt-2 text-sm text-slate-500">Recent automated and analyst-triggered actions.</p>
            </div>
            <div className="rounded-2xl bg-slate-900/75 p-4">
              <p className="text-sm text-slate-400">Model mode</p>
              <p className="mt-3 text-2xl font-semibold text-white">{soc.health.model_mode}</p>
              <p className="mt-2 text-sm text-slate-500">Current backend classification mode.</p>
            </div>
          </div>
        </Panel>
      </section>
    </div>
  );
}

export default CommandCenterScreen;
