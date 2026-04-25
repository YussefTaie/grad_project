import { useMemo, useState } from "react";
import Panel from "../components/common/Panel";
import SelectField from "../components/common/SelectField";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";
import SearchInput from "../components/common/SearchInput";
import { useDebouncedValue } from "../hooks/useDebouncedValue";

function AlertsScreen({ soc, onSelectIp, onNavigate, onOpenIncident }) {
  const [typeFilter, setTypeFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [sortBy, setSortBy] = useState("Newest");
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search, 300);

  const rows = useMemo(() => {
    const filtered = soc.alerts.filter((alert) => {
      const matchesType = typeFilter === "All" || alert.type === typeFilter.toUpperCase();
      const matchesStatus =
        statusFilter === "All" ||
        (statusFilter === "Open" && !alert.is_read) ||
        (statusFilter === "Acknowledged" && alert.is_read);
      const matchesSearch =
        !debouncedSearch ||
        alert.ip.toLowerCase().includes(debouncedSearch.toLowerCase()) ||
        String(alert.message || "").toLowerCase().includes(debouncedSearch.toLowerCase());

      return matchesType && matchesStatus && matchesSearch;
    });

    return [...filtered].sort((left, right) => {
      if (sortBy === "Oldest") {
        return String(left.time).localeCompare(String(right.time));
      }
      if (sortBy === "Type") {
        return String(left.type).localeCompare(String(right.type));
      }
      return String(right.time).localeCompare(String(left.time));
    });
  }, [debouncedSearch, soc.alerts, sortBy, statusFilter, typeFilter]);

  return (
    <Panel
      title="Alert triage"
      subtitle="Alerts"
      rightSlot={
        <div className="flex w-full flex-col gap-3 md:w-auto md:flex-row">
          <div className="min-w-[260px]">
            <SearchInput value={search} onChange={setSearch} placeholder="Search alerts by IP or message" />
          </div>
          <SelectField value={typeFilter} onChange={setTypeFilter} options={["All", "ATTACK", "SUSPICIOUS", "BLOCK", "MALWARE", "PENTEST_FINDING"]} />
          <SelectField value={statusFilter} onChange={setStatusFilter} options={["All", "Open", "Acknowledged"]} />
          <SelectField value={sortBy} onChange={setSortBy} options={["Newest", "Oldest", "Type"]} />
        </div>
      }
    >
      <DataTable
        columns={[
          { key: "ip", header: "IP" },
          { key: "type", header: "Type" },
          { key: "message", header: "Message" },
          {
            key: "status",
            header: "Status",
            render: (row) => (
              <StatusBadge
                label={row.statusLabel}
                tone={
                  row.type === "BLOCK"
                    ? "success"
                    : row.type === "SUSPICIOUS"
                      ? "warning"
                      : row.type === "ATTACK"
                        ? "danger"
                        : row.type === "PENTEST_FINDING"
                          ? "warning"
                        : row.is_read
                          ? "info"
                          : "neutral"
                }
              />
            ),
          },
          { key: "timeLabel", header: "Time" },
          {
            key: "actions",
            header: "Actions",
            render: (row) => (
              <div className="flex gap-2">
                <button
                  type="button"
                  className="rounded-lg bg-emerald-500/15 px-3 py-2 text-xs font-medium text-emerald-300"
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpenIncident?.(row.id || row.ip);
                  }}
                >
                  View Incident
                </button>
                <button
                  type="button"
                  className="rounded-lg bg-sky-500/15 px-3 py-2 text-xs font-medium text-sky-300"
                  onClick={(event) => {
                    event.stopPropagation();
                    soc.markAlertAsRead(row.id);
                  }}
                >
                  Mark as Read
                </button>
              </div>
            ),
          },
        ]}
        rows={rows}
        loading={soc.loading}
        emptyMessage="No alerts matched the selected type, status, or search query."
        onRowClick={(row) => {
          onSelectIp(row.ip);
          onNavigate("hosts");
        }}
      />
    </Panel>
  );
}

export default AlertsScreen;
