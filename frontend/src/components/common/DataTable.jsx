import EmptyState from "./EmptyState";
import SkeletonBlock from "./SkeletonBlock";

function DataTable({
  columns,
  rows,
  rowKey,
  emptyMessage = "No data available.",
  onRowClick,
  rowClassName,
  loading = false,
}) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
        <thead>
          <tr className="text-slate-400">
            {columns.map((column) => (
              <th key={column.key} className="pb-3 pr-4 font-medium last:pr-0">
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/80 text-slate-200">
          {loading ? (
            Array.from({ length: 5 }).map((_, index) => (
              <tr key={`skeleton-${index}`}>
                {columns.map((column) => (
                  <td key={`${column.key}-${index}`} className="py-3 pr-4 align-top last:pr-0">
                    <SkeletonBlock className="h-5 w-full max-w-[140px]" />
                  </td>
                ))}
              </tr>
            ))
          ) : rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="py-8 text-center text-slate-500">
                <EmptyState
                  title="Nothing matched the current view"
                  description={emptyMessage}
                />
              </td>
            </tr>
          ) : (
            rows.map((row, index) => (
              <tr
                key={rowKey ? rowKey(row) : row.id || index}
                className={`${onRowClick ? "cursor-pointer" : ""} transition-all duration-500 ease-in-out ${rowClassName ? rowClassName(row) : "hover:bg-slate-900/75"}`}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
              >
                {columns.map((column) => (
                  <td key={column.key} className="py-3 pr-4 align-top last:pr-0">
                    {column.render ? column.render(row) : row[column.key]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default DataTable;
