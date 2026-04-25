import Panel from "../components/common/Panel";
import EmptyState from "../components/common/EmptyState";

function SecurityToolsPage() {
  return (
    <Panel title="Security Tools" subtitle="Future Module">
      <EmptyState
        title="Security tools module is ready for expansion"
        description="Use this route for future playbooks, enrichment tools, IOC search, and analyst utilities."
      />
    </Panel>
  );
}

export default SecurityToolsPage;
