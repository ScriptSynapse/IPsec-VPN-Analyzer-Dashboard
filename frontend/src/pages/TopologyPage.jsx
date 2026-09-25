import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { TopologyGraph } from "../components/TopologyGraph.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api } from "../api.js";

export function TopologyPage() {
  const { data, error, loading, reload } = useAsync(() => api.getTopology(), []);

  const agentCount = data?.nodes.filter((n) => n.type === "agent").length ?? 0;
  const tunnelCount = data?.nodes.filter((n) => n.type === "tunnel").length ?? 0;
  const peerCount = data?.nodes.filter((n) => n.type === "peer").length ?? 0;

  return (
    <Layout>
      <PageHeader crumbs="Analysis Objects /" title="Global Topology" />
      <div className="p-8 space-y-6">
        <p className="text-sm text-slate-500 max-w-3xl">
          Every agent, every tunnel it's fed data into, and every peer IP observed on those tunnels — aggregated
          across all sessions, not just one capture. Hover a node to trace its connections; click a tunnel to open
          its Observer Profile.
        </p>

        {loading && <LoadingBlock label="Loading topology..." />}
        {error && <ErrorBlock error={error} onRetry={reload} />}

        {data && data.nodes.length === 0 && (
          <div className="dashboard-card p-8 text-center text-sm text-slate-500">
            Nothing to show yet — upload a session with a <code className="font-mono">tunnel_id</code>, or register
            an agent under <a href="/agents" className="text-apple-blue">Monitoring Agents</a> and let it report in.
          </div>
        )}

        {data && data.nodes.length > 0 && (
          <>
            <div className="grid grid-cols-3 gap-4 max-w-xl">
              <Card>
                <div className="p-4 text-center">
                  <p className="text-2xl font-semibold text-blue-600">{agentCount}</p>
                  <p className="text-xs text-slate-500 uppercase tracking-wide mt-1">Agents</p>
                </div>
              </Card>
              <Card>
                <div className="p-4 text-center">
                  <p className="text-2xl font-semibold text-violet-600">{tunnelCount}</p>
                  <p className="text-xs text-slate-500 uppercase tracking-wide mt-1">Tunnels</p>
                </div>
              </Card>
              <Card>
                <div className="p-4 text-center">
                  <p className="text-2xl font-semibold text-emerald-600">{peerCount}</p>
                  <p className="text-xs text-slate-500 uppercase tracking-wide mt-1">Peer IPs</p>
                </div>
              </Card>
            </div>
            <Card>
              <div className="p-6">
                <TopologyGraph nodes={data.nodes} edges={data.edges} />
              </div>
            </Card>
          </>
        )}
      </div>
    </Layout>
  );
}
