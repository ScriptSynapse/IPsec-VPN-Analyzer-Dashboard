import { Link } from "react-router-dom";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api } from "../api.js";

export function TunnelsListPage() {
  const { data: sessions, error, loading, reload } = useAsync(() => api.listSessions(), []);

  const tunnels = {};
  for (const s of sessions || []) {
    if (!s.tunnel_id) continue;
    tunnels[s.tunnel_id] ??= { count: 0, peerLabel: s.peer_label, latest: s.created_at };
    tunnels[s.tunnel_id].count += 1;
    if (s.created_at > tunnels[s.tunnel_id].latest) tunnels[s.tunnel_id].latest = s.created_at;
    if (s.peer_label) tunnels[s.tunnel_id].peerLabel = s.peer_label;
  }
  const tunnelEntries = Object.entries(tunnels);

  return (
    <Layout>
      <PageHeader crumbs="Analysis Objects /" title="Tunnels (Observer Profiles)" />
      <div className="p-8">
        <p className="text-sm text-slate-500 mb-4">
          Sessions with the same <code className="font-mono">tunnel_id</code> (set from a session's detail page)
          get correlated here -- temporal patterns, peer stability, volume signatures. Fewer than 2 sessions in a
          tunnel shows an explicit "insufficient history" note instead of guessing.
        </p>
        {loading && <LoadingBlock label="Loading sessions..." />}
        {error && <ErrorBlock error={error} onRetry={reload} />}
        {tunnelEntries.length === 0 && sessions && (
          <div className="dashboard-card p-8 text-center text-sm text-slate-500">
            No sessions are grouped into a tunnel yet. Open a session and set its <code>tunnel_id</code> to start
            correlating it with others.
          </div>
        )}
        {tunnelEntries.length > 0 && (
          <Card>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 text-left text-xs uppercase text-slate-400">
                  <th className="px-5 py-3 font-semibold">Tunnel ID</th>
                  <th className="px-5 py-3 font-semibold">Peer label</th>
                  <th className="px-5 py-3 font-semibold">Sessions</th>
                  <th className="px-5 py-3 font-semibold">Latest capture</th>
                </tr>
              </thead>
              <tbody>
                {tunnelEntries.map(([tunnelId, info]) => (
                  <tr key={tunnelId} className="border-b border-slate-50 last:border-0 hover:bg-slate-50">
                    <td className="px-5 py-3">
                      <Link to={`/tunnels/${encodeURIComponent(tunnelId)}`} className="font-medium text-apple-blue">
                        {tunnelId}
                      </Link>
                    </td>
                    <td className="px-5 py-3">{info.peerLabel || "—"}</td>
                    <td className="px-5 py-3">{info.count}</td>
                    <td className="px-5 py-3 text-slate-500">{new Date(info.latest).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>
    </Layout>
  );
}
