import { Link } from "react-router-dom";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api } from "../api.js";

export function SessionsListPage() {
  const { data: sessions, error, loading, reload } = useAsync(() => api.listSessions(), []);

  return (
    <Layout>
      <PageHeader
        crumbs="Analysis Objects /"
        title="Captured Sessions"
        actions={
          <Link to="/sessions/upload" className="apple-button-primary px-4 py-1.5 inline-block">
            Upload capture
          </Link>
        }
      />
      <div className="p-8">
        {loading && <LoadingBlock label="Loading sessions..." />}
        {error && <ErrorBlock error={error} onRetry={reload} />}
        {sessions && sessions.length === 0 && (
          <div className="dashboard-card p-8 text-center text-sm text-slate-500">
            No sessions yet.{" "}
            <Link to="/sessions/upload" className="text-apple-blue font-medium">
              Upload a capture
            </Link>{" "}
            to get started.
          </div>
        )}
        {sessions && sessions.length > 0 && (
          <Card>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 text-left text-xs uppercase text-slate-400">
                  <th className="px-5 py-3 font-semibold">Filename</th>
                  <th className="px-5 py-3 font-semibold">IKE version</th>
                  <th className="px-5 py-3 font-semibold">Mode</th>
                  <th className="px-5 py-3 font-semibold">Tunnel</th>
                  <th className="px-5 py-3 font-semibold">Uploaded</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.id} className="border-b border-slate-50 last:border-0 hover:bg-slate-50">
                    <td className="px-5 py-3">
                      <Link to={`/sessions/${s.id}`} className="font-medium text-apple-blue">
                        {s.filename}
                      </Link>
                      <div className="text-xs text-slate-400 font-mono">{s.id.slice(0, 8)}...</div>
                    </td>
                    <td className="px-5 py-3">{s.ike_version || "—"}</td>
                    <td className="px-5 py-3">{s.mode || "—"}</td>
                    <td className="px-5 py-3">
                      {s.tunnel_id ? (
                        <span className="bg-slate-100 px-2 py-0.5 rounded text-xs font-medium">{s.tunnel_id}</span>
                      ) : (
                        <span className="text-slate-400 text-xs">ungrouped</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-slate-500">{new Date(s.created_at).toLocaleString()}</td>
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
