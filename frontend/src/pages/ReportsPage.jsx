import { Link } from "react-router-dom";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api } from "../api.js";

export function ReportsPage() {
  const { data: sessions, error, loading, reload } = useAsync(() => api.listSessions(), []);

  return (
    <Layout>
      <PageHeader crumbs="Output /" title="Assessment Reports" />
      <div className="p-8">
        <p className="text-sm text-slate-500 mb-4">
          Technical and executive reports are generated per session -- pick one below to view or download it
          (requires that session to have been analyzed and scored already).
        </p>
        {loading && <LoadingBlock label="Loading sessions..." />}
        {error && <ErrorBlock error={error} onRetry={reload} />}
        {sessions && sessions.length === 0 && (
          <div className="dashboard-card p-8 text-center text-sm text-slate-500">No sessions to report on yet.</div>
        )}
        {sessions && sessions.length > 0 && (
          <Card>
            <ul className="divide-y divide-slate-100">
              {sessions.map((s) => (
                <li key={s.id} className="p-4 flex items-center justify-between hover:bg-slate-50">
                  <div>
                    <div className="font-medium text-sm text-slate-800">{s.filename}</div>
                    <div className="text-xs text-slate-400">{new Date(s.created_at).toLocaleString()}</div>
                  </div>
                  <Link to={`/sessions/${s.id}`} className="apple-button-secondary px-3 py-1.5 text-xs">
                    View report
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>
    </Layout>
  );
}
