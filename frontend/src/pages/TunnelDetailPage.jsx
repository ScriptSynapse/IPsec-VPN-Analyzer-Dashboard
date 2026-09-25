import { Link, useParams } from "react-router-dom";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { Icons } from "../components/Icons.jsx";
import { ObserverFindingsList } from "../components/ObserverFindings.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api } from "../api.js";

export function TunnelDetailPage() {
  const { tunnelId } = useParams();
  const { data, error, loading, reload } = useAsync(async () => {
    const [profile, sessions] = await Promise.all([
      api.getTunnelObserverProfile(tunnelId),
      api.listSessions(),
    ]);
    return { profile, sessions: sessions.filter((s) => s.tunnel_id === tunnelId) };
  }, [tunnelId]);

  return (
    <Layout>
      <PageHeader
        crumbs="Analysis Objects / Tunnels /"
        title={tunnelId}
        actions={
          <Link to="/tunnels" className="apple-button-secondary px-4 py-1.5 flex items-center gap-2">
            <Icons.ArrowLeft className="w-4 h-4" /> Back
          </Link>
        }
      />
      <div className="p-8">
        {loading && <LoadingBlock label="Loading tunnel..." />}
        {error && <ErrorBlock error={error} onRetry={reload} />}
        {data && (
          <div className="grid grid-cols-12 gap-6 items-start">
            <div className="col-span-12 xl:col-span-5">
              <Card title={`Sessions in this tunnel (${data.profile.session_count})`}>
                <ul className="divide-y divide-slate-100">
                  {data.sessions.map((s) => (
                    <li key={s.id} className="p-4">
                      <Link to={`/sessions/${s.id}`} className="font-medium text-apple-blue text-sm">
                        {s.filename}
                      </Link>
                      <div className="text-xs text-slate-400">{new Date(s.created_at).toLocaleString()}</div>
                    </li>
                  ))}
                </ul>
              </Card>
            </div>
            <div className="col-span-12 xl:col-span-7">
              <Card title="Correlated Observer Profile">
                <ObserverFindingsList findings={data.profile.findings} />
              </Card>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
