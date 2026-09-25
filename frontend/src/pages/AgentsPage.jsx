import { useState } from "react";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { StatusBadge } from "../components/StatusBadge.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api } from "../api.js";

const STATUS_VARIANT = { online: "success", offline: "danger", pending: "warning" };

function timeAgo(iso) {
  if (!iso) return "never";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function RegisterAgentForm({ onRegistered }) {
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [issued, setIssued] = useState(null); // { id, name, api_key } -- shown once
  const [copied, setCopied] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const agent = await api.registerAgent(name.trim());
      setIssued(agent);
      setName("");
      onRegistered();
    } catch (err) {
      setError(err);
    } finally {
      setSubmitting(false);
    }
  }

  if (issued) {
    return (
      <Card title="Agent registered — copy this key now">
        <div className="p-5 space-y-3">
          <p className="text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            This API key is shown <strong>exactly once</strong>. The backend only stores a hash of it — if you lose
            it, you'll need to register a new agent. See <code className="font-mono">backend/agent/README.md</code>{" "}
            for how to run the agent with it.
          </p>
          <div>
            <p className="text-xs uppercase text-slate-400 font-semibold mb-1">Agent ID</p>
            <code className="block text-xs bg-slate-50 border border-apple-border rounded px-3 py-2 font-mono break-all">
              {issued.id}
            </code>
          </div>
          <div>
            <p className="text-xs uppercase text-slate-400 font-semibold mb-1">API Key</p>
            <code className="block text-xs bg-slate-50 border border-apple-border rounded px-3 py-2 font-mono break-all">
              {issued.api_key}
            </code>
          </div>
          <div className="flex gap-2">
            <button
              className="apple-button-secondary px-3 py-1.5 text-xs"
              onClick={() => {
                navigator.clipboard?.writeText(
                  `--agent-id ${issued.id} --api-key ${issued.api_key}`,
                );
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
            >
              {copied ? "Copied!" : "Copy --agent-id / --api-key flags"}
            </button>
            <button className="apple-button-secondary px-3 py-1.5 text-xs" onClick={() => setIssued(null)}>
              Register another agent
            </button>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card title="Register a new agent">
      <form onSubmit={handleSubmit} className="p-5 flex gap-3 items-end">
        <div className="flex-1">
          <label className="block text-xs uppercase text-slate-400 font-semibold mb-1">Name</label>
          <input
            className="w-full border border-apple-border rounded-lg px-3 py-2 text-sm"
            placeholder="e.g. member-pc-1"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <button type="submit" disabled={submitting || !name.trim()} className="apple-button-primary px-4 py-2 text-sm">
          {submitting ? "Registering..." : "Register agent"}
        </button>
      </form>
      {error && <div className="px-5 pb-4"><ErrorBlock error={error} /></div>}
    </Card>
  );
}

export function AgentsPage() {
  const { data: agents, error, loading, reload } = useAsync(() => api.listAgents(), []);

  return (
    <Layout>
      <PageHeader crumbs="Analysis Objects /" title="Monitoring Agents" />
      <div className="p-8 space-y-6">
        <p className="text-sm text-slate-500 max-w-3xl">
          Agents run on authorized remote machines (see <code className="font-mono">backend/agent/</code>), capture
          traffic locally in rolling chunks, and upload each chunk here as a new Session — the same way Wazuh agents
          report back to a central manager. Tag an agent's uploads with a <code className="font-mono">tunnel_id</code>{" "}
          to feed real, time-spread data into that tunnel's Observer Profile correlation.
        </p>

        <RegisterAgentForm onRegistered={reload} />

        {loading && <LoadingBlock label="Loading agents..." />}
        {error && <ErrorBlock error={error} onRetry={reload} />}
        {agents && agents.length === 0 && (
          <div className="dashboard-card p-8 text-center text-sm text-slate-500">
            No agents registered yet. Register one above, then follow{" "}
            <code className="font-mono">backend/agent/README.md</code> to run it.
          </div>
        )}
        {agents && agents.length > 0 && (
          <Card title={`${agents.length} agent${agents.length === 1 ? "" : "s"}`}>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 text-left text-xs uppercase text-slate-400">
                  <th className="px-5 py-3 font-semibold">Name</th>
                  <th className="px-5 py-3 font-semibold">Status</th>
                  <th className="px-5 py-3 font-semibold">Sessions sent</th>
                  <th className="px-5 py-3 font-semibold">Last seen</th>
                  <th className="px-5 py-3 font-semibold">Registered</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.id} className="border-b border-slate-50 last:border-0 hover:bg-slate-50">
                    <td className="px-5 py-3 font-medium">{a.name}</td>
                    <td className="px-5 py-3">
                      <StatusBadge variant={STATUS_VARIANT[a.status] || "neutral"}>{a.status}</StatusBadge>
                    </td>
                    <td className="px-5 py-3">{a.session_count}</td>
                    <td className="px-5 py-3 text-slate-500">{timeAgo(a.last_seen_at)}</td>
                    <td className="px-5 py-3 text-slate-500">{new Date(a.created_at).toLocaleDateString()}</td>
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
