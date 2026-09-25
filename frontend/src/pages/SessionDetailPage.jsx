import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { MetricBar } from "../components/MetricBar.jsx";
import { RingScore } from "../components/RingScore.jsx";
import { StatusBadge } from "../components/StatusBadge.jsx";
import { Icons } from "../components/Icons.jsx";
import { ObserverFindingsList } from "../components/ObserverFindings.jsx";
import { ReportPanel } from "../components/ReportPanel.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api, ApiError } from "../api.js";

function useSessionBundle(id) {
  return useAsync(async () => {
    const session = await api.getSession(id);
    const [ike, flows, score, observerProfile] = await Promise.allSettled([
      api.getIke(id),
      api.getFlows(id),
      api.getScore(id),
      api.getSessionObserverProfile(id),
    ]);
    return {
      session,
      ike: ike.status === "fulfilled" ? ike.value : null,
      ikeError: ike.status === "rejected" ? ike.reason : null,
      flows: flows.status === "fulfilled" ? flows.value : [],
      score: score.status === "fulfilled" ? score.value : null,
      scoreError: score.status === "rejected" ? score.reason : null,
      observerProfile: observerProfile.status === "fulfilled" ? observerProfile.value : null,
    };
  }, [id]);
}

function TunnelGroupingForm({ session, onSaved }) {
  const [tunnelId, setTunnelId] = useState(session.tunnel_id || "");
  const [peerLabel, setPeerLabel] = useState(session.peer_label || "");
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try {
      await api.updateSession(session.id, { tunnel_id: tunnelId || null, peer_label: peerLabel || null });
      onSaved();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex items-center gap-3">
      <input
        className="text-sm font-medium bg-slate-100 px-2 py-1 rounded w-32 focus:outline-none focus:ring-1 focus:ring-apple-blue"
        placeholder="tunnel_id"
        value={tunnelId}
        onChange={(e) => setTunnelId(e.target.value)}
      />
      <input
        className="text-sm font-medium bg-slate-100 px-2 py-1 rounded w-40 focus:outline-none focus:ring-1 focus:ring-apple-blue"
        placeholder="peer_label"
        value={peerLabel}
        onChange={(e) => setPeerLabel(e.target.value)}
      />
      <button onClick={save} disabled={saving} className="apple-button-secondary px-3 py-1 text-xs">
        {saving ? "Saving..." : "Save"}
      </button>
    </div>
  );
}

export function SessionDetailPage() {
  const { id } = useParams();
  const { data, error, loading, reload } = useSessionBundle(id);
  const [analyzing, setAnalyzing] = useState(false);

  async function handleReanalyze() {
    setAnalyzing(true);
    try {
      await api.analyzeSession(id);
      reload();
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <Layout>
      <PageHeader
        crumbs="Analysis Objects / Sessions /"
        title={data?.session.filename || id}
        badge={
          data?.ike ? (
            <StatusBadge variant="success">ANALYZED</StatusBadge>
          ) : (
            <StatusBadge variant="warning">NOT ANALYZED</StatusBadge>
          )
        }
        actions={
          <>
            <Link to="/sessions" className="apple-button-secondary px-4 py-1.5 flex items-center gap-2">
              <Icons.ArrowLeft className="w-4 h-4" /> Back
            </Link>
            <button onClick={handleReanalyze} disabled={analyzing} className="apple-button-primary px-4 py-1.5">
              {analyzing ? "Analyzing..." : "Re-run Analysis"}
            </button>
          </>
        }
      />

      {loading && <div className="p-8">{<LoadingBlock label="Loading session..." />}</div>}
      {error && <div className="p-8">{<ErrorBlock error={error} onRetry={reload} />}</div>}

      {data && (
        <>
          {/* Top metadata strip */}
          <div className="px-8 py-5 flex flex-wrap items-center gap-8 bg-white border-b border-apple-border text-sm">
            <div>
              <span className="text-slate-500 font-medium block text-xs uppercase mb-1">Local Node</span>
              <span className="font-mono font-medium">{data.session.peer_src_ip || "—"}</span>
            </div>
            <div className="text-slate-300">↔</div>
            <div>
              <span className="text-slate-500 font-medium block text-xs uppercase mb-1">Remote Node</span>
              <span className="font-mono font-medium">{data.session.peer_dst_ip || "—"}</span>
            </div>
            <div className="w-px h-8 bg-slate-200"></div>
            <div>
              <span className="text-slate-500 font-medium block text-xs uppercase mb-1">Tunnel grouping</span>
              <TunnelGroupingForm session={data.session} onSaved={reload} />
            </div>
          </div>

          <div className="p-8 pb-16 grid grid-cols-12 gap-6 items-start">
            {/* LEFT COLUMN */}
            <div className="col-span-12 xl:col-span-8 flex flex-col gap-6">
              <div className="dashboard-card p-6">
                {!data.score ? (
                  <p className="text-sm text-slate-500">
                    {data.scoreError instanceof ApiError && data.scoreError.status === 404
                      ? "No score yet -- run analysis first."
                      : String(data.scoreError)}
                  </p>
                ) : (
                  <div className="flex flex-col md:flex-row items-start md:items-center gap-8">
                    <div className="flex items-center gap-6 md:pr-8 md:border-r border-slate-100">
                      <RingScore score={data.score.overall_score} />
                      <div>
                        <h2 className="text-xl font-semibold tracking-tight text-slate-900 mb-1">
                          {data.score.overall_score >= 85
                            ? "Architecture Approved"
                            : data.score.overall_score >= 65
                              ? "Moderate Risk"
                              : "Architecture At Risk"}
                        </h2>
                        <p className="text-sm text-slate-500 max-w-[220px] leading-snug">
                          Overall score covers crypto strength, compliance, and key management only. Metadata
                          exposure is reported independently below -- see the Observer Profile.
                        </p>
                      </div>
                    </div>
                    <div className="flex-1 w-full">
                      <MetricBar label="Cryptographic Matrix Strength" score={data.score.crypto_strength} />
                      <MetricBar label="Protocol Parameter Compliance" score={data.score.compliance} />
                      <MetricBar label="Key Management Protocols" score={data.score.key_management} />
                      <MetricBar
                        label="Metadata Exposure Liability"
                        score={data.score.metadata_exposure}
                        warning={data.score.metadata_exposure < 60}
                      />
                    </div>
                  </div>
                )}
              </div>

              <Card
                title="Deterministic IKE Configuration Extraction"
                badge={
                  data.ike && (
                    <div className="px-2 py-0.5 rounded text-xs bg-slate-200 text-slate-600 font-medium font-mono border border-slate-300 shadow-sm">
                      IKEv{data.ike.ike_version} / exch {data.ike.exchange_type}
                    </div>
                  )
                }
              >
                {!data.ike ? (
                  <p className="p-5 text-sm text-slate-500">No IKE finding yet -- run analysis first.</p>
                ) : (
                  <table className="w-full text-sm">
                    <tbody>
                      <Row label="IKE Specification Version" value={`IKEv${data.ike.ike_version}`} />
                      <Row label="Mode" value={data.session.mode || "unknown"} shaded />
                      <Row label="Proposed Cipher Suite" value={data.ike.encryption_alg || "unknown"} shaded />
                      <Row label="Integrity / Auth Algorithm" value={data.ike.auth_alg || "unknown"} />
                      <Row label="Diffie-Hellman Key Exchange Group" value={data.ike.dh_group || "unknown"} shaded />
                      <Row
                        label="Perfect Forward Secrecy (PFS)"
                        value={
                          <StatusBadge variant={data.ike.pfs_enabled ? "success" : "danger"}>
                            {data.ike.pfs_enabled ? "ENABLED" : "MISSING"}
                          </StatusBadge>
                        }
                      />
                      <Row label="SA Lifetime" value={data.ike.sa_lifetime ? `${data.ike.sa_lifetime}s` : "unknown"} shaded />
                      <Row label="Implementation guess" value={data.ike.implementation_guess || "unknown"} />
                    </tbody>
                  </table>
                )}
              </Card>

              <ReportPanel sessionId={id} />
            </div>

            {/* RIGHT COLUMN */}
            <div className="col-span-12 xl:col-span-4 flex flex-col gap-6">
              <Card
                title="Passive Heuristic Identifier (ESP)"
                badge={
                  <span className="flex items-center text-[10px] font-bold text-apple-blue uppercase tracking-widest">
                    <div className="w-1.5 h-1.5 rounded-full bg-apple-blue animate-pulse mr-1.5"></div>AI active
                  </span>
                }
              >
                {data.flows.length === 0 ? (
                  <p className="p-5 text-sm text-slate-500">No ESP flows found.</p>
                ) : (
                  <ul className="divide-y divide-slate-100">
                    {data.flows.map((flow, i) => (
                      <li key={i} className="p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-[13px] bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200 text-slate-700">
                            {flow.flow_key}
                          </span>
                          <span
                            className={`text-[11px] font-bold rounded px-1.5 py-0.5 ${
                              flow.confidence > 0.75 ? "bg-amber-100 text-amber-700" : "bg-slate-100 text-slate-500"
                            }`}
                          >
                            {(flow.confidence * 100).toFixed(0)}% CNF
                          </span>
                        </div>
                        <div className="font-semibold text-slate-900 text-sm">
                          {flow.predicted_traffic_type} traffic indicated
                        </div>
                        <div className="flex items-center gap-4 mt-2">
                          <div className="flex items-center text-[11px] text-slate-400">
                            <Icons.Terminal className="w-4 h-4 mr-1 text-slate-400" />
                            <span className="font-mono">avg size: {flow.avg_packet_size.toFixed(0)} B</span>
                          </div>
                          <div className="flex items-center text-[11px] text-slate-400">
                            <span className="font-mono text-slate-500">n= {flow.packet_count}</span>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>

              <Card title="Threat Matrix">
                {!data.score || data.score.threat_matrix.length === 0 ? (
                  <p className="p-5 text-sm text-slate-500">No threats flagged against the active policy.</p>
                ) : (
                  <div>
                    {data.score.threat_matrix.map((threat, i) => (
                      <div key={i} className="border-b border-slate-100 last:border-0 p-4">
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className={`inline-block w-2 h-2 rounded-full ${
                              threat.likelihood === "High" ? "bg-red-500" : "bg-amber-400"
                            }`}
                          ></span>
                          <span className="text-[11px] uppercase font-bold text-slate-500 tracking-wider">
                            {threat.likelihood} likelihood / {threat.impact} impact
                          </span>
                        </div>
                        <p className="text-sm text-slate-800 font-medium pl-4">{threat.finding}</p>
                        <p className="text-xs text-slate-500 pl-4 mt-1">{threat.recommendation}</p>
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card title="Observer Profile">
                <ObserverFindingsList findings={data.observerProfile?.findings} />
              </Card>
            </div>
          </div>
        </>
      )}
    </Layout>
  );
}

function Row({ label, value, shaded = false }) {
  return (
    <tr className={`border-b border-slate-50 hover:bg-slate-50 ${shaded ? "bg-slate-50/50" : ""}`}>
      <td className="px-5 py-3 text-slate-500 w-1/2">{label}</td>
      <td className="px-5 py-3 font-medium text-slate-900">{value}</td>
    </tr>
  );
}
