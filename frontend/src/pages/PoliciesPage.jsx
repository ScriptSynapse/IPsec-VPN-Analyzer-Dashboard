import { useState } from "react";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Card } from "../components/Card.jsx";
import { LoadingBlock, ErrorBlock } from "../components/Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api, ApiError } from "../api.js";

export function PoliciesPage() {
  const { data: policies, error, loading, reload } = useAsync(() => api.listPolicies(), []);
  const [file, setFile] = useState(null);
  const [uploadError, setUploadError] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [selected, setSelected] = useState(null);

  async function handleUpload() {
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    try {
      await api.uploadPolicy(file);
      setFile(null);
      reload();
    } catch (err) {
      setUploadError(err instanceof ApiError ? err : new Error(String(err)));
    } finally {
      setUploading(false);
    }
  }

  return (
    <Layout>
      <PageHeader crumbs="Analysis Objects /" title="Custom Policies" />
      <div className="p-8 grid grid-cols-12 gap-6 items-start">
        <div className="col-span-12 xl:col-span-5">
          <div className="dashboard-card p-6 mb-6">
            <h3 className="font-semibold text-slate-800 text-sm mb-3">Upload a policy (YAML)</h3>
            <label className="block border-2 border-dashed border-apple-border rounded-lg p-5 text-center text-sm text-slate-500 cursor-pointer hover:bg-slate-50 mb-3">
              <input type="file" accept=".yaml,.yml" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              {file ? <span className="font-medium text-slate-800">{file.name}</span> : <span>Click to choose a .yaml file</span>}
            </label>
            <button
              className="apple-button-primary px-4 py-2 w-full"
              disabled={!file || uploading}
              onClick={handleUpload}
            >
              {uploading ? "Uploading..." : "Upload policy"}
            </button>
            {uploadError && <p className="text-sm text-red-600 mt-2">{uploadError.message}</p>}
            <p className="text-xs text-slate-400 mt-3">
              Overrides the default minimum scores, banned algorithms, PFS requirement, max SA lifetime, and
              category weights used by the scoring engine -- see API-SPEC.md for the schema.
            </p>
          </div>

          {loading && <LoadingBlock label="Loading policies..." />}
          {error && <ErrorBlock error={error} onRetry={reload} />}
          {policies && (
            <Card title={`Uploaded policies (${policies.length})`}>
              {policies.length === 0 ? (
                <p className="p-5 text-sm text-slate-500">No custom policies uploaded yet -- the default policy is used.</p>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {policies.map((p) => (
                    <li
                      key={p.id}
                      className={`p-4 cursor-pointer hover:bg-slate-50 ${selected?.id === p.id ? "bg-slate-50" : ""}`}
                      onClick={() => setSelected(p)}
                    >
                      <div className="font-medium text-sm text-slate-800">{p.name}</div>
                      <div className="text-xs text-slate-400">{new Date(p.created_at).toLocaleString()}</div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          )}
        </div>

        <div className="col-span-12 xl:col-span-7">
          <Card title={selected ? `Definition -- ${selected.name}` : "Select a policy to view its definition"}>
            {selected ? (
              <pre className="text-xs bg-slate-50 p-4 overflow-x-auto font-mono">
                {JSON.stringify(selected.definition, null, 2)}
              </pre>
            ) : (
              <p className="p-5 text-sm text-slate-500">Nothing selected.</p>
            )}
          </Card>
        </div>
      </div>
    </Layout>
  );
}
