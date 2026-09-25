import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layout, PageHeader } from "../components/Layout.jsx";
import { Icons } from "../components/Icons.jsx";
import { api, ApiError } from "../api.js";

export function UploadPage() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("idle"); // idle | uploading | analyzing | error
  const [error, setError] = useState(null);

  async function handleUploadAndAnalyze() {
    if (!file) return;
    setError(null);
    try {
      setStatus("uploading");
      const session = await api.uploadSession(file);
      setStatus("analyzing");
      await api.analyzeSession(session.id);
      navigate(`/sessions/${session.id}`);
    } catch (err) {
      setStatus("error");
      setError(err instanceof ApiError ? err : new Error(String(err)));
    }
  }

  return (
    <Layout>
      <PageHeader crumbs="Ingestion /" title="Upload Sandbox" />
      <div className="p-8 max-w-2xl">
        <div className="dashboard-card p-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-full bg-slate-900 text-white flex items-center justify-center">
              <Icons.Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Upload a capture</h2>
              <p className="text-sm text-slate-500">pcap / pcapng only. Analysis runs automatically after upload.</p>
            </div>
          </div>

          <label className="block border-2 border-dashed border-apple-border rounded-lg p-6 text-center text-sm text-slate-500 cursor-pointer hover:bg-slate-50 mb-4">
            <input
              type="file"
              accept=".pcap,.pcapng"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            {file ? (
              <span className="font-medium text-slate-800">{file.name}</span>
            ) : (
              <span>Click to choose a pcap/pcapng file</span>
            )}
          </label>

          <button
            className="apple-button-primary px-4 py-2 w-full"
            disabled={!file || status === "uploading" || status === "analyzing"}
            onClick={handleUploadAndAnalyze}
          >
            {status === "uploading" && "Uploading..."}
            {status === "analyzing" && "Analyzing..."}
            {(status === "idle" || status === "error") && "Upload + Analyze"}
          </button>

          {error && <p className="text-sm text-red-600 mt-3">{error.message}</p>}
        </div>
      </div>
    </Layout>
  );
}
