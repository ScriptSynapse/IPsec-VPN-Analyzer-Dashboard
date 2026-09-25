import { useState } from "react";
import { Card } from "./Card.jsx";
import { LoadingBlock, ErrorBlock } from "./Loading.jsx";
import { useAsync } from "../hooks/useAsync.js";
import { api } from "../api.js";

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function ReportPanel({ sessionId }) {
  const [type, setType] = useState("technical");
  const { data: report, error, loading, reload } = useAsync(
    () => api.getReport(sessionId, type, "json"),
    [sessionId, type],
  );

  async function handleDownload() {
    const md = await api.getReport(sessionId, type, "markdown");
    downloadText(`${sessionId}_${type}_report.md`, md);
  }

  return (
    <Card
      title="Assessment Report"
      badge={
        <div className="flex gap-1">
          {["technical", "executive"].map((t) => (
            <button
              key={t}
              onClick={() => setType(t)}
              className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${
                type === t ? "bg-slate-800 text-white" : "bg-slate-200 text-slate-600"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      }
    >
      <div className="p-5">
        {loading && <LoadingBlock label="Building report..." />}
        {error && <ErrorBlock error={error} onRetry={reload} />}
        {/* "risk_band" in report guards against the one-frame race where `type`
            has already flipped to "executive" but the previous (technical-
            shaped) report object hasn't been cleared/replaced yet. */}
        {report && type === "executive" && "risk_band" in report && (
          <div>
            <div className="flex items-center gap-4 mb-3">
              <span className="text-sm font-semibold">Risk band: {report.risk_band}</span>
              <span className="text-sm text-slate-500">Overall score: {report.overall_score?.toFixed(1)}/100</span>
            </div>
            <p className="text-sm text-slate-700 whitespace-pre-line leading-relaxed">{report.summary}</p>
          </div>
        )}
        {report && type === "technical" && (
          <pre className="text-xs bg-slate-50 rounded-lg p-4 overflow-x-auto max-h-96 overflow-y-auto font-mono">
            {JSON.stringify(report, null, 2)}
          </pre>
        )}
        {report && (
          <button onClick={handleDownload} className="apple-button-secondary px-3 py-1.5 text-xs mt-4">
            Download markdown
          </button>
        )}
      </div>
    </Card>
  );
}
