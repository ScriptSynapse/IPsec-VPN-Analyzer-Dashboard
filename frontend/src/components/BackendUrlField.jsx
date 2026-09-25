import { useEffect, useState } from "react";
import { getBaseUrl, setBaseUrl, api } from "../api.js";

export function BackendUrlField() {
  const [url, setUrl] = useState(getBaseUrl());
  const [status, setStatus] = useState("unknown"); // unknown | ok | down

  useEffect(() => {
    let cancelled = false;
    api
      .health()
      .then(() => !cancelled && setStatus("ok"))
      .catch(() => !cancelled && setStatus("down"));
    return () => {
      cancelled = true;
    };
  }, [url]);

  return (
    <div className="p-4 border-t border-apple-border">
      <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
        API base URL
      </label>
      <input
        className="w-full text-xs font-mono rounded-md border border-apple-border px-2 py-1.5 mb-2 focus:outline-none focus:ring-1 focus:ring-apple-blue"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        onBlur={() => setBaseUrl(url)}
      />
      <div className="flex items-center justify-between text-xs font-medium text-slate-500">
        <span>{status === "ok" ? "Backend reachable" : status === "down" ? "Backend unreachable" : "Checking..."}</span>
        <div
          className={`h-2 w-2 rounded-full ${
            status === "ok" ? "bg-green-500" : status === "down" ? "bg-red-500" : "bg-slate-300"
          }`}
        ></div>
      </div>
    </div>
  );
}
