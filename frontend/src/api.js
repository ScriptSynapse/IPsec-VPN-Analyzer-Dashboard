const DEFAULT_BASE_URL = "http://localhost:8000";
const STORAGE_KEY = "ipsec-analyzer.backend-url";

export function getBaseUrl() {
  return localStorage.getItem(STORAGE_KEY) || DEFAULT_BASE_URL;
}

export function setBaseUrl(url) {
  localStorage.setItem(STORAGE_KEY, url.replace(/\/+$/, ""));
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, { method = "GET", body, isForm = false, params } = {}) {
  const url = new URL(getBaseUrl() + path);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) url.searchParams.set(key, value);
    }
  }

  let resp;
  try {
    resp = await fetch(url, {
      method,
      body,
      headers: isForm ? undefined : body ? { "Content-Type": "application/json" } : undefined,
    });
  } catch {
    throw new ApiError(
      `Could not reach the backend at ${getBaseUrl()}. Is uvicorn running?`,
      0,
    );
  }

  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const data = await resp.json();
      detail = data.detail || JSON.stringify(data);
    } catch {
      /* body wasn't JSON */
    }
    throw new ApiError(`${method} ${path} -> ${resp.status}: ${detail}`, resp.status);
  }

  const contentType = resp.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return resp.json();
  return resp.text();
}

export const api = {
  health: () => request("/health"),

  uploadSession: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/sessions/upload", { method: "POST", body: form, isForm: true });
  },
  listSessions: () => request("/sessions"),
  getSession: (id) => request(`/sessions/${id}`),
  updateSession: (id, patch) =>
    request(`/sessions/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  analyzeSession: (id) => request(`/sessions/${id}/analyze`, { method: "POST" }),

  getIke: (id) => request(`/sessions/${id}/ike`),
  getFlows: (id) => request(`/sessions/${id}/flows`),
  getScore: (id, policyId) => request(`/sessions/${id}/score`, { params: { policy_id: policyId } }),
  getReport: (id, type, format) =>
    request(`/sessions/${id}/report`, { params: { type, format } }),

  getSessionObserverProfile: (id, format) =>
    request(`/sessions/${id}/observer-profile`, { params: { format } }),
  getTunnelObserverProfile: (tunnelId, format) =>
    request(`/tunnels/${encodeURIComponent(tunnelId)}/observer-profile`, { params: { format } }),

  listPolicies: () => request("/policy"),
  uploadPolicy: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/policy", { method: "POST", body: form, isForm: true });
  },
  getPolicy: (id) => request(`/policy/${id}`),

  listAgents: () => request("/agents"),
  registerAgent: (name) =>
    request("/agents", { method: "POST", body: JSON.stringify({ name }) }),

  getTopology: () => request("/topology"),
};
