// ─────────────────────────────────────────────────────────────────────────────
// socApi.js  —  HTTP client for the IDS/IPS Flask backend
// Base URL read from .env (VITE_API_BASE_URL) — defaults to Flask port 5000.
// ─────────────────────────────────────────────────────────────────────────────

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

// Build a WebSocket URL from the same base (kept for future WS support)
export function createWebSocketUrl(path = "/ws") {
  const baseUrl = new URL(API_BASE_URL);
  const protocol = baseUrl.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${baseUrl.host}${path}`;
}

// ─── low-level fetch wrapper ─────────────────────────────────────────────────
async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    throw new Error(
      `[socApi] ${options.method || "GET"} ${path} → HTTP ${response.status}`
    );
  }

  return response.json();
}

// ─── public API ──────────────────────────────────────────────────────────────
export const socApi = {
  /** Last N alerts ordered newest-first */
  getAlerts(limit = 50) {
    return request(`/alerts?limit=${limit}`);
  },

  /** Recent ML detections ordered by detected_at DESC */
  getDetections(limit = 20) {
    return request(`/detections?limit=${limit}`);
  },

  /** Recent network flows ordered by captured_at DESC */
  getFlows(limit = 20) {
    return request(`/flows?limit=${limit}`);
  },

  /** Recent IPS actions (BLOCK / MONITOR / ISOLATE / UNBLOCK) */
  getActions(limit = 20) {
    return request(`/actions?limit=${limit}`);
  },

  /** All currently blocked IPs */
  getBlockedIps() {
    return request("/blocked-ips");
  },

  /** API + DB health check */
  getHealth() {
    return request("/health");
  },

  getPentestFindings(limit = 50, target = null, includeResolved = true) {
    const params = new URLSearchParams({ limit });
    if (target) params.set("target", target);
    params.set("include_resolved", includeResolved ? "true" : "false");
    return request(`/pentest/findings?${params.toString()}`);
  },

  getAutoResponseStatus() {
    return request("/auto-response/status");
  },

  setAutoResponseEnabled(enabled) {
    return request("/auto-response/status", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
  },

  getActionState(target) {
    return request(`/actions/state/${encodeURIComponent(target)}`);
  },

  blockHost(target, reason = "Manual block") {
    return request("/actions/block", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  isolateHost(target, reason = "Manual isolate") {
    return request("/actions/isolate", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  whitelistHost(target, reason = "Manual whitelist") {
    return request("/actions/whitelist", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  /** Mark one alert as read (Flask route: POST /alerts/read/<id>) */
  markAlertRead(id) {
    return request(`/alerts/read/${id}`, { method: "POST" });
  },

  /** OS-level execution: Block IP */
  blockIp(ip) {
    return request(`/block`, {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  },

  /** OS-level execution: Unblock IP */
  unblockIp(ip) {
    return request(`/unblock`, {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  },

  /** OS-level execution: Isolate Host/Device */
  isolateIp(ip) {
    return request(`/isolate`, {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  },

  /** OS-level execution: Remove Isolation */
  unisolateIp(ip) {
    return request(`/unisolate`, {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  },
};
