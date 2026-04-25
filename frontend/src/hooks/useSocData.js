import { useEffect, useMemo, useRef, useState } from "react";
import { socApi } from "../services/socApi";
import {
  fallbackActions,
  fallbackAlerts,
  fallbackBlockedIps,
  fallbackDetections,
  fallbackFlows,
} from "../data/fallbackData";
import {
  deriveAttackDistribution,
  deriveHosts,
  deriveIncidents,
  deriveThreatState,
  normalizeAlerts,
  normalizeDetections,
  normalizeFlows,
  normalizePentestFindings,
} from "../utils/socMappers";
import { formatTimestamp } from "../utils/formatters";

// Poll every 5 s — fast enough for a live SOC view, safe for the DB pool
const POLL_INTERVAL = 5000;


function serialize(value) {
  return JSON.stringify(value);
}

function mergeCollections(previous, incoming, keyField = "id") {
  if (!Array.isArray(previous) || previous.length === 0) {
    return incoming;
  }

  const previousMap = new Map(previous.map((item) => [item[keyField] ?? serialize(item), item]));

  return incoming.map((item) => {
    const key = item[keyField] ?? serialize(item);
    const previousItem = previousMap.get(key);

    if (!previousItem) {
      return item;
    }

    return serialize(previousItem) === serialize(item) ? previousItem : { ...previousItem, ...item };
  });
}

function mergeObject(previous, incoming) {
  if (!previous || serialize(previous) !== serialize(incoming)) {
    return incoming;
  }

  return previous;
}

export function useSocData() {
  const [alerts, setAlerts] = useState([]);
  const [detections, setDetections] = useState([]);
  const [flows, setFlows] = useState([]);
  const [actions, setActions] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [health, setHealth] = useState({ status: "degraded", model_mode: "unknown", db_status: "unknown" });
  const [pentestFindings, setPentestFindings] = useState([]);
  const [apiStatus, setApiStatus] = useState({
    alerts: "fallback",
    detections: "fallback",
    flows: "fallback",
    actions: "fallback",
    blockedIps: "fallback",
    pentestFindings: "fallback",
    health: "fallback",
  });
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState("");
  const [newAlertsCount, setNewAlertsCount] = useState(0);
  const [autoResponseEnabled, setAutoResponseEnabled] = useState(false);
  const [latestActionToast, setLatestActionToast] = useState(null);
  const previousAlertIdsRef = useRef([]);
  const firstLoadRef = useRef(true);
  const loadDataRef = useRef(null);

  useEffect(() => {
    let isMounted = true;

    const loadData = async () => {
      if (isMounted && firstLoadRef.current) {
        setLoading(true);
      }

      const nextStatus = {
        alerts: "live",
        detections: "live",
        flows: "live",
        actions: "live",
        blockedIps: "live",
        pentestFindings: "live",
        health: "live",
      };

      const results = await Promise.allSettled([
        socApi.getAlerts(12),
        socApi.getDetections(20),
        socApi.getFlows(20),
        socApi.getActions(20),
        socApi.getBlockedIps(),
        socApi.getPentestFindings(20),
        socApi.getHealth(),
      ]);

      if (!isMounted) {
        return;
      }

      const alertsData = results[0].status === "fulfilled" ? results[0].value : fallbackAlerts;
      const detectionsData = results[1].status === "fulfilled" ? results[1].value : fallbackDetections;
      const flowsData = results[2].status === "fulfilled" ? results[2].value : fallbackFlows;
      const actionsData = results[3].status === "fulfilled" ? results[3].value : fallbackActions;
      const blockedIpsData = results[4].status === "fulfilled" ? results[4].value : fallbackBlockedIps;
      const pentestFindingsData = results[5].status === "fulfilled" ? results[5].value : [];
      const healthData =
        results[6].status === "fulfilled"
          ? results[6].value
          : { status: "degraded", model_mode: "fallback", db_status: "unavailable" };

      results.forEach((result, index) => {
        if (result.status === "fulfilled") {
          return;
        }

        const keys = ["alerts", "detections", "flows", "actions", "blockedIps", "pentestFindings", "health"];
        nextStatus[keys[index]] = "fallback";
      });

      const normalizedDetections = normalizeDetections(detectionsData);
      const normalizedAlerts = normalizeAlerts(alertsData);
      const normalizedPentestFindings = normalizePentestFindings(pentestFindingsData);
      const incomingAlertIds = normalizedAlerts.map((item) => item.id).filter(Boolean);
      const freshAlerts = incomingAlertIds.filter((id) => !previousAlertIdsRef.current.includes(id)).length;
      const normalizedFlows = normalizeFlows(flowsData, normalizedDetections);

      setAlerts((current) => {
        const merged = mergeCollections(current, normalizedAlerts, "id");
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setDetections((current) => {
        const merged = mergeCollections(current, normalizedDetections, "id");
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setFlows((current) => {
        const merged = mergeCollections(current, normalizedFlows, "id");
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setActions((current) => {
        const merged = mergeCollections(current, actionsData, "id");
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setBlockedIps((current) => {
        const merged = mergeCollections(current, blockedIpsData, "ip");
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setPentestFindings((current) => {
        const merged = mergeCollections(current, normalizedPentestFindings, "finding_id");
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setHealth((current) => mergeObject(current, healthData));
      setAutoResponseEnabled(Boolean(healthData.auto_response_enabled));
      setApiStatus((current) => mergeObject(current, nextStatus));
      setLastUpdated(new Date().toISOString());
      setNewAlertsCount((current) =>
        previousAlertIdsRef.current.length === 0 || freshAlerts === current ? current : freshAlerts,
      );
      previousAlertIdsRef.current = incomingAlertIds;
      if (firstLoadRef.current) {
        firstLoadRef.current = false;
        setLoading(false);
      }
    };

    // Store loadData in ref so WebSocket can call it
    loadDataRef.current = loadData;

    loadData();
    const intervalId = window.setInterval(loadData, POLL_INTERVAL);

    return () => {
      isMounted = false;
      window.clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    if (!latestActionToast) return undefined;
    const timeoutId = window.setTimeout(() => setLatestActionToast(null), 3200);
    return () => window.clearTimeout(timeoutId);
  }, [latestActionToast]);
  // ── WebSocket: instant push from agent → dashboard ──────────
  useEffect(() => {
    const WS_URL = import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8001/ws/live";
    let ws;
    let reconnectTimer;

    const connect = () => {
      try {
        ws = new WebSocket(WS_URL);
      } catch {
        return;
      }

      ws.onopen = () => {
        console.log("[WS] Connected to live stream");
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          // When we receive an alert or action push, refresh data immediately
          if (msg.type === "alert" || msg.type === "action") {
            if (msg.type === "action") {
              setLatestActionToast({
                message: `${msg.data.source === "auto" ? "Auto-response" : "Manual action"}: ${msg.data.action} on ${msg.data.ip}`,
                id: `${msg.data.ip}-${msg.data.time}`,
              });
            }
            if (loadDataRef.current) {
              loadDataRef.current();
            }
          }
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        console.log("[WS] Disconnected — reconnecting in 3s");
        reconnectTimer = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      clearTimeout(reconnectTimer);
      if (ws) {
        ws.close();
      }
    };
  }, []);

  const markAlertAsRead = async (id) => {
    setAlerts((current) =>
      current.map((alert) =>
        alert.id === id ? { ...alert, is_read: true, statusLabel: "Acknowledged" } : alert,
      ),
    );

    try {
      await socApi.markAlertRead(id);
    } catch {
      // Keep optimistic state to avoid a disruptive UX when the endpoint is unavailable.
    }
  };

  const triggerHostAction = async (action, ip) => {
    const reason = `Manual ${action.toLowerCase()} from SOC analyst`;
    const methodMap = {
      BLOCK: socApi.blockHost,
      ISOLATE: socApi.isolateHost,
      WHITELIST: socApi.whitelistHost,
    };
    const handler = methodMap[action];
    if (!handler) {
      throw new Error(`Unsupported action: ${action}`);
    }
    const response = await handler(ip, reason);
    await loadDataRef.current?.();
    setLatestActionToast({
      message: `${response.log?.source === "auto" ? "Auto-response" : "Manual action"}: ${response.message}`,
      id: `${ip}-${Date.now()}`,
    });
    return response;
  };

  const toggleAutoResponse = async (enabled) => {
    const response = await socApi.setAutoResponseEnabled(enabled);
    setAutoResponseEnabled(Boolean(response.enabled));
    await loadDataRef.current?.();
    return response;
  };

  const threatState = useMemo(() => deriveThreatState(detections, alerts, pentestFindings), [alerts, detections, pentestFindings]);
  const distribution = useMemo(() => deriveAttackDistribution(detections), [detections]);
  const hosts = useMemo(() => deriveHosts(flows, detections, blockedIps, actions), [actions, blockedIps, detections, flows]);
  const incidents = useMemo(() => deriveIncidents(alerts, detections, pentestFindings), [alerts, detections, pentestFindings]);

  const sidebarCounts = useMemo(
    () => ({
      alerts: alerts.filter((item) => !item.is_read).length,
      suspiciousQueue: detections.filter((item) => item.result !== "NORMAL").length,
    }),
    [alerts, detections],
  );

  return {
    alerts,
    detections,
    flows,
    actions,
    blockedIps,
    pentestFindings,
    health,
    hosts,
    incidents,
    threatState,
    distribution,
    loading,
    apiStatus,
    sidebarCounts,
    newAlertsCount,
    markAlertAsRead,
    triggerHostAction,
    toggleAutoResponse,
    autoResponseEnabled,
    latestActionToast,
    pentestMode: health.pentest_mode || "lab",
    lastUpdatedLabel: formatTimestamp(lastUpdated),
  };
}
