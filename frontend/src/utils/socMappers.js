import { formatMegabytes, formatNumber, formatPercent, formatTimestamp, titleize } from "./formatters";

function inferPort(attackType) {
  const normalized = String(attackType || "").toUpperCase();

  if (normalized.includes("BRUTE")) {
    return 22;
  }
  if (normalized.includes("MALWARE")) {
    return 445;
  }
  if (normalized.includes("DDOS")) {
    return 443;
  }

  return 80;
}

export function normalizeAlerts(alerts = []) {
  return alerts.map((alert) => ({
    ...alert,
    timeLabel: formatTimestamp(alert.time),
    statusLabel: alert.is_read ? "Acknowledged" : "Open",
  }));
}

export function normalizeDetections(detections = []) {
  return detections.map((item) => ({
    ...item,
    attack_type: String(item.attack_type || "UNKNOWN").toUpperCase(),
    attackLabel: titleize(item.attack_type || "UNKNOWN"),
    confidenceLabel: formatPercent(item.confidence),
    detectedAtLabel: formatTimestamp(item.detected_at),
  }));
}

export function normalizePentestFindings(findings = []) {
  return findings.map((item) => ({
    ...item,
    severity: String(item.severity || "medium").toUpperCase(),
    statusLabel: String(item.status || "detected").replaceAll("_", " "),
    mitigationLabel: String(item.mitigation_state || "unresolved").replaceAll("_", " "),
    confidenceLabel: formatPercent(item.confidence),
    updatedAtLabel: formatTimestamp(item.updated_at),
  }));
}

export function normalizeFlows(flows = [], detections = []) {
  return flows.map((flow, index) => {
    const linkedDetection = detections[index] || detections.find((item) => item.src_ip === flow.src_ip);
    const confidence = Number(flow.confidence ?? linkedDetection?.confidence ?? 0);

    return {
      id: flow.id ?? `${flow.src_ip}-${flow.dst_ip}-${index}`,
      timestamp: flow.captured_at || flow.detected_at || linkedDetection?.detected_at,
      timestampLabel: formatTimestamp(flow.captured_at || flow.detected_at || linkedDetection?.detected_at),
      sourceIp: flow.src_ip || linkedDetection?.src_ip || "Unknown",
      destinationIp: flow.dst_ip || "Internal host",
      port: flow.port ?? inferPort(linkedDetection?.attack_type),
      attackType: titleize(flow.attack_type || linkedDetection?.attack_type || "UNKNOWN"),
      result: flow.result || linkedDetection?.result || "NORMAL",
      confidence,
      confidenceLabel: formatPercent(confidence),
      pps: formatNumber(flow.pps),
      packets: formatNumber(flow.packets),
      bytes: formatNumber(flow.bytes),
      bytesCompact: formatMegabytes(flow.bytes),
    };
  });
}

export function deriveThreatState(detections = [], alerts = [], pentestFindings = []) {
  const riskScore =
    detections.filter((item) => item.result === "ATTACK").length * 18 +
    detections.filter((item) => item.result === "SUSPICIOUS").length * 10 +
    alerts.filter((item) => !item.is_read).length * 6 +
    pentestFindings.reduce((total, item) => total + Number(item.risk_score || 0), 0) * 0.2;

  const percent = Math.min(100, Math.max(12, Math.round(riskScore)));

  if (percent >= 75) {
    return { percent, label: "Threat Level: HIGH", tone: "danger" };
  }
  if (percent >= 45) {
    return { percent, label: "Threat Level: MEDIUM", tone: "warning" };
  }
  return { percent, label: "Threat Level: LOW", tone: "success" };
}

export function deriveAttackDistribution(detections = []) {
  const relevant = detections.filter((item) => item.attack_type !== "BENIGN");
  const total = relevant.length || 1;
  const ddos = relevant.filter((item) => item.attack_type.includes("DDOS")).length;
  const bruteForce = relevant.filter((item) => item.attack_type.includes("BRUTE")).length;
  const malware = relevant.filter((item) => item.attack_type.includes("MALWARE")).length;

  return [
    { label: "DDOS", value: Math.round((ddos / total) * 100), color: "bg-red-500" },
    { label: "Brute Force", value: Math.round((bruteForce / total) * 100), color: "bg-yellow-400" },
    { label: "Malware", value: Math.round((malware / total) * 100), color: "bg-emerald-500" },
  ];
}

export function deriveHosts(flows = [], detections = [], blockedIps = [], actions = []) {
  const hostMap = new Map();
  const blockedSet = new Set(blockedIps.map((item) => item.ip));
  const latestActionByIp = new Map();

  actions.forEach((action) => {
    const current = latestActionByIp.get(action.ip);
    if (!current || new Date(action.acted_at || 0).getTime() > new Date(current.acted_at || 0).getTime()) {
      latestActionByIp.set(action.ip, action);
    }
  });

  flows.forEach((flow) => {
    const current = hostMap.get(flow.sourceIp) || {
      ip: flow.sourceIp,
      firstSeen: flow.timestamp,
      lastSeen: flow.timestamp,
      packets: 0,
      bytes: 0,
      pps: 0,
      incidentCount: 0,
      status: "CLEAN",
    };

    current.firstSeen = current.firstSeen < flow.timestamp ? current.firstSeen : flow.timestamp;
    current.lastSeen = current.lastSeen > flow.timestamp ? current.lastSeen : flow.timestamp;
    current.packets += Number(String(flow.packets).replaceAll(",", ""));
    current.bytes += Number(String(flow.bytes).replaceAll(",", ""));
    current.pps = Math.max(current.pps, Number(String(flow.pps).replaceAll(",", "")));

    hostMap.set(flow.sourceIp, current);
  });

  detections.forEach((detection) => {
    const current = hostMap.get(detection.src_ip) || {
      ip: detection.src_ip,
      firstSeen: detection.detected_at,
      lastSeen: detection.detected_at,
      packets: 0,
      bytes: 0,
      pps: 0,
      incidentCount: 0,
      status: "MONITORED",
    };

    current.incidentCount += detection.result === "NORMAL" ? 0 : 1;
    current.lastSeen = current.lastSeen > detection.detected_at ? current.lastSeen : detection.detected_at;

    if (blockedSet.has(detection.src_ip)) {
      current.status = "ISOLATED";
    } else if (detection.result === "ATTACK") {
      current.status = "COMPROMISED";
    } else if (detection.result === "SUSPICIOUS") {
      current.status = "MONITORED";
    }

    hostMap.set(detection.src_ip, current);
  });

  return Array.from(hostMap.values())
    .map((host) => ({
      ...host,
      lastAction: latestActionByIp.get(host.ip)?.action_type || "NONE",
      actionReason: latestActionByIp.get(host.ip)?.reason || "",
      actionSource: latestActionByIp.get(host.ip)?.source || "manual",
      actionConfidence: latestActionByIp.get(host.ip)?.confidence ?? 0,
      actionAt: latestActionByIp.get(host.ip)?.acted_at || null,
      firstSeenLabel: formatTimestamp(host.firstSeen),
      lastSeenLabel: formatTimestamp(host.lastSeen),
      packetsLabel: formatNumber(host.packets),
      bytesLabel: formatMegabytes(host.bytes),
      ppsLabel: formatNumber(host.pps),
    }))
    .sort((left, right) => right.incidentCount - left.incidentCount);
}

export function deriveIncidents(alerts = [], detections = [], pentestFindings = []) {
  const pentestIncidents = pentestFindings.map((item) => ({
    id: item.finding_id,
    ip: item.target,
    severity: item.severity,
    attackType: item.title,
    timeline: (item.timeline || []).map(
      (step) => `${formatTimestamp(step.time)}: ${step.label}${step.details ? ` - ${step.details}` : ""}`,
    ),
    note: item.remediation || `${item.mitigationLabel}. Risk score ${item.risk_score}.`,
  }));

  const detectionIncidents = detections
    .filter((item) => item.result !== "NORMAL")
    .map((item, index) => {
      const relatedAlerts = alerts.filter((alert) => alert.ip === item.src_ip);
      return {
        id: item.id ?? `${item.src_ip}-${index}`,
        ip: item.src_ip,
        severity: item.result,
        attackType: item.attackLabel,
        timeline: [
          `${item.detectedAtLabel}: Detection classified as ${item.result}.`,
          ...relatedAlerts.slice(0, 2).map((alert) => `${alert.timeLabel}: ${alert.message}`),
        ],
        note: relatedAlerts[0]?.message || "Analyst note pending review.",
      };
    });

  return [...pentestIncidents, ...detectionIncidents].slice(0, 8);
}
