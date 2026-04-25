export function formatTimestamp(value) {
  if (!value) {
    return "--";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat("en-GB", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

export function formatPercent(value) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

export function formatMegabytes(bytes) {
  const normalized = Number(bytes || 0);
  if (normalized >= 1024 * 1024) {
    return `${(normalized / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (normalized >= 1024) {
    return `${(normalized / 1024).toFixed(1)} KB`;
  }
  return `${normalized} B`;
}

export function titleize(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
