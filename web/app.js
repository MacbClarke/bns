// BNS WebUI logic.
// - Uses fetch() to call `/api/*` endpoints.
// - Stores admin token in localStorage.
// - Renders rules and query logs.
// - Implements infinite scroll for logs (IntersectionObserver + offset paging).

const tokenInput = document.getElementById("token");
const saveTokenBtn = document.getElementById("saveToken");
const authErrorEl = document.getElementById("authError");
const authStatusEl = document.getElementById("authStatus");

// Read admin token from localStorage.
function loadToken() {
  return localStorage.getItem("bns_token") || "";
}
// Save admin token to localStorage.
function saveToken(t) {
  localStorage.setItem("bns_token", t || "");
}
// Display an auth error message next to the token input.
function setAuthError(msg) {
  if (!authErrorEl) return;
  const m = String(msg || "");
  authErrorEl.textContent = m;
  authErrorEl.style.display = m ? "inline" : "none";
}
// Display a short status message (e.g. after saving token).
function setAuthStatus(msg) {
  if (!authStatusEl) return;
  const m = String(msg || "");
  authStatusEl.textContent = m;
  authStatusEl.style.display = m ? "inline" : "none";
}
// Normalize different error shapes into "is this unauthorized?".
function isUnauthorized(e) {
  if (!e) return false;
  if (e.unauthorized === true) return true;
  if (e.status === 401) return true;
  if (typeof e.message === "string" && e.message.startsWith("401 ")) return true;
  return false;
}
// Build Authorization header if token exists.
function authHeaders() {
  const t = loadToken();
  if (!t) return {};
  return { Authorization: `Bearer ${t}` };
}
// Build a query string, skipping empty values.
function qs(params) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    u.set(k, v);
  }
  const s = u.toString();
  return s ? `?${s}` : "";
}

// Call JSON API under `/api`.
//
// Important behavior:
// - On 401, do NOT alert; instead show the message near the token input and throw
//   a marked error so callers can silently abort UI updates.
// - On success, clears auth error/status.
async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...authHeaders(),
    ...(options.headers || {}),
  };
  const res = await fetch(`/api${path}`, { ...options, headers });
  if (!res.ok) {
    if (res.status === 401) {
      setAuthError("Token 无效或未填写");
      setAuthStatus("");
      const err = new Error("unauthorized");
      err.unauthorized = true;
      err.status = 401;
      throw err;
    }
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`.trim());
  }
  setAuthError("");
  setAuthStatus("");
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res.text();
}

// Simple notification (used for non-auth errors and cleanup result).
function toast(msg) {
  alert(msg);
}

function initAuth() {
  if (!tokenInput || !saveTokenBtn) return;
  tokenInput.value = loadToken();
  saveTokenBtn.addEventListener("click", () => {
    saveToken(tokenInput.value.trim());
    setAuthError("");
    setAuthStatus("已保存");
    setTimeout(() => setAuthStatus(""), 1500);
  });
}

function initNavActive() {
  const path = location.pathname;
  const active =
    path.endsWith("/stats.html") || path.endsWith("stats.html")
      ? "stats"
      : path.endsWith("/rules.html") || path.endsWith("rules.html")
      ? "rules"
      : path.endsWith("/logs.html") || path.endsWith("logs.html")
      ? "logs"
      : "";
  document.querySelectorAll("nav a[data-nav]").forEach((a) => {
    if (a.getAttribute("data-nav") === active) a.classList.add("active");
    else a.classList.remove("active");
  });
}

function initRulesPage() {
  const rulesCard = document.getElementById("rulesCard");
  if (!rulesCard) return;

  const rulesTableBody = document.querySelector("#rulesTable tbody");
  const refreshRulesBtn = document.getElementById("refreshRules");
  const createRuleForm = document.getElementById("createRule");

  function renderRules(rules) {
    rulesTableBody.innerHTML = "";
    for (const r of rules) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.id}</td>
        <td>${r.enabled ? "yes" : "no"}</td>
        <td>${r.match_kind}</td>
        <td>${escapeHtml(r.name)}</td>
        <td>${r.rr_type}</td>
        <td>${escapeHtml(r.value)}</td>
        <td>${r.ttl}</td>
        <td>${r.priority}</td>
        <td class="rowActions"></td>
      `;
      const actions = tr.querySelector(".rowActions");
      const toggle = document.createElement("button");
      toggle.textContent = r.enabled ? "禁用" : "启用";
      toggle.addEventListener("click", async () => {
        try {
          await api(`/rules/${r.id}/enable`, {
            method: "POST",
            body: JSON.stringify({ enabled: !r.enabled }),
          });
          await refreshRules();
        } catch (e) {
          if (isUnauthorized(e)) return;
          toast(e.message);
        }
      });
      const del = document.createElement("button");
      del.textContent = "删除";
      del.className = "danger";
      del.addEventListener("click", async () => {
        if (!confirm(`删除规则 ${r.id}?`)) return;
        try {
          await api(`/rules/${r.id}`, { method: "DELETE" });
          await refreshRules();
        } catch (e) {
          if (isUnauthorized(e)) return;
          toast(e.message);
        }
      });
      actions.appendChild(toggle);
      actions.appendChild(del);
      rulesTableBody.appendChild(tr);
    }
  }

  async function refreshRules() {
    try {
      const rules = await api("/rules");
      renderRules(rules);
    } catch (e) {
      if (isUnauthorized(e)) return;
      toast(e.message);
    }
  }

  refreshRulesBtn.addEventListener("click", refreshRules);
  createRuleForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const data = new FormData(createRuleForm);
    const body = {
      match_kind: data.get("match_kind"),
      name: data.get("name"),
      rr_type: data.get("rr_type"),
      value: data.get("value"),
      ttl: Number(data.get("ttl") || 60),
      priority: Number(data.get("priority") || 0),
    };
    try {
      await api("/rules", { method: "POST", body: JSON.stringify(body) });
      createRuleForm.reset();
      createRuleForm.querySelector('[name="ttl"]').value = "60";
      await refreshRules();
    } catch (e) {
      if (isUnauthorized(e)) return;
      toast(e.message);
    }
  });

  refreshRules();
}

function initLogsPage() {
  const logsCard = document.getElementById("logsCard");
  if (!logsCard) return;

  const logsTableBody = document.querySelector("#logsTable tbody");
  const refreshLogsBtn = document.getElementById("refreshLogs");
  const cleanupLogsBtn = document.getElementById("cleanupLogs");
  const logsSentinel = document.getElementById("logsSentinel");
  const logFromTs = document.getElementById("logFromTs");
  const logToTs = document.getElementById("logToTs");
  const logQnameLike = document.getElementById("logQnameLike");
  const logClientIp = document.getElementById("logClientIp");

  const LOG_PAGE_SIZE = 200;
  let logsLoading = false;
  let logsDone = false;
  let logsQueryKey = "";
  let logsCursor = null;

  function renderLogs(rows) {
    for (const r of rows) {
      const answers = r.answers_json ? safeParseJson(r.answers_json) : [];
      const answersText = Array.isArray(answers)
        ? answers.map((a) => `${a.rr_type} ${a.value} ttl=${a.ttl}`).join("; ")
        : r.answers_json;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td title="${escapeHtml(r.ts)}">${escapeHtml(formatTsLocal(r.ts))}</td>
        <td>${escapeHtml(r.client_ip)}</td>
        <td>${escapeHtml(r.transport)}</td>
        <td>${escapeHtml(r.qname)}</td>
        <td>${escapeHtml(r.qtype)}</td>
        <td>${escapeHtml(r.rcode)}</td>
        <td>${r.latency_ms}</td>
        <td>${r.cache_hit ? "yes" : "no"}</td>
        <td>${r.rule_hit ? "yes" : "no"}</td>
        <td>${escapeHtml(r.upstream || "")}</td>
        <td>${escapeHtml(answersText || "")}</td>
      `;
      logsTableBody.appendChild(tr);
    }
  }

  function currentLogsQuery() {
    const fromTs = toRfc3339FromDateTimeLocal(logFromTs.value);
    const toTs = toRfc3339FromDateTimeLocalEnd(logToTs.value);
    return {
      from_ts: fromTs,
      to_ts: toTs,
      qname_like: logQnameLike.value.trim(),
      client_ip: logClientIp.value.trim(),
    };
  }

  async function loadMoreLogs() {
    if (logsLoading || logsDone) return;
    logsLoading = true;
    try {
      const base = currentLogsQuery();
      const cursorParams =
        logsCursor && typeof logsCursor.ts_unix_ms === "number" && typeof logsCursor.id === "number"
          ? { before_ts_unix_ms: logsCursor.ts_unix_ms, before_id: logsCursor.id }
          : {};
      const rows = await api(
        `/logs${qs({
          ...base,
          limit: LOG_PAGE_SIZE,
          ...cursorParams,
        })}`
      );
      renderLogs(rows);
      if (rows && rows.length) {
        const last = rows[rows.length - 1];
        if (last && typeof last.ts_unix_ms === "number" && typeof last.id === "number") {
          logsCursor = { ts_unix_ms: last.ts_unix_ms, id: last.id };
        }
      }
      if (!rows || rows.length < LOG_PAGE_SIZE) logsDone = true;
    } catch (e) {
      if (isUnauthorized(e)) return;
      toast(e.message);
    } finally {
      logsLoading = false;
    }
  }

  async function refreshLogs(reset = true) {
    const key = JSON.stringify(currentLogsQuery());
    if (reset || key !== logsQueryKey) {
      logsQueryKey = key;
      logsLoading = false;
      logsDone = false;
      logsCursor = null;
      logsTableBody.innerHTML = "";
    }
    await loadMoreLogs();
  }

  refreshLogsBtn.addEventListener("click", () => refreshLogs(true));
  cleanupLogsBtn.addEventListener("click", async () => {
    try {
      const res = await api("/cleanup", { method: "POST", body: "{}" });
      toast(`已删除 ${res.deleted} 条`);
      await refreshLogs(true);
    } catch (e) {
      if (isUnauthorized(e)) return;
      toast(e.message);
    }
  });

  if (logsSentinel && "IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries) => {
        for (const ent of entries) {
          if (ent.isIntersecting) refreshLogs(false);
        }
      },
      { root: null, rootMargin: "300px", threshold: 0.01 }
    );
    io.observe(logsSentinel);
  }

  refreshLogs(true);
}

function initStatsPage() {
  const statsCard = document.getElementById("statsCard");
  if (!statsCard) return;

  const refreshBtn = document.getElementById("refreshStats");
  const statTotal = document.getElementById("statTotal");
  const statHit = document.getElementById("statHit");
  const statRate = document.getElementById("statRate");
  const statAvg = document.getElementById("statAvg");

  function fmtPct(x) {
    return `${(x * 100).toFixed(2)}%`;
  }

  async function refreshStats() {
    try {
      const s = await api("/stats");
      statTotal.textContent = String(s.total ?? 0);
      statHit.textContent = String(s.cache_hit ?? 0);
      statRate.textContent = fmtPct(Number(s.hit_rate ?? 0));
      const avg = Number(s.avg_latency_ms ?? 0);
      statAvg.textContent = `${avg.toFixed(2)} ms`;
    } catch (e) {
      if (isUnauthorized(e)) return;
      toast(e.message);
    }
  }

  refreshBtn.addEventListener("click", refreshStats);
  refreshStats();

  initCacheCard();
}

function initCacheCard() {
  const cacheCard = document.getElementById("cacheCard");
  if (!cacheCard) return;

  const refreshBtn = document.getElementById("refreshCache");
  const filterEl = document.getElementById("cacheFilter");
  const hideExpiredEl = document.getElementById("cacheHideExpired");
  const metaEl = document.getElementById("cacheMeta");
  const tbody = document.querySelector("#cacheTable tbody");

  const CACHE_LIMIT = 2000; // server clamps to 2000
  const CACHE_SCAN_LIMIT = 20000; // keep small to avoid blocking cache ops
  const HIDE_EXPIRED_KEY = "bns_cache_hide_expired";
  const CACHE_FILTER_KEY = "bns_cache_filter";
  let loading = false;
  let total = 0;
  let scanned = 0;
  let truncated = false;
  let lastItems = [];
  let filterTimer = null;

  function hideExpiredEnabled() {
    return Boolean(hideExpiredEl?.checked);
  }

  if (hideExpiredEl) {
    const saved = localStorage.getItem(HIDE_EXPIRED_KEY);
    hideExpiredEl.checked = saved == null ? true : saved === "1";
    hideExpiredEl.addEventListener("change", () => {
      localStorage.setItem(HIDE_EXPIRED_KEY, hideExpiredEl.checked ? "1" : "0");
      refresh();
    });
  }

  function filterValue() {
    return String(filterEl?.value || "").trim();
  }

  if (filterEl) {
    filterEl.value = localStorage.getItem(CACHE_FILTER_KEY) || "";
    filterEl.addEventListener("input", () => {
      if (filterTimer) clearTimeout(filterTimer);
      filterTimer = setTimeout(() => {
        localStorage.setItem(CACHE_FILTER_KEY, filterValue());
        refresh();
      }, 350);
    });
    filterEl.addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter") return;
      localStorage.setItem(CACHE_FILTER_KEY, filterValue());
      refresh();
    });
  }

  function fmtTs(unixMs) {
    if (!unixMs && unixMs !== 0) return "";
    const d = new Date(Number(unixMs));
    if (Number.isNaN(d.getTime())) return "";
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(d);
  }

  function render() {
    tbody.innerHTML = "";
    for (const it of lastItems) {
      const tr = document.createElement("tr");
      const ttl = Number(it.remaining_ttl_secs ?? 0);
      const stale = Number(it.remaining_stale_secs ?? 0);
      tr.innerHTML = `
        <td>${escapeHtml(it.qname || "")}</td>
        <td>${escapeHtml(it.qtype_name || String(it.qtype || ""))}</td>
        <td>${escapeHtml(it.state || "")}</td>
        <td>${ttl}</td>
        <td>${stale}</td>
        <td title="${escapeHtml(String(it.expires_unix_ms))}">${escapeHtml(fmtTs(it.expires_unix_ms))}</td>
      `;
      tbody.appendChild(tr);
    }

    if (metaEl) {
      const loaded = Array.isArray(lastItems) ? lastItems.length : 0;
      const filt = filterValue();
      const bits = [`共 ${total} 条`, `已返回 ${loaded} 条`];
      if (hideExpiredEnabled()) bits.push("已隐藏 expired");
      if (filt) bits.push(`qname 包含 "${filt}"`);
      if (scanned) bits.push(`已扫描 ${scanned} 条`);
      if (truncated) bits.push("扫描已截断");
      metaEl.textContent = bits.join("，");
    }
  }

  async function refresh() {
    if (loading) return;
    loading = true;
    try {
      const res = await api(
        `/cache${qs({
          limit: CACHE_LIMIT,
          offset: 0,
          hide_expired: hideExpiredEnabled() ? "true" : "",
          qname_like: filterValue(),
          scan_limit: CACHE_SCAN_LIMIT,
        })}`
      );
      total = Number(res.total ?? 0);
      lastItems = Array.isArray(res.items) ? res.items : [];
      scanned = Number(res.scanned ?? 0);
      truncated = Boolean(res.truncated);
      render();
    } catch (e) {
      if (isUnauthorized(e)) return;
      toast(e.message);
    } finally {
      loading = false;
    }
  }

  if (refreshBtn) refreshBtn.addEventListener("click", () => refresh());
  refresh();
}

// Escape user/content values before inserting into innerHTML.
function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Parse JSON safely; if parsing fails, return the original string.
function safeParseJson(s) {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}

// Convert `datetime-local` value to RFC3339 (UTC) for the server.
function toRfc3339FromDateTimeLocal(v) {
  if (!v) return "";
  const d = parseDateTimeLocal(v);
  if (!d) return "";
  return d.toISOString();
}

// Convert "to" time to RFC3339 (UTC), treating minute-level values as inclusive.
//
// HTML `datetime-local` commonly only provides minute precision (`YYYY-MM-DDTHH:mm`).
// Users typically expect "to 10:30" to include values within that minute, so we
// convert it to 10:30:59.999 local time before encoding.
function toRfc3339FromDateTimeLocalEnd(v) {
  if (!v) return "";
  const d = parseDateTimeLocal(v);
  if (!d) return "";
  // For typical `datetime-local` values like `YYYY-MM-DDTHH:mm`, treat "to" as inclusive end of that minute.
  if (v.length === 16) {
    d.setTime(d.getTime() + 60_000 - 1);
  }
  return d.toISOString();
}

// Parse `datetime-local` value as local time.
//
// We avoid `new Date("YYYY-MM-DDTHH:mm")` because browsers differ on whether that
// string is parsed as local time or UTC.
function parseDateTimeLocal(v) {
  // Avoid browser differences around `new Date("YYYY-MM-DDTHH:mm")` parsing.
  // Parse as local time explicitly.
  const m = String(v).match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/
  );
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = m[6] ? Number(m[6]) : 0;
  const ms = m[7] ? Number(m[7].padEnd(3, "0")) : 0;
  const d = new Date(year, month - 1, day, hour, minute, second, ms);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

// Format server timestamp (RFC3339) to the browser's local time zone.
//
// The raw timestamp is preserved in the `title` attribute of the table cell.
function formatTsLocal(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);
}

document.addEventListener("DOMContentLoaded", () => {
  initNavActive();
  initAuth();
  initStatsPage();
  initRulesPage();
  initLogsPage();
});
