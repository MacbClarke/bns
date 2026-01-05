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

tokenInput.value = loadToken();
saveTokenBtn.addEventListener("click", () => {
  saveToken(tokenInput.value.trim());
  setAuthError("");
  setAuthStatus("已保存");
  setTimeout(() => setAuthStatus(""), 1500);
});

// Rules
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

// Fetch and render rules list.
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
    // restore defaults
    createRuleForm.querySelector('[name="ttl"]').value = "60";
    await refreshRules();
  } catch (e) {
    if (isUnauthorized(e)) return;
    toast(e.message);
  }
});

// Logs
const logsTableBody = document.querySelector("#logsTable tbody");
const refreshLogsBtn = document.getElementById("refreshLogs");
const cleanupLogsBtn = document.getElementById("cleanupLogs");
const logsSentinel = document.getElementById("logsSentinel");
const logFromTs = document.getElementById("logFromTs");
const logToTs = document.getElementById("logToTs");
const logQnameLike = document.getElementById("logQnameLike");
const logClientIp = document.getElementById("logClientIp");

const LOG_PAGE_SIZE = 200;
let logsOffset = 0;
let logsLoading = false;
let logsDone = false;
let logsQueryKey = "";

// Append log rows to the table.
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

// Current logs filter values (converted to server-friendly RFC3339).
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
  // Fetch the next page of logs and append to the table.
  //
  // This function is idempotent w.r.t. concurrent calls:
  // - `logsLoading` prevents overlapping fetches
  // - `logsDone` stops once the server returns fewer than `LOG_PAGE_SIZE` rows
  if (logsLoading || logsDone) return;
  logsLoading = true;
  try {
    const base = currentLogsQuery();
    const rows = await api(
      `/logs${qs({
        ...base,
        limit: LOG_PAGE_SIZE,
        offset: logsOffset,
      })}`
    );
    renderLogs(rows);
    logsOffset += rows.length;
    if (!rows || rows.length < LOG_PAGE_SIZE) logsDone = true;
  } catch (e) {
    if (isUnauthorized(e)) return;
    toast(e.message);
  } finally {
    logsLoading = false;
  }
}

async function refreshLogs(reset = true) {
  // Refresh logs, optionally resetting pagination state.
  //
  // We hash the current filter into `logsQueryKey`; when filters change we reset
  // offset and clear the table.
  const key = JSON.stringify(currentLogsQuery());
  if (reset || key !== logsQueryKey) {
    logsQueryKey = key;
    logsOffset = 0;
    logsLoading = false;
    logsDone = false;
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

// initial load
refreshRules();
refreshLogs(true);

if (logsSentinel && "IntersectionObserver" in window) {
  // Infinite scroll for logs: when the sentinel reaches the viewport, fetch next page.
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
