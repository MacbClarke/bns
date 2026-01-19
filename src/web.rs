//! Admin HTTP server and API.
//!
//! Provides:
//! - Static Web UI from `./web/` (served as fallback service),
//! - JSON API under `/api/*` for managing rules and inspecting logs.
//!
//! All database calls are executed via `spawn_blocking` to keep the async runtime
//! responsive.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::watch;
use tower_http::services::ServeDir;
use tracing::info;

use crate::{
    cache::{CacheSnapshot, DnsCache},
    config::AdminConfig,
    rules::{MatchKind, RuleSet, RuleType},
    store::{QueryLogRow, QueryStats, Store},
};

/// Dependencies required by the web server.
pub struct WebServerDeps {
    /// Admin bind + optional auth token.
    pub admin: AdminConfig,
    /// Log retention used by the manual cleanup endpoint.
    pub retention_days: i64,
    /// In-memory cache (for inspection APIs).
    pub cache: Arc<DnsCache>,
    pub store: Arc<Store>,
    pub rules: Arc<RuleSet>,
}

/// Admin web server.
pub struct WebServer {
    deps: WebServerDeps,
}

impl WebServer {
    /// Create a new server instance.
    pub fn new(deps: WebServerDeps) -> Self {
        Self { deps }
    }

    /// Run the server until shutdown is requested.
    ///
    /// - Serves `/api/*` with optional bearer-token auth.
    /// - Serves static UI for all other paths.
    pub async fn run(self, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let state = AppState {
            admin: self.deps.admin.clone(),
            retention_days: self.deps.retention_days,
            cache: self.deps.cache.clone(),
            store: self.deps.store.clone(),
            rules: self.deps.rules.clone(),
        };

        let api = Router::new()
            .route("/health", get(api_health))
            .route("/stats", get(api_stats))
            .route("/cache", get(api_cache))
            .route("/rules", get(api_rules_list).post(api_rules_create))
            .route("/rules/{id}", delete(api_rules_delete))
            .route("/rules/{id}/enable", post(api_rules_enable))
            .route("/logs", get(api_logs_list))
            .route("/cleanup", post(api_cleanup))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state.clone());

        let app = Router::new()
            .nest("/api", api)
            .fallback_service(ServeDir::new("web").append_index_html_on_directories(true));

        let addr: SocketAddr = self.deps.admin.addr;
        info!(addr = %addr, "admin web listening");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(crate::shutdown::wait(shutdown))
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    admin: AdminConfig,
    retention_days: i64,
    cache: Arc<DnsCache>,
    store: Arc<Store>,
    rules: Arc<RuleSet>,
}

/// Optional bearer-token authentication for `/api/*`.
///
/// If `admin.token` is unset/empty, the API is open.
async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(token) = state.admin.token.as_deref().filter(|t| !t.is_empty()) {
        let auth = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());
        let ok = auth
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|t| t == token)
            .unwrap_or(false);
        if !ok {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    next.run(req).await
}

/// Basic liveness endpoint.
async fn api_health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Statistics for last 24 hours.
///
/// Returns JSON:
/// - `total`: total queries handled
/// - `cache_hit`: number of queries served from cache (fresh or stale)
/// - `hit_rate`: `cache_hit/total`
/// - `avg_latency_ms`: average response time (ms)
async fn api_stats(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let since = OffsetDateTime::now_utc() - Duration::hours(24);
    let since_ms: i64 = (since.unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .unwrap_or(i64::MIN);
    let store = state.store.clone();
    let stats: QueryStats = tokio::task::spawn_blocking(move || store.stats_since(since_ms))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "window_hours": 24,
        "total": stats.total,
        "cache_hit": stats.cache_hit,
        "hit_rate": stats.hit_rate(),
        "avg_latency_ms": stats.avg_latency_ms
    })))
}

#[derive(Debug, Deserialize)]
struct CacheQuery {
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
    /// If true, do not return entries whose state is `expired`.
    #[serde(default)]
    hide_expired: bool,
    /// Case-insensitive substring match against normalized qname.
    #[serde(default)]
    qname_like: Option<String>,
    /// Upper bound on how many entries to scan (starting at `offset`) while collecting results.
    #[serde(default = "default_cache_scan_limit")]
    scan_limit: u32,
}

fn default_cache_scan_limit() -> u32 {
    20_000
}

/// In-memory cache snapshot.
///
/// Intended for admin inspection only; returns a page of cache keys and entry metadata.
async fn api_cache(
    State(state): State<AppState>,
    Query(q): Query<CacheQuery>,
) -> Result<Json<CacheSnapshot>, StatusCode> {
    let limit = q.limit.min(2000) as usize;
    let offset = q.offset as usize;
    let scan_limit = q.scan_limit.clamp(limit as u32, 20_000) as usize;
    Ok(Json(state.cache.snapshot(
        offset,
        limit,
        scan_limit,
        q.hide_expired,
        q.qname_like.as_deref(),
    )))
}

#[derive(Serialize)]
struct RuleRow {
    id: i64,
    match_kind: MatchKind,
    name: String,
    rr_type: RuleType,
    value: String,
    ttl: u32,
    priority: i32,
    enabled: bool,
}

async fn api_rules_list(State(state): State<AppState>) -> impl IntoResponse {
    let rules = state
        .rules
        .list()
        .into_iter()
        .map(|r| RuleRow {
            id: r.id,
            match_kind: r.match_kind,
            name: r.name,
            rr_type: r.rr_type,
            value: r.value,
            ttl: r.ttl,
            priority: r.priority,
            enabled: r.enabled,
        })
        .collect::<Vec<_>>();
    Json(rules)
}

#[derive(Debug, Deserialize)]
struct CreateRuleReq {
    match_kind: MatchKind,
    name: String,
    rr_type: RuleType,
    value: String,
    ttl: u32,
    #[serde(default)]
    priority: i32,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Create a new rule.
///
/// This writes to SQLite and then refreshes the in-memory rule set.
async fn api_rules_create(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleReq>,
) -> Result<impl IntoResponse, StatusCode> {
    if req.ttl == 0 || req.name.trim().is_empty() || req.value.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let store = state.store.clone();
    let rules = state.rules.clone();
    let id = tokio::task::spawn_blocking(move || {
        store.insert_rule(
            req.match_kind,
            &req.name,
            req.rr_type,
            &req.value,
            req.ttl,
            req.priority,
            req.enabled,
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = rules.refresh();
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Delete a rule by id.
async fn api_rules_delete(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.delete_rule(id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state.rules.refresh();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct EnableReq {
    enabled: bool,
}

async fn api_rules_enable(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<EnableReq>,
) -> Result<impl IntoResponse, StatusCode> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.set_rule_enabled(id, req.enabled))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state.rules.refresh();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    from_ts: Option<String>,
    to_ts: Option<String>,
    qname_like: Option<String>,
    client_ip: Option<String>,
    /// Cursor paging: fetch rows older than this `(ts_unix_ms, id)` pair.
    before_ts_unix_ms: Option<i64>,
    before_id: Option<i64>,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}

fn default_limit() -> u32 {
    200
}

/// List query logs with filtering + pagination.
///
/// `from_ts/to_ts` must be RFC3339 strings (e.g. from browser `toISOString()`).
async fn api_logs_list(
    State(state): State<AppState>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<Vec<QueryLogRow>>, StatusCode> {
    let store = state.store.clone();
    let rows = tokio::task::spawn_blocking(move || {
        store.list_query_logs(
            q.from_ts.as_deref(),
            q.to_ts.as_deref(),
            q.qname_like.as_deref(),
            q.client_ip.as_deref(),
            q.limit.min(2000),
            q.offset,
            q.before_ts_unix_ms,
            q.before_id,
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

/// Manually trigger log cleanup according to configured retention days.
async fn api_cleanup(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let store = state.store.clone();
    let retention_days = state.retention_days;
    let affected = tokio::task::spawn_blocking(move || store.cleanup_query_logs(retention_days))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "deleted": affected })))
}
