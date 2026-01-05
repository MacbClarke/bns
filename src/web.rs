use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;
use tokio::sync::watch;
use tracing::info;

use crate::{
    config::AdminConfig,
    rules::{MatchKind, RuleSet, RuleType},
    store::{QueryLogRow, Store},
};

pub struct WebServerDeps {
    pub admin: AdminConfig,
    pub retention_days: i64,
    pub store: Arc<Store>,
    pub rules: Arc<RuleSet>,
}

pub struct WebServer {
    deps: WebServerDeps,
}

impl WebServer {
    pub fn new(deps: WebServerDeps) -> Self {
        Self { deps }
    }

    pub async fn run(self, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let state = AppState {
            admin: self.deps.admin.clone(),
            retention_days: self.deps.retention_days,
            store: self.deps.store.clone(),
            rules: self.deps.rules.clone(),
        };

        let api = Router::new()
            .route("/health", get(api_health))
            .route("/rules", get(api_rules_list).post(api_rules_create))
            .route("/rules/{id}", delete(api_rules_delete))
            .route("/rules/{id}/enable", post(api_rules_enable))
            .route("/logs", get(api_logs_list))
            .route("/cleanup", post(api_cleanup))
            .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
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
    store: Arc<Store>,
    rules: Arc<RuleSet>,
}

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

async fn api_health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
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
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}

fn default_limit() -> u32 {
    200
}

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
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

async fn api_cleanup(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let store = state.store.clone();
    let retention_days = state.retention_days;
    let affected = tokio::task::spawn_blocking(move || store.cleanup_query_logs(retention_days))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "deleted": affected })))
}
