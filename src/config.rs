//! YAML configuration structures.
//!
//! This module defines the on-disk configuration schema (`config.yaml`).
//! All structures are `serde`-compatible and are loaded at startup.

use std::{fs, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};

/// Full application configuration (parsed from YAML).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// DNS listener configuration (bind address and transports).
    pub listen: ListenConfig,
    /// Upstream resolvers used for forwarding (UDP/TCP depending on client transport).
    pub upstreams: Vec<SocketAddr>,
    /// Strategy for choosing which upstream to try first.
    #[serde(default = "default_upstream_policy")]
    pub upstream_policy: UpstreamPolicy,
    /// Timeout applied per upstream attempt.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// In-memory cache behavior.
    #[serde(default)]
    pub cache: CacheConfig,
    /// SQLite storage settings (path, log retention).
    pub storage: StorageConfig,
    /// Admin web server settings.
    pub admin: AdminConfig,
    /// Optional: insert these rules only when the DB has no rules.
    #[serde(default)]
    pub bootstrap_rules: Vec<BootstrapRule>,
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&raw)?;
        Ok(cfg)
    }
}

/// DNS listener configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    /// Bind address, e.g. `0.0.0.0:53` or `[::]:53`.
    pub addr: SocketAddr,
    /// Whether to serve DNS-over-UDP.
    #[serde(default = "default_true")]
    pub udp: bool,
    /// Whether to serve DNS-over-TCP.
    #[serde(default = "default_true")]
    pub tcp: bool,
}

/// Upstream selection policy.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPolicy {
    /// Try upstreams in listed order until one succeeds.
    Failover,
    /// Rotate the starting upstream index per query.
    RoundRobin,
    /// Choose a pseudo-random starting upstream index per query.
    Random,
}

fn default_upstream_policy() -> UpstreamPolicy {
    UpstreamPolicy::Failover
}

fn default_timeout_ms() -> u64 {
    2000
}

/// Cache configuration (LRU in-memory).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Maximum number of cached entries (LRU).
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    /// Lower bound for cached TTL.
    #[serde(default = "default_cache_min_ttl")]
    pub min_ttl: u64,
    /// Upper bound for cached TTL.
    #[serde(default = "default_cache_max_ttl")]
    pub max_ttl: u64,
    /// TTL used for negative caching (NXDOMAIN / no-answer / other errors).
    #[serde(default = "default_cache_negative_ttl")]
    pub negative_ttl: u64,
    /// Enable stale-while-revalidate.
    #[serde(default)]
    pub stale_while_revalidate: bool,
    /// How long an expired entry can be served as stale (seconds).
    #[serde(default = "default_cache_stale_max_age")]
    pub stale_max_age: u64,
    /// Minimum stale window (seconds) used for adaptive stale window.
    #[serde(default = "default_cache_stale_min_age")]
    pub stale_min_age: u64,
    /// Half-life (seconds) for the hotness score decay used for adaptive stale window.
    #[serde(default = "default_cache_stale_half_life_secs")]
    pub stale_half_life_secs: u64,
    /// Hotness curve parameter (roughly: hits per half-life to reach ~50% of the range).
    #[serde(default = "default_cache_stale_hotness_k")]
    pub stale_hotness_k: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_cache_max_entries(),
            min_ttl: default_cache_min_ttl(),
            max_ttl: default_cache_max_ttl(),
            negative_ttl: default_cache_negative_ttl(),
            stale_while_revalidate: false,
            stale_max_age: default_cache_stale_max_age(),
            stale_min_age: default_cache_stale_min_age(),
            stale_half_life_secs: default_cache_stale_half_life_secs(),
            stale_hotness_k: default_cache_stale_hotness_k(),
        }
    }
}

fn default_cache_max_entries() -> usize {
    200_000
}
fn default_cache_min_ttl() -> u64 {
    5
}
fn default_cache_max_ttl() -> u64 {
    86_400
}
fn default_cache_negative_ttl() -> u64 {
    60
}
fn default_cache_stale_max_age() -> u64 {
    60
}
fn default_cache_stale_min_age() -> u64 {
    0
}
fn default_cache_stale_half_life_secs() -> u64 {
    300
}
fn default_cache_stale_hotness_k() -> u64 {
    10
}

/// Persistent storage settings (SQLite).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    /// SQLite database file path.
    pub path: String,
    /// How many days of query logs to retain.
    #[serde(default = "default_retention_days")]
    pub retention_days: i64,
}

fn default_retention_days() -> i64 {
    7
}

/// Admin web server configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    /// Bind address for HTTP (e.g. `127.0.0.1:8080`).
    pub addr: SocketAddr,
    /// Optional bearer token for API access. If empty/None, API is open.
    #[serde(default)]
    pub token: Option<String>,
}

/// Rule inserted at startup only when the rules table is empty.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BootstrapRule {
    pub match_kind: crate::rules::MatchKind,
    pub name: String,
    pub rr_type: crate::rules::RuleType,
    pub value: String,
    pub ttl: u32,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}
