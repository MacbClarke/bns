use std::{fs, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub upstreams: Vec<SocketAddr>,
    #[serde(default = "default_upstream_policy")]
    pub upstream_policy: UpstreamPolicy,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub cache: CacheConfig,
    pub storage: StorageConfig,
    pub admin: AdminConfig,
    #[serde(default)]
    pub bootstrap_rules: Vec<BootstrapRule>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&raw)?;
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    pub addr: SocketAddr,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default = "default_true")]
    pub tcp: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPolicy {
    Failover,
    RoundRobin,
    Random,
}

fn default_upstream_policy() -> UpstreamPolicy {
    UpstreamPolicy::Failover
}

fn default_timeout_ms() -> u64 {
    2000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_cache_min_ttl")]
    pub min_ttl: u64,
    #[serde(default = "default_cache_max_ttl")]
    pub max_ttl: u64,
    #[serde(default = "default_cache_negative_ttl")]
    pub negative_ttl: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_cache_max_entries(),
            min_ttl: default_cache_min_ttl(),
            max_ttl: default_cache_max_ttl(),
            negative_ttl: default_cache_negative_ttl(),
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub path: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: i64,
}

fn default_retention_days() -> i64 {
    7
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    pub addr: SocketAddr,
    #[serde(default)]
    pub token: Option<String>,
}

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

