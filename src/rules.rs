//! Rule engine for local DNS answers.
//!
//! Rules are stored in SQLite, loaded into memory, and evaluated for each DNS query.
//! Only A/AAAA/CNAME are supported by design.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::store::Store;

/// How a rule matches a query name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// Exact FQDN match (after normalization).
    Exact,
    /// Suffix match, e.g. pattern `.internal.` matches `a.internal.`.
    Suffix,
    /// `*.example.com.` style match (one or more labels before the suffix).
    Wildcard,
}

/// Supported rule record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum RuleType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    AAAA,
    #[serde(rename = "CNAME")]
    CNAME,
}

/// Rule as stored in DB and evaluated in memory.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: i64,
    pub match_kind: MatchKind,
    pub name: String,
    pub rr_type: RuleType,
    pub value: String,
    pub ttl: u32,
    pub priority: i32,
    pub enabled: bool,
}

/// Parsed and validated answer derived from a rule.
#[derive(Debug, Clone)]
pub enum RuleAnswer {
    A { addr: Ipv4Addr, ttl: u32 },
    AAAA { addr: Ipv6Addr, ttl: u32 },
    CNAME { name: String, ttl: u32 },
}

/// In-memory ruleset with a refresh capability.
///
/// We keep an `RwLock<Vec<Rule>>` so reads are cheap and refresh is atomic.
#[derive(Debug)]
pub struct RuleSet {
    store: std::sync::Arc<Store>,
    rules: std::sync::RwLock<Vec<Rule>>,
}

impl RuleSet {
    /// Load rules from SQLite and keep a reference for later refresh.
    pub fn load_from_store(store: std::sync::Arc<Store>) -> anyhow::Result<Self> {
        let mut rules = store.load_rules()?;
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
        Ok(Self {
            store,
            rules: std::sync::RwLock::new(rules),
        })
    }

    /// Reload rules from SQLite.
    ///
    /// Called after mutations (create/delete/enable) via the admin API.
    pub fn refresh(&self) -> anyhow::Result<()> {
        let mut rules = self.store.load_rules()?;
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
        *self.rules.write().unwrap() = rules;
        Ok(())
    }

    /// Find the first matching rule answer for a query.
    ///
    /// Ordering:
    /// - Rules are pre-sorted by `priority DESC, id ASC`.
    /// - The first enabled rule that matches and parses successfully wins.
    pub fn find_answer(&self, qname: &str, qtype: RuleType) -> Option<(i64, RuleAnswer)> {
        let qname = normalize_name(qname);
        for rule in self.rules.read().unwrap().iter() {
            if !rule.enabled {
                continue;
            }
            if rule.rr_type != qtype {
                continue;
            }
            if !match_rule(rule.match_kind, &rule.name, &qname) {
                continue;
            }
            if let Some(ans) = rule_to_answer(rule) {
                return Some((rule.id, ans));
            }
        }
        None
    }

    /// Return a copy of all rules (for UI/API list endpoint).
    pub fn list(&self) -> Vec<Rule> {
        self.rules.read().unwrap().clone()
    }
}

/// Check whether a rule pattern matches the query name.
///
/// All comparisons use normalized names (lowercase + trailing dot).
fn match_rule(kind: MatchKind, pattern: &str, qname: &str) -> bool {
    let pattern = normalize_name(pattern);
    match kind {
        MatchKind::Exact => qname == pattern,
        MatchKind::Suffix => qname.ends_with(&pattern),
        MatchKind::Wildcard => {
            // Only supports patterns like `*.example.com.`.
            let Some(rest) = pattern.strip_prefix("*.") else {
                return false;
            };
            qname.ends_with(rest) && qname != rest
        }
    }
}

/// Convert a rule row into a typed answer (validating IP formats etc).
fn rule_to_answer(rule: &Rule) -> Option<RuleAnswer> {
    let ttl = rule.ttl;
    match rule.rr_type {
        RuleType::A => match rule.value.parse::<IpAddr>() {
            Ok(IpAddr::V4(addr)) => Some(RuleAnswer::A { addr, ttl }),
            _ => None,
        },
        RuleType::AAAA => match rule.value.parse::<IpAddr>() {
            Ok(IpAddr::V6(addr)) => Some(RuleAnswer::AAAA { addr, ttl }),
            _ => None,
        },
        RuleType::CNAME => Some(RuleAnswer::CNAME {
            name: normalize_name(&rule.value),
            ttl,
        }),
    }
}

/// Normalize a DNS name for consistent matching and cache keys.
///
/// Behavior:
/// - trims whitespace,
/// - lowercases ASCII,
/// - ensures a trailing dot (`example.com.`).
pub fn normalize_name(name: &str) -> String {
    let s = name.trim().to_ascii_lowercase();
    if s.ends_with('.') { s } else { format!("{s}.") }
}
