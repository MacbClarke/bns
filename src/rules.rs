use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Exact,
    Suffix,
    Wildcard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum RuleType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    AAAA,
    #[serde(rename = "CNAME")]
    CNAME,
}

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

#[derive(Debug, Clone)]
pub enum RuleAnswer {
    A { addr: Ipv4Addr, ttl: u32 },
    AAAA { addr: Ipv6Addr, ttl: u32 },
    CNAME { name: String, ttl: u32 },
}

impl RuleAnswer {
}

#[derive(Debug)]
pub struct RuleSet {
    store: std::sync::Arc<Store>,
    rules: std::sync::RwLock<Vec<Rule>>,
}

impl RuleSet {
    pub fn load_from_store(store: std::sync::Arc<Store>) -> anyhow::Result<Self> {
        let mut rules = store.load_rules()?;
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
        Ok(Self {
            store,
            rules: std::sync::RwLock::new(rules),
        })
    }

    pub fn refresh(&self) -> anyhow::Result<()> {
        let mut rules = self.store.load_rules()?;
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
        *self.rules.write().unwrap() = rules;
        Ok(())
    }

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

    pub fn list(&self) -> Vec<Rule> {
        self.rules.read().unwrap().clone()
    }
}

fn match_rule(kind: MatchKind, pattern: &str, qname: &str) -> bool {
    let pattern = normalize_name(pattern);
    match kind {
        MatchKind::Exact => qname == pattern,
        MatchKind::Suffix => qname.ends_with(&pattern),
        MatchKind::Wildcard => {
            let Some(rest) = pattern.strip_prefix("*.") else {
                return false;
            };
            qname.ends_with(rest) && qname != rest
        }
    }
}

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

pub fn normalize_name(name: &str) -> String {
    let s = name.trim().to_ascii_lowercase();
    if s.ends_with('.') {
        s
    } else {
        format!("{s}.")
    }
}
