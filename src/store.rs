//! SQLite persistence layer.
//!
//! Responsibilities:
//! - store and manage rule definitions,
//! - store query logs for later inspection,
//! - periodically delete old logs according to retention policy.
//!
//! Notes:
//! - We use a single `rusqlite::Connection` protected by a `Mutex`. This keeps
//!   the implementation simple and is sufficient for an admin/logging workload.
//! - All database calls are blocking; callers should prefer `spawn_blocking`
//!   from async contexts (see `dns.rs` and `web.rs`).
//! - Query log time filtering is based on `ts_unix_ms` (numeric milliseconds),
//!   to avoid subtle issues with string time comparisons.

use std::{path::Path, sync::Mutex};

use rusqlite::{Connection, params};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    config::BootstrapRule,
    rules::{MatchKind, Rule, RuleType},
};

/// SQLite store wrapper.
///
/// The underlying `Connection` is not thread-safe, so we guard it with a `Mutex`.
#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (and create if needed) the SQLite database file.
    ///
    /// Also configures WAL mode for better concurrent read/write behavior.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let p = Path::new(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create required tables and indexes.
    ///
    /// Important:
    /// - This project treats schema mismatches as fatal (no migration logic).
    /// - If you change the schema, you must delete the existing sqlite file.
    pub fn init_schema(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              match_kind TEXT NOT NULL,
              name TEXT NOT NULL,
              rr_type TEXT NOT NULL,
              value TEXT NOT NULL,
              ttl INTEGER NOT NULL,
              priority INTEGER NOT NULL DEFAULT 0,
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
              updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_rules_lookup ON rules(enabled, rr_type, match_kind, name, priority);
            "#,
        )?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS query_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              ts_unix_ms INTEGER NOT NULL,
              client_ip TEXT NOT NULL,
              transport TEXT NOT NULL,
              qname TEXT NOT NULL,
              qtype TEXT NOT NULL,
              rcode TEXT NOT NULL,
              latency_ms INTEGER NOT NULL,
              cache_hit INTEGER NOT NULL,
              rule_hit INTEGER NOT NULL,
              upstream TEXT,
              answers TEXT
            );
            "#,
        )?;

        verify_query_log_schema(&conn)?;

        conn.execute_batch(
            r#"
            CREATE INDEX IF NOT EXISTS idx_query_log_ts_unix_ms ON query_log(ts_unix_ms);
            CREATE INDEX IF NOT EXISTS idx_query_log_qname ON query_log(qname);
            "#,
        )?;
        Ok(())
    }

    /// Insert `bootstrap_rules` only if the rules table is currently empty.
    ///
    /// This provides a convenient way to ship a default rule set without
    /// overwriting user-managed rules in an existing database.
    pub fn maybe_bootstrap_rules(&self, bootstrap: &[BootstrapRule]) -> anyhow::Result<()> {
        if bootstrap.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(1) FROM rules", [], |row| row.get(0))?;
        if count > 0 {
            return Ok(());
        }
        let tx = conn.transaction()?;
        for r in bootstrap {
            tx.execute(
                r#"
                INSERT INTO rules(match_kind, name, rr_type, value, ttl, priority, enabled)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    match_kind_to_str(r.match_kind),
                    r.name,
                    rule_type_to_str(r.rr_type),
                    r.value,
                    r.ttl as i64,
                    r.priority,
                    if r.enabled { 1 } else { 0 }
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Load all rules from the database.
    pub fn load_rules(&self) -> anyhow::Result<Vec<Rule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, match_kind, name, rr_type, value, ttl, priority, enabled
            FROM rules
            ORDER BY priority DESC, id ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let match_kind: String = row.get(1)?;
            let rr_type: String = row.get(3)?;
            Ok(Rule {
                id: row.get(0)?,
                match_kind: match_kind_from_str(&match_kind).ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(
                        1,
                        "match_kind".into(),
                        rusqlite::types::Type::Text,
                    )
                })?,
                name: row.get(2)?,
                rr_type: rule_type_from_str(&rr_type).ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(
                        3,
                        "rr_type".into(),
                        rusqlite::types::Type::Text,
                    )
                })?,
                value: row.get(4)?,
                ttl: row.get::<_, i64>(5)? as u32,
                priority: row.get(6)?,
                enabled: row.get::<_, i64>(7)? != 0,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Insert a single rule and return its row id.
    pub fn insert_rule(
        &self,
        match_kind: MatchKind,
        name: &str,
        rr_type: RuleType,
        value: &str,
        ttl: u32,
        priority: i32,
        enabled: bool,
    ) -> anyhow::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO rules(match_kind, name, rr_type, value, ttl, priority, enabled, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            "#,
            params![
                match_kind_to_str(match_kind),
                name,
                rule_type_to_str(rr_type),
                value,
                ttl as i64,
                priority,
                if enabled { 1 } else { 0 }
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Delete a rule by id.
    pub fn delete_rule(&self, id: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Enable/disable a rule by id.
    pub fn set_rule_enabled(&self, id: i64, enabled: bool) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE rules SET enabled = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2",
            params![if enabled { 1 } else { 0 }, id],
        )?;
        Ok(())
    }

    /// Insert a DNS query log row.
    pub fn insert_query_log(&self, entry: QueryLogEntry<'_>) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO query_log(ts, ts_unix_ms, client_ip, transport, qname, qtype, rcode, latency_ms, cache_hit, rule_hit, upstream, answers)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                entry.ts,
                entry.ts_unix_ms,
                entry.client_ip,
                entry.transport,
                entry.qname,
                entry.qtype,
                entry.rcode,
                entry.latency_ms,
                if entry.cache_hit { 1 } else { 0 },
                if entry.rule_hit { 1 } else { 0 },
                entry.upstream,
                entry.answers_json,
            ],
        )?;
        Ok(())
    }

    /// Delete query logs older than `retention_days`.
    pub fn cleanup_query_logs(&self, retention_days: i64) -> anyhow::Result<u64> {
        let cutoff = OffsetDateTime::now_utc() - Duration::days(retention_days.max(0));
        let cutoff_ms: i64 = (cutoff.unix_timestamp_nanos() / 1_000_000)
            .try_into()
            .unwrap_or(i64::MIN);
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "DELETE FROM query_log WHERE ts_unix_ms < ?1",
            params![cutoff_ms],
        )?;
        Ok(affected as u64)
    }

    /// List query logs with optional filters and pagination.
    ///
    /// Filters:
    /// - `from_ts` / `to_ts`: RFC3339 timestamps (e.g. from browser `toISOString()`).
    /// - `qname_like`: SQL LIKE pattern (e.g. `%example.com.%`).
    /// - `client_ip`: exact string match.
    ///
    /// Pagination:
    /// - `limit` and `offset` are applied after filtering and sorting by newest first.
    pub fn list_query_logs(
        &self,
        from_ts: Option<&str>,
        to_ts: Option<&str>,
        qname_like: Option<&str>,
        client_ip: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> anyhow::Result<Vec<QueryLogRow>> {
        let conn = self.conn.lock().unwrap();

        let mut sql = String::from(
            "SELECT id, ts, client_ip, transport, qname, qtype, rcode, latency_ms, cache_hit, rule_hit, upstream, answers FROM query_log WHERE 1=1",
        );
        let mut args: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(v) = from_ts.and_then(parse_rfc3339_ms) {
            sql.push_str(" AND ts_unix_ms >= ?");
            args.push(v.into());
        }
        if let Some(v) = to_ts.and_then(parse_rfc3339_ms) {
            sql.push_str(" AND ts_unix_ms <= ?");
            args.push(v.into());
        }
        if let Some(v) = qname_like {
            sql.push_str(" AND qname LIKE ?");
            args.push(rusqlite::types::Value::Text(v.to_string()));
        }
        if let Some(v) = client_ip {
            sql.push_str(" AND client_ip = ?");
            args.push(rusqlite::types::Value::Text(v.to_string()));
        }

        sql.push_str(" ORDER BY ts_unix_ms DESC LIMIT ? OFFSET ?");
        args.push((limit as i64).into());
        args.push((offset as i64).into());

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;

        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(QueryLogRow {
                id: row.get(0)?,
                ts: row.get(1)?,
                client_ip: row.get(2)?,
                transport: row.get(3)?,
                qname: row.get(4)?,
                qtype: row.get(5)?,
                rcode: row.get(6)?,
                latency_ms: row.get(7)?,
                cache_hit: row.get::<_, i64>(8)? != 0,
                rule_hit: row.get::<_, i64>(9)? != 0,
                upstream: row.get(10)?,
                answers_json: row.get(11)?,
            });
        }

        Ok(out)
    }

    /// Get aggregated statistics since a unix millisecond timestamp (inclusive).
    ///
    /// This is used by the WebUI stats page to compute "last 24h" metrics.
    pub fn stats_since(&self, since_unix_ms: i64) -> anyhow::Result<QueryStats> {
        let conn = self.conn.lock().unwrap();
        let (total, cache_hit, avg_latency): (i64, i64, Option<f64>) = conn.query_row(
            r#"
            SELECT
              COUNT(1) AS total,
              COALESCE(SUM(cache_hit), 0) AS cache_hit,
              AVG(latency_ms) AS avg_latency_ms
            FROM query_log
            WHERE ts_unix_ms >= ?1
            "#,
            params![since_unix_ms],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(QueryStats {
            total,
            cache_hit,
            avg_latency_ms: avg_latency.unwrap_or(0.0),
        })
    }
}

/// Borrowed query log row for insertion.
///
/// `ts` is RFC3339 for readability; `ts_unix_ms` is used for stable numeric filtering.
pub struct QueryLogEntry<'a> {
    pub ts: &'a str,
    pub ts_unix_ms: i64,
    pub client_ip: &'a str,
    pub transport: &'a str,
    pub qname: &'a str,
    pub qtype: &'a str,
    pub rcode: &'a str,
    pub latency_ms: i64,
    pub cache_hit: bool,
    pub rule_hit: bool,
    pub upstream: Option<&'a str>,
    pub answers_json: Option<&'a str>,
}

/// Returned query log row (for API/UI).
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryLogRow {
    pub id: i64,
    pub ts: String,
    pub client_ip: String,
    pub transport: String,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub latency_ms: i64,
    pub cache_hit: bool,
    pub rule_hit: bool,
    pub upstream: Option<String>,
    pub answers_json: Option<String>,
}

/// Aggregated statistics for a time window.
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryStats {
    pub total: i64,
    pub cache_hit: i64,
    pub avg_latency_ms: f64,
}

impl QueryStats {
    pub fn hit_rate(&self) -> f64 {
        if self.total <= 0 {
            0.0
        } else {
            (self.cache_hit as f64) / (self.total as f64)
        }
    }
}

/// Convert rule match kind into the canonical DB string.
fn match_kind_to_str(k: MatchKind) -> &'static str {
    match k {
        MatchKind::Exact => "exact",
        MatchKind::Suffix => "suffix",
        MatchKind::Wildcard => "wildcard",
    }
}

/// Parse DB string into a rule match kind.
fn match_kind_from_str(s: &str) -> Option<MatchKind> {
    match s {
        "exact" => Some(MatchKind::Exact),
        "suffix" => Some(MatchKind::Suffix),
        "wildcard" => Some(MatchKind::Wildcard),
        _ => None,
    }
}

/// Convert rule type into the canonical DB string.
fn rule_type_to_str(t: RuleType) -> &'static str {
    match t {
        RuleType::A => "A",
        RuleType::AAAA => "AAAA",
        RuleType::CNAME => "CNAME",
    }
}

/// Parse DB string into a rule type.
fn rule_type_from_str(s: &str) -> Option<RuleType> {
    match s {
        "A" => Some(RuleType::A),
        "AAAA" => Some(RuleType::AAAA),
        "CNAME" => Some(RuleType::CNAME),
        _ => None,
    }
}

/// Ensure the `query_log` table matches the expected schema.
///
/// We intentionally do not try to migrate old schemas. If this check fails,
/// the program instructs the operator to delete the sqlite DB and restart.
fn verify_query_log_schema(conn: &Connection) -> anyhow::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(query_log)")?;
    let mut rows = stmt.query([])?;
    let mut ok = false;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        let notnull: i64 = row.get(3)?;
        if name == "ts_unix_ms" && notnull == 1 {
            ok = true;
            break;
        }
    }
    if !ok {
        anyhow::bail!("incompatible sqlite schema for query_log; delete the sqlite db and restart");
    }
    Ok(())
}

/// Parse RFC3339 timestamp string into Unix milliseconds.
fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    // Accept RFC3339 from the WebUI (`toISOString`) and from internal logs.
    let dt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let ms: i64 = (dt.unix_timestamp_nanos() / 1_000_000).try_into().ok()?;
    Some(ms)
}
