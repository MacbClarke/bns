//! In-memory DNS response cache.
//!
//! Stores whole wire-format DNS responses (as bytes) in an LRU keyed by:
//! - normalized qname (lowercase + trailing dot),
//! - qtype (u16).
//!
//! On cache hit, we rewrite:
//! - the DNS message ID to match the current request,
//! - the TTLs to represent the remaining lifetime.
//!
//! Optional stale-while-revalidate (SWR):
//! - When enabled, expired entries are kept for an additional `stale_max_age`.
//! - During that window, we may serve the stale response (TTL=0) and refresh
//!   asynchronously in the background.

use std::sync::Mutex;

use hickory_proto::op::Message;
use lru::LruCache;
use time::{Duration, OffsetDateTime};

use crate::config::CacheConfig;

/// Cache key for a DNS question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Normalized domain name: lowercase + trailing dot.
    pub qname: String,
    /// DNS record type as integer (e.g. A=1, AAAA=28).
    pub qtype: u16,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: OffsetDateTime,
    stale_until: OffsetDateTime,
}

#[derive(Debug)]
pub struct DnsCache {
    cfg: CacheConfig,
    inner: Mutex<LruCache<CacheKey, CacheEntry>>,
}

/// A lightweight view of an in-memory cache entry for the admin UI/API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheEntryInfo {
    pub qname: String,
    pub qtype: u16,
    pub qtype_name: String,
    pub state: CacheEntryState,
    pub expires_unix_ms: i64,
    pub stale_until_unix_ms: i64,
    pub remaining_ttl_secs: i64,
    pub remaining_stale_secs: i64,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEntryState {
    Fresh,
    Stale,
    Expired,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheSnapshot {
    pub total: usize,
    pub items: Vec<CacheEntryInfo>,
}

impl DnsCache {
    /// Create a new cache with a fixed maximum entry count.
    pub fn new(cfg: CacheConfig) -> Self {
        let cap = std::num::NonZeroUsize::new(cfg.max_entries.max(1)).unwrap();
        Self {
            cfg,
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Get a fresh cached response.
    ///
    /// Returns `None` if:
    /// - there is no entry, or
    /// - the entry has expired.
    ///
    /// Returned bytes have:
    /// - the request ID rewritten, and
    /// - TTLs rewritten to the remaining TTL.
    pub fn get(&self, key: &CacheKey, request_id: u16) -> Option<Vec<u8>> {
        let now = OffsetDateTime::now_utc();
        let mut cache = self.inner.lock().unwrap();
        let entry = cache.get(key)?.clone();
        if entry.expires_at <= now {
            // If SWR is disabled, or the stale window is over, evict immediately.
            if !self.cfg.stale_while_revalidate || entry.stale_until <= now {
                cache.pop(key);
            }
            return None;
        }

        let remaining = entry.expires_at - now;
        let remaining_secs: u32 = remaining
            .whole_seconds()
            .try_into()
            .unwrap_or(0)
            .max(0);

        rewrite_response_id_and_ttl(&entry.response, request_id, remaining_secs).ok()
    }

    /// Get a stale cached response (SWR), if enabled.
    ///
    /// A stale response may be served when:
    /// - `stale_while_revalidate` is enabled,
    /// - the entry is expired (`expires_at <= now`),
    /// - but still within the stale window (`now < stale_until`).
    ///
    /// Stale responses are returned with TTL=0.
    pub fn get_stale(&self, key: &CacheKey, request_id: u16) -> Option<Vec<u8>> {
        if !self.cfg.stale_while_revalidate {
            return None;
        }
        let now = OffsetDateTime::now_utc();
        let mut cache = self.inner.lock().unwrap();
        let entry = cache.get(key)?.clone();
        if entry.expires_at > now {
            return None;
        }
        if entry.stale_until <= now {
            cache.pop(key);
            return None;
        }
        rewrite_response_id_and_ttl(&entry.response, request_id, 0).ok()
    }

    /// Snapshot cache keys and entry metadata for inspection in the admin UI.
    ///
    /// This does not include response bytes, and it is safe to call even with a
    /// large cache, but it is still O(n) w.r.t. `offset + limit` because we must
    /// iterate the LRU to reach the requested page.
    pub fn snapshot(&self, offset: usize, limit: usize) -> CacheSnapshot {
        let now = OffsetDateTime::now_utc();
        let cache = self.inner.lock().unwrap();
        let total = cache.len();
        let mut items = Vec::with_capacity(limit.min(1000));

        for (idx, (k, v)) in cache.iter().enumerate() {
            if idx < offset {
                continue;
            }
            if items.len() >= limit {
                break;
            }

            let state = if v.expires_at > now {
                CacheEntryState::Fresh
            } else if self.cfg.stale_while_revalidate && v.stale_until > now {
                CacheEntryState::Stale
            } else {
                CacheEntryState::Expired
            };

            let expires_unix_ms: i64 = (v.expires_at.unix_timestamp_nanos() / 1_000_000)
                .try_into()
                .unwrap_or(i64::MAX);
            let stale_until_unix_ms: i64 =
                (v.stale_until.unix_timestamp_nanos() / 1_000_000)
                    .try_into()
                    .unwrap_or(i64::MAX);
            let remaining_ttl_secs = (v.expires_at - now).whole_seconds();
            let remaining_stale_secs = (v.stale_until - now).whole_seconds();

            items.push(CacheEntryInfo {
                qname: k.qname.clone(),
                qtype: k.qtype,
                qtype_name: format!("{:?}", hickory_proto::rr::RecordType::from(k.qtype)),
                state,
                expires_unix_ms,
                stale_until_unix_ms,
                remaining_ttl_secs,
                remaining_stale_secs,
            });
        }

        CacheSnapshot { total, items }
    }

    /// Insert/replace a cache entry.
    ///
    /// The provided TTL is clamped to `[min_ttl, max_ttl]` (and forced to >= 1).
    /// If SWR is enabled, the stale window is set to `expires_at + stale_max_age`.
    pub fn put(&self, key: CacheKey, response: &[u8], ttl_secs: u64) {
        let ttl_secs = ttl_secs
            .clamp(self.cfg.min_ttl, self.cfg.max_ttl)
            .max(1);
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(ttl_secs as i64);
        let stale_until =
            expires_at + Duration::seconds(self.cfg.stale_max_age.max(0) as i64);

        let mut cache = self.inner.lock().unwrap();
        cache.put(
            key,
            CacheEntry {
                response: response.to_vec(),
                expires_at,
                stale_until,
            },
        );
    }

    /// Negative caching TTL to apply when there is no positive answer TTL to use.
    pub fn negative_ttl(&self) -> u64 {
        self.cfg.negative_ttl
    }
}

/// Rewrite response ID and TTLs for a cached/stale response.
///
/// We set the same TTL for all records in answer/authority/additional sections.
/// This is a simplification that works well for typical resolver caching, but
/// it does not preserve per-record TTL differences.
fn rewrite_response_id_and_ttl(
    response: &[u8],
    request_id: u16,
    remaining_ttl: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut msg = Message::from_vec(response)?;
    msg.set_id(request_id);

    for r in msg.answers_mut().iter_mut() {
        r.set_ttl(remaining_ttl);
    }
    for r in msg.name_servers_mut().iter_mut() {
        r.set_ttl(remaining_ttl);
    }
    for r in msg.additionals_mut().iter_mut() {
        r.set_ttl(remaining_ttl);
    }

    Ok(msg.to_vec()?)
}
