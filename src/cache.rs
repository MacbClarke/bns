//! In-memory DNS response cache.
//!
//! Stores whole wire-format DNS responses (as bytes) in a W-TinyLFU cache keyed by:
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

use std::{collections::HashMap, hash::Hash, sync::Mutex};

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
    /// Exponentially-decayed hit counter used for adaptive stale windows.
    heat: f64,
    heat_updated_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct DnsCache {
    cfg: CacheConfig,
    inner: Mutex<WTinyLfuCache>,
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
    /// Number of entries scanned (starting from the requested offset).
    pub scanned: usize,
    /// Whether scanning stopped early due to `scan_limit`.
    pub truncated: bool,
    pub items: Vec<CacheEntryInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment {
    Window,
    Probation,
    Protected,
}

#[derive(Debug)]
struct WTinyLfuCache {
    entries: HashMap<CacheKey, CacheEntry>,
    segments: HashMap<CacheKey, Segment>,
    window: LruCache<CacheKey, ()>,
    probation: LruCache<CacheKey, ()>,
    protected: LruCache<CacheKey, ()>,
    window_cap: usize,
    probation_cap: usize,
    protected_cap: usize,
    sketch: TinyLfu,
}

impl WTinyLfuCache {
    fn new(max_entries: usize) -> Self {
        let max_entries = max_entries.max(1);
        let window_cap = ((max_entries as f64 * 0.01).round() as usize).clamp(1, max_entries);
        let main_cap = max_entries.saturating_sub(window_cap);
        let probation_cap = if main_cap == 0 {
            0
        } else {
            ((main_cap as f64 * 0.20).round() as usize).clamp(1, main_cap)
        };
        let protected_cap = main_cap.saturating_sub(probation_cap);

        Self {
            entries: HashMap::with_capacity(max_entries),
            segments: HashMap::with_capacity(max_entries),
            window: LruCache::unbounded(),
            probation: LruCache::unbounded(),
            protected: LruCache::unbounded(),
            window_cap,
            probation_cap,
            protected_cap,
            sketch: TinyLfu::new(max_entries),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get_mut(&mut self, key: &CacheKey) -> Option<&mut CacheEntry> {
        if !self.entries.contains_key(key) {
            return None;
        }
        self.sketch.increment(key);
        self.on_hit(key);
        self.entries.get_mut(key)
    }

    fn put(&mut self, key: CacheKey, entry: CacheEntry) {
        self.sketch.increment(&key);

        if self.entries.contains_key(&key) {
            self.entries.insert(key.clone(), entry);
            self.on_hit(&key);
            return;
        }

        self.entries.insert(key.clone(), entry);
        self.segments.insert(key.clone(), Segment::Window);
        self.window.put(key, ());
        self.evict_from_window();
    }

    fn heat_for_update(&self, key: &CacheKey, now: OffsetDateTime) -> (f64, OffsetDateTime) {
        self.entries
            .get(key)
            .map(|entry| (entry.heat, entry.heat_updated_at))
            .unwrap_or((0.0, now))
    }

    fn remove(&mut self, key: &CacheKey) -> Option<CacheEntry> {
        self.window.pop(key);
        self.probation.pop(key);
        self.protected.pop(key);
        self.segments.remove(key);
        self.entries.remove(key)
    }

    fn iter(&self) -> WTinyLfuIter<'_> {
        WTinyLfuIter {
            cache: self,
            segment_idx: 0,
            window: self.window.iter(),
            protected: self.protected.iter(),
            probation: self.probation.iter(),
        }
    }

    fn on_hit(&mut self, key: &CacheKey) {
        match self.segments.get(key).copied() {
            Some(Segment::Window) => {
                self.window.get(key);
            }
            Some(Segment::Protected) => {
                self.protected.get(key);
            }
            Some(Segment::Probation) => {
                self.promote_to_protected(key);
            }
            None => {}
        }
    }

    fn promote_to_protected(&mut self, key: &CacheKey) {
        if self.protected_cap == 0 {
            self.probation.get(key);
            return;
        }
        if self.probation.pop(key).is_none() {
            return;
        }
        self.segments.insert(key.clone(), Segment::Protected);
        self.protected.put(key.clone(), ());

        while self.protected.len() > self.protected_cap {
            let Some((demoted, ())) = self.protected.pop_lru() else {
                break;
            };
            self.segments.insert(demoted.clone(), Segment::Probation);
            self.probation.put(demoted, ());
        }
        self.trim_probation_to_capacity();
    }

    fn evict_from_window(&mut self) {
        while self.window.len() > self.window_cap {
            let Some((candidate, ())) = self.window.pop_lru() else {
                break;
            };
            self.segments.remove(&candidate);
            self.admit_to_main(candidate);
        }
    }

    fn admit_to_main(&mut self, candidate: CacheKey) {
        if self.probation_cap == 0 && self.protected_cap == 0 {
            self.entries.remove(&candidate);
            return;
        }

        if self.probation.len() < self.probation_cap {
            self.segments.insert(candidate.clone(), Segment::Probation);
            self.probation.put(candidate, ());
            return;
        }

        let Some(victim) = self.probation.peek_lru().map(|(k, _)| k.clone()) else {
            self.segments.insert(candidate.clone(), Segment::Probation);
            self.probation.put(candidate, ());
            self.trim_probation_to_capacity();
            return;
        };

        if self.sketch.estimate(&candidate) > self.sketch.estimate(&victim) {
            self.probation.pop(&victim);
            self.segments.remove(&victim);
            self.entries.remove(&victim);
            self.segments.insert(candidate.clone(), Segment::Probation);
            self.probation.put(candidate, ());
        } else {
            self.entries.remove(&candidate);
        }
    }

    fn trim_probation_to_capacity(&mut self) {
        while self.probation.len() > self.probation_cap {
            let Some((victim, ())) = self.probation.pop_lru() else {
                break;
            };
            self.segments.remove(&victim);
            self.entries.remove(&victim);
        }
    }
}

struct WTinyLfuIter<'a> {
    cache: &'a WTinyLfuCache,
    segment_idx: u8,
    window: lru::Iter<'a, CacheKey, ()>,
    protected: lru::Iter<'a, CacheKey, ()>,
    probation: lru::Iter<'a, CacheKey, ()>,
}

impl<'a> Iterator for WTinyLfuIter<'a> {
    type Item = (&'a CacheKey, &'a CacheEntry);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let next_key = match self.segment_idx {
                0 => self.window.next().map(|(k, _)| k),
                1 => self.protected.next().map(|(k, _)| k),
                2 => self.probation.next().map(|(k, _)| k),
                _ => return None,
            };

            if let Some(key) = next_key {
                if let Some(entry) = self.cache.entries.get(key) {
                    return Some((key, entry));
                }
            } else {
                self.segment_idx += 1;
            }
        }
    }
}

#[derive(Debug)]
struct TinyLfu {
    sketch: CountMinSketch,
    doorkeeper: Doorkeeper,
    sample_size: u64,
    samples: u64,
}

impl TinyLfu {
    fn new(capacity: usize) -> Self {
        Self {
            sketch: CountMinSketch::new(capacity),
            doorkeeper: Doorkeeper::new(capacity),
            sample_size: (capacity as u64).saturating_mul(10).max(100),
            samples: 0,
        }
    }

    fn increment(&mut self, key: &CacheKey) {
        self.samples = self.samples.saturating_add(1);
        if self.doorkeeper.contains(key) {
            self.sketch.increment(key);
        } else {
            self.doorkeeper.insert(key);
        }

        if self.samples >= self.sample_size {
            self.sketch.halve();
            self.doorkeeper.clear();
            self.samples /= 2;
        }
    }

    fn estimate(&self, key: &CacheKey) -> u8 {
        self.sketch.estimate(key) + u8::from(self.doorkeeper.contains(key))
    }
}

#[derive(Debug)]
struct CountMinSketch {
    width: usize,
    counters: Vec<u8>,
}

impl CountMinSketch {
    const DEPTH: usize = 4;

    fn new(capacity: usize) -> Self {
        let width = capacity.next_power_of_two().max(64);
        Self {
            width,
            counters: vec![0; width * Self::DEPTH],
        }
    }

    fn increment(&mut self, key: &CacheKey) {
        for row in 0..Self::DEPTH {
            let idx = self.index(key, row);
            self.counters[idx] = self.counters[idx].saturating_add(1).min(15);
        }
    }

    fn estimate(&self, key: &CacheKey) -> u8 {
        (0..Self::DEPTH)
            .map(|row| self.counters[self.index(key, row)])
            .min()
            .unwrap_or(0)
    }

    fn halve(&mut self) {
        for counter in &mut self.counters {
            *counter >>= 1;
        }
    }

    fn index(&self, key: &CacheKey, row: usize) -> usize {
        row * self.width + (hash_with_seed(key, SKETCH_SEEDS[row]) as usize & (self.width - 1))
    }
}

#[derive(Debug)]
struct Doorkeeper {
    bits: Vec<u64>,
    mask: usize,
}

impl Doorkeeper {
    fn new(capacity: usize) -> Self {
        let bit_count = (capacity.saturating_mul(8)).next_power_of_two().max(64);
        Self {
            bits: vec![0; bit_count / 64],
            mask: bit_count - 1,
        }
    }

    fn contains(&self, key: &CacheKey) -> bool {
        DOORKEEPER_SEEDS.iter().all(|seed| {
            let bit = hash_with_seed(key, *seed) as usize & self.mask;
            self.bits[bit / 64] & (1u64 << (bit % 64)) != 0
        })
    }

    fn insert(&mut self, key: &CacheKey) {
        for seed in DOORKEEPER_SEEDS {
            let bit = hash_with_seed(key, seed) as usize & self.mask;
            self.bits[bit / 64] |= 1u64 << (bit % 64);
        }
    }

    fn clear(&mut self) {
        self.bits.fill(0);
    }
}

const SKETCH_SEEDS: [u64; 4] = [
    0x9e37_79b9_7f4a_7c15,
    0xc2b2_ae3d_27d4_eb4f,
    0x1656_67b1_9e37_79f9,
    0x85eb_ca6b_c2b2_ae35,
];
const DOORKEEPER_SEEDS: [u64; 2] = [0x27d4_eb2f_1656_67c5, 0x94d0_49bb_1331_11eb];

fn hash_with_seed<T: Hash>(value: &T, seed: u64) -> u64 {
    use std::hash::Hasher;

    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write_u64(seed);
    value.hash(&mut h);
    h.finish()
}

impl DnsCache {
    /// Create a new cache with a fixed maximum entry count.
    pub fn new(cfg: CacheConfig) -> Self {
        let max_entries = cfg.max_entries.max(1);
        Self {
            cfg,
            inner: Mutex::new(WTinyLfuCache::new(max_entries)),
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
        let (expires_at, stale_until, response) = {
            let entry = cache.get_mut(key)?;
            let expires_at = entry.expires_at;
            let stale_until = entry.stale_until;
            if expires_at <= now {
                (expires_at, stale_until, None)
            } else {
                if self.cfg.stale_while_revalidate {
                    self.bump_heat_on_hit(entry, now);
                    let stale_age = self.stale_age_secs_for_heat(entry.heat);
                    entry.stale_until = entry.expires_at + Duration::seconds(stale_age as i64);
                }
                (expires_at, entry.stale_until, Some(entry.response.clone()))
            }
        };

        if expires_at <= now {
            // If SWR is disabled, or the stale window is over, evict immediately.
            if !self.cfg.stale_while_revalidate || stale_until <= now {
                cache.remove(key);
            }
            return None;
        }

        let response = response?;
        drop(cache);

        let remaining = expires_at - now;
        let remaining_secs: u32 = remaining.whole_seconds().try_into().unwrap_or(0).max(0);

        rewrite_response_id_and_ttl(&response, request_id, remaining_secs).ok()
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
        let (expires_at, stale_until, response) = {
            let entry = cache.get_mut(key)?;
            let expires_at = entry.expires_at;
            let stale_until = entry.stale_until;
            if expires_at > now {
                (expires_at, stale_until, None)
            } else if stale_until <= now {
                (expires_at, stale_until, None)
            } else {
                // Count stale hits toward hotness, but do not extend the current stale window.
                self.bump_heat_on_hit(entry, now);
                (expires_at, stale_until, Some(entry.response.clone()))
            }
        };
        if expires_at > now {
            return None;
        }
        if stale_until <= now {
            cache.remove(key);
            return None;
        }
        let response = response?;
        drop(cache);
        rewrite_response_id_and_ttl(&response, request_id, 0).ok()
    }

    /// Snapshot cache keys and entry metadata for inspection in the admin UI.
    ///
    /// This does not include response bytes, and it is safe to call even with a
    /// large cache, but it is still O(n) w.r.t. `offset + scanned` because we must
    /// iterate the W-TinyLFU segments to reach the requested page.
    ///
    /// When filters are enabled (e.g. hide expired or qname substring match), we may
    /// need to scan more than `limit` entries to collect `limit` results, so callers
    /// should keep `scan_limit` reasonably small to avoid blocking cache operations.
    pub fn snapshot(
        &self,
        offset: usize,
        limit: usize,
        scan_limit: usize,
        hide_expired: bool,
        qname_like: Option<&str>,
    ) -> CacheSnapshot {
        let now = OffsetDateTime::now_utc();
        let cache = self.inner.lock().unwrap();
        let total = cache.len();
        let mut items = Vec::with_capacity(limit.min(1000));
        let qname_like = qname_like
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let scan_limit = scan_limit.max(limit).max(1);
        let mut scanned = 0usize;
        let mut truncated = false;

        for (idx, (k, v)) in cache.iter().enumerate() {
            if idx < offset {
                continue;
            }
            if scanned >= scan_limit {
                truncated = true;
                break;
            }
            scanned += 1;

            let state = if v.expires_at > now {
                CacheEntryState::Fresh
            } else if self.cfg.stale_while_revalidate && v.stale_until > now {
                CacheEntryState::Stale
            } else {
                CacheEntryState::Expired
            };

            if hide_expired && matches!(state, CacheEntryState::Expired) {
                continue;
            }
            if let Some(substr) = qname_like.as_deref() {
                // qname in cache keys is normalized to lowercase + trailing dot.
                if !k.qname.contains(substr) {
                    continue;
                }
            }

            let expires_unix_ms: i64 = (v.expires_at.unix_timestamp_nanos() / 1_000_000)
                .try_into()
                .unwrap_or(i64::MAX);
            let stale_until_unix_ms: i64 = (v.stale_until.unix_timestamp_nanos() / 1_000_000)
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

            if items.len() >= limit {
                break;
            }
        }

        CacheSnapshot {
            total,
            scanned,
            truncated,
            items,
        }
    }

    /// Insert/replace a cache entry.
    ///
    /// The provided TTL is clamped to `[min_ttl, max_ttl]` (and forced to >= 1).
    /// If SWR is enabled, the stale window is derived from hit frequency, and
    /// bounded by `stale_min_age..=stale_max_age`.
    pub fn put(&self, key: CacheKey, response: &[u8], ttl_secs: u64) {
        let ttl_secs = ttl_secs.clamp(self.cfg.min_ttl, self.cfg.max_ttl).max(1);
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::seconds(ttl_secs as i64);

        let mut cache = self.inner.lock().unwrap();
        let (mut heat, mut heat_updated_at) = cache.heat_for_update(&key, now);
        heat = decay_heat(heat, heat_updated_at, now, self.cfg.stale_half_life_secs);
        heat_updated_at = now;

        let stale_age_secs = self.stale_age_secs_for_heat(heat);
        let stale_until = expires_at + Duration::seconds(stale_age_secs as i64);
        cache.put(
            key,
            CacheEntry {
                response: response.to_vec(),
                expires_at,
                stale_until,
                heat,
                heat_updated_at,
            },
        );
    }

    /// Negative caching TTL to apply when there is no positive answer TTL to use.
    pub fn negative_ttl(&self) -> u64 {
        self.cfg.negative_ttl
    }

    fn bump_heat_on_hit(&self, entry: &mut CacheEntry, now: OffsetDateTime) {
        entry.heat = decay_heat(
            entry.heat,
            entry.heat_updated_at,
            now,
            self.cfg.stale_half_life_secs,
        ) + 1.0;
        entry.heat_updated_at = now;
    }

    fn stale_age_secs_for_heat(&self, heat: f64) -> u64 {
        let max_age = self.cfg.stale_max_age;
        if max_age == 0 {
            return 0;
        }
        let min_age = self.cfg.stale_min_age.min(max_age);
        if max_age <= min_age {
            return max_age;
        }
        let k = self.cfg.stale_hotness_k.max(1) as f64;
        let h = heat.max(0.0);
        let frac = h / (h + k);
        let secs = min_age as f64 + (max_age - min_age) as f64 * frac;
        secs.round().clamp(min_age as f64, max_age as f64) as u64
    }
}

fn decay_heat(heat: f64, last: OffsetDateTime, now: OffsetDateTime, half_life_secs: u64) -> f64 {
    if heat <= 0.0 {
        return 0.0;
    }
    if half_life_secs == 0 {
        return 0.0;
    }
    let dt_secs: f64 = (now - last).whole_seconds().max(0) as f64;
    let hl: f64 = half_life_secs as f64;
    heat * 2f64.powf(-dt_secs / hl)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };
    use std::net::Ipv4Addr;

    fn key(name: &str) -> CacheKey {
        CacheKey {
            qname: name.to_string(),
            qtype: RecordType::A.into(),
        }
    }

    fn response(id: u16, ttl: u32, octet: u8) -> Vec<u8> {
        let name = Name::from_ascii("example.com.").unwrap();
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, octet))),
        ));
        msg.to_vec().unwrap()
    }

    fn cfg(max_entries: usize) -> CacheConfig {
        CacheConfig {
            max_entries,
            min_ttl: 1,
            max_ttl: 86_400,
            negative_ttl: 60,
            stale_while_revalidate: false,
            stale_max_age: 60,
            stale_min_age: 0,
            stale_half_life_secs: 300,
            stale_hotness_k: 10,
        }
    }

    #[test]
    fn cache_hit_rewrites_id_and_remaining_ttl() {
        let cache = DnsCache::new(cfg(16));
        cache.put(key("example.com."), &response(7, 120, 1), 120);

        let hit = cache.get(&key("example.com."), 99).unwrap();
        let msg = Message::from_vec(&hit).unwrap();

        assert_eq!(msg.id(), 99);
        assert!((1..=120).contains(&msg.answers()[0].ttl()));
    }

    #[test]
    fn capacity_never_exceeds_max_entries() {
        let cache = DnsCache::new(cfg(8));
        for i in 0..100 {
            cache.put(key(&format!("cold-{i}.example.")), &response(i, 60, 1), 60);
        }

        assert!(cache.inner.lock().unwrap().len() <= 8);
    }

    #[test]
    fn scan_workload_keeps_hot_key() {
        let cache = DnsCache::new(cfg(8));
        let hot = key("hot.example.");
        cache.put(hot.clone(), &response(1, 60, 1), 60);

        for _ in 0..20 {
            assert!(cache.get(&hot, 2).is_some());
        }
        cache.put(key("warmup.example."), &response(9, 60, 2), 60);
        assert!(cache.get(&hot, 2).is_some());

        for i in 0..40 {
            cache.put(key(&format!("scan-{i}.example.")), &response(i, 60, 2), 60);
        }

        assert!(cache.get(&hot, 3).is_some());
        assert!(cache.inner.lock().unwrap().len() <= 8);
    }

    #[test]
    fn probation_hit_promotes_key_to_protected() {
        let cache = DnsCache::new(cfg(8));
        let promoted = key("promoted.example.");
        cache.put(promoted.clone(), &response(1, 60, 1), 60);
        cache.put(key("window-overflow.example."), &response(2, 60, 2), 60);

        assert!(cache.get(&promoted, 3).is_some());

        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.segments.get(&promoted), Some(&Segment::Protected));
    }

    #[test]
    fn updating_existing_key_preserves_segment() {
        let cache = DnsCache::new(cfg(8));
        let promoted = key("refresh.example.");
        cache.put(promoted.clone(), &response(1, 60, 1), 60);
        cache.put(key("window-overflow.example."), &response(2, 60, 2), 60);
        assert!(cache.get(&promoted, 3).is_some());

        cache.put(promoted.clone(), &response(4, 60, 3), 60);

        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.segments.get(&promoted), Some(&Segment::Protected));
    }

    #[test]
    fn expired_entry_misses_and_is_removed_without_swr() {
        let cache = DnsCache::new(cfg(4));
        let k = key("expired.example.");
        cache.put(k.clone(), &response(1, 60, 1), 60);

        {
            let mut inner = cache.inner.lock().unwrap();
            let entry = inner.entries.get_mut(&k).unwrap();
            entry.expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
            entry.stale_until = entry.expires_at;
        }

        assert!(cache.get(&k, 2).is_none());
        assert!(!cache.inner.lock().unwrap().entries.contains_key(&k));
    }

    #[test]
    fn stale_entry_returns_ttl_zero_when_swr_enabled() {
        let mut config = cfg(4);
        config.stale_while_revalidate = true;
        config.stale_max_age = 60;
        config.stale_min_age = 60;
        let cache = DnsCache::new(config);
        let k = key("stale.example.");
        cache.put(k.clone(), &response(1, 60, 1), 60);

        {
            let mut inner = cache.inner.lock().unwrap();
            let entry = inner.entries.get_mut(&k).unwrap();
            entry.expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
            entry.stale_until = OffsetDateTime::now_utc() + Duration::seconds(60);
        }

        let hit = cache.get_stale(&k, 2).unwrap();
        let msg = Message::from_vec(&hit).unwrap();

        assert_eq!(msg.id(), 2);
        assert_eq!(msg.answers()[0].ttl(), 0);
    }
}
