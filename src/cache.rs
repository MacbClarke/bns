use std::sync::Mutex;

use hickory_proto::op::Message;
use lru::LruCache;
use time::{Duration, OffsetDateTime};

use crate::config::CacheConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct DnsCache {
    cfg: CacheConfig,
    inner: Mutex<LruCache<CacheKey, CacheEntry>>,
}

impl DnsCache {
    pub fn new(cfg: CacheConfig) -> Self {
        let cap = std::num::NonZeroUsize::new(cfg.max_entries.max(1)).unwrap();
        Self {
            cfg,
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn get(&self, key: &CacheKey, request_id: u16) -> Option<Vec<u8>> {
        let now = OffsetDateTime::now_utc();
        let mut cache = self.inner.lock().unwrap();
        let entry = cache.get(key)?.clone();
        if entry.expires_at <= now {
            cache.pop(key);
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

    pub fn put(&self, key: CacheKey, response: &[u8], ttl_secs: u64) {
        let ttl_secs = ttl_secs
            .clamp(self.cfg.min_ttl, self.cfg.max_ttl)
            .max(1);
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(ttl_secs as i64);

        let mut cache = self.inner.lock().unwrap();
        cache.put(
            key,
            CacheEntry {
                response: response.to_vec(),
                expires_at,
            },
        );
    }

    pub fn negative_ttl(&self) -> u64 {
        self.cfg.negative_ttl
    }
}

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

