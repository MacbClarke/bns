//! Singleflight-style de-duplication for concurrent async work.
//!
//! Motivation:
//! - When many identical DNS queries arrive at the same time and the cache is cold,
//!   we want to avoid sending N identical requests to the upstream resolver.
//! - Instead, we run one upstream fetch per key and let other callers await the
//!   same result.
//!
//! This implementation stores a per-key shared state containing:
//! - a `Notify` to wake waiters once the result is ready,
//! - a `result` slot populated by the first caller that "wins" the race.
//!
//! Note: errors are stored as strings to keep the shared state `Clone`-friendly.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::{Mutex, Notify};

#[derive(Debug)]
struct State<T> {
    notify: Notify,
    result: Mutex<Option<Result<T, String>>>,
}

/// De-duplicate concurrent computations keyed by `K`.
///
/// Typical use: `run_or_join(key, || async { ... })`.
#[derive(Debug)]
pub struct InFlight<K, T> {
    inner: Mutex<HashMap<K, Arc<State<T>>>>,
}

impl<K, T> InFlight<K, T>
where
    K: std::hash::Hash + Eq + Clone,
    T: Clone,
{
    /// Create an empty in-flight map.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Run `f` once per key; concurrent callers await the same result.
    ///
    /// Detailed behavior:
    /// - The first caller to insert `key` into the internal map becomes the "leader".
    /// - The leader executes `f()`, stores the result, removes the key from the map,
    ///   and notifies all waiters.
    /// - Waiters simply await the leader's notification and then clone the stored
    ///   result.
    ///
    /// Guarantees:
    /// - At most one `f()` runs at a time per key.
    /// - After completion, the key is removed to avoid unbounded growth.
    ///
    /// Caveat:
    /// - If the leader task is cancelled/panics before it stores a result, waiters
    ///   could block. In this codebase, the leader is awaited within the DNS handler
    ///   flow, so this is not expected in normal operation.
    pub async fn run_or_join<F, Fut>(&self, key: K, f: F) -> anyhow::Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        let state = {
            let mut map = self.inner.lock().await;
            if let Some(s) = map.get(&key) {
                s.clone()
            } else {
                let s = Arc::new(State {
                    notify: Notify::new(),
                    result: Mutex::new(None),
                });
                map.insert(key.clone(), s.clone());
                drop(map);

                let res = f().await.map_err(|e| e.to_string());
                *s.result.lock().await = Some(res);

                let mut map = self.inner.lock().await;
                map.remove(&key);
                drop(map);

                s.notify.notify_waiters();
                return s
                    .result
                    .lock()
                    .await
                    .clone()
                    .unwrap_or_else(|| Err("inflight missing result".into()))
                    .map_err(|e| anyhow::anyhow!(e));
            }
        };

        state.notify.notified().await;
        state
            .result
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| Err("inflight missing result".into()))
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Start `f` only if no in-flight exists; if one exists, returns immediately.
    ///
    /// This is used for stale-while-revalidate:
    /// - If a refresh is already running for a key, do nothing.
    /// - Otherwise, kick off the refresh once.
    pub async fn run_if_absent<F, Fut>(&self, key: K, f: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        let should_run = {
            let mut map = self.inner.lock().await;
            if map.contains_key(&key) {
                false
            } else {
                let s = Arc::new(State {
                    notify: Notify::new(),
                    result: Mutex::new(None),
                });
                map.insert(key.clone(), s);
                true
            }
        };

        if !should_run {
            return;
        }

        let _ = self.run_or_join(key, f).await;
    }
}
