//! Singleflight-style de-duplication for concurrent async work.
//!
//! This is used to collapse concurrent cold-cache DNS queries into a single
//! upstream request:
//! - First caller becomes the "leader" and performs the work.
//! - Other callers "join" and await the leader's result.
//!
//! Implementation notes:
//! - We use a per-key `watch` channel to publish completion. `watch` is used
//!   specifically because it is level-triggered: late subscribers will still
//!   observe the last value and will not miss the completion signal.
//! - This avoids subtle missed-wakeup issues that can occur with `Notify`
//!   when waiters subscribe after a notification is fired.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::{Mutex, watch};

#[derive(Debug)]
struct State<T> {
    tx: watch::Sender<Option<Result<T, String>>>,
}

/// De-duplicate concurrent computations keyed by `K`.
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
    /// - The leader executes `f()`, broadcasts the result via `watch`, removes the key,
    ///   and returns the result.
    /// - Waiters subscribe to the `watch` channel and return the published result.
    pub async fn run_or_join<F, Fut>(&self, key: K, f: F) -> anyhow::Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        // Fast path: is there already a leader?
        let existing = {
            let map = self.inner.lock().await;
            map.get(&key).cloned()
        };
        if let Some(state) = existing {
            return join_state(state).await;
        }

        // Try to become leader.
        let (tx, _rx) = watch::channel::<Option<Result<T, String>>>(None);
        let state = Arc::new(State { tx });

        let became_leader = {
            let mut map = self.inner.lock().await;
            if let Some(existing) = map.get(&key) {
                // Lost the race; join the existing leader.
                Some(existing.clone())
            } else {
                map.insert(key.clone(), state.clone());
                None
            }
        };
        if let Some(existing) = became_leader {
            return join_state(existing).await;
        }

        // Leader executes and publishes.
        let res = f().await.map_err(|e| e.to_string());
        let _ = state.tx.send(Some(res.clone()));

        let mut map = self.inner.lock().await;
        map.remove(&key);
        drop(map);

        res.map_err(|e| anyhow::anyhow!(e))
    }

    /// Start `f` only if no in-flight exists; otherwise return immediately.
    ///
    /// This is used for stale-while-revalidate background refresh: if a refresh
    /// is already running for the key, we do nothing.
    pub async fn run_if_absent<F, Fut>(&self, key: K, f: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        let (tx, _rx) = watch::channel::<Option<Result<T, String>>>(None);
        let state = Arc::new(State { tx });

        let should_run = {
            let mut map = self.inner.lock().await;
            if map.contains_key(&key) {
                false
            } else {
                map.insert(key.clone(), state.clone());
                true
            }
        };

        if !should_run {
            return;
        }

        let res = f().await.map_err(|e| e.to_string());
        let _ = state.tx.send(Some(res));

        let mut map = self.inner.lock().await;
        map.remove(&key);
    }
}

async fn join_state<T: Clone>(state: Arc<State<T>>) -> anyhow::Result<T> {
    let mut rx = state.tx.subscribe();
    loop {
        if let Some(res) = rx.borrow().clone() {
            return res.map_err(|e| anyhow::anyhow!(e));
        }
        rx.changed()
            .await
            .map_err(|_| anyhow::anyhow!("inflight channel closed"))?;
    }
}

