//! Small helpers for cooperative shutdown signals.
//!
//! We use a `watch<bool>` channel where `true` means "shutdown requested".

use tokio::sync::watch;

/// Create a new shutdown channel. Initial value is `false` (running).
pub fn channel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

/// Await until shutdown is requested.
///
/// This returns immediately if the receiver already observed `true`.
pub async fn wait(mut rx: watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
}
