mod cache;
mod config;
mod dns;
mod rules;
mod shutdown;
mod store;
mod web;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use tracing::{error, info};

fn config_path_from_args() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(p) = args.next() {
                return PathBuf::from(p);
            }
        }
    }
    std::env::var_os("BNS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.yaml"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config_path = config_path_from_args();
    let config = config::Config::load(&config_path)?;

    let store = Arc::new(store::Store::open(&config.storage.path)?);
    store.init_schema()?;
    store.maybe_bootstrap_rules(&config.bootstrap_rules)?;

    let rules = Arc::new(rules::RuleSet::load_from_store(store.clone())?);
    let cache = Arc::new(cache::DnsCache::new(config.cache.clone()));

    let dns_bind: SocketAddr = config.listen.addr;
    let admin_bind: SocketAddr = config.admin.addr;

    let (shutdown_tx, shutdown_rx) = shutdown::channel();

    let dns_server = dns::DnsServer::new(dns::DnsServerDeps {
        config: config.clone(),
        cache: cache.clone(),
        rules: rules.clone(),
        store: store.clone(),
    });

    let web_server = web::WebServer::new(web::WebServerDeps {
        admin: config.admin.clone(),
        retention_days: config.storage.retention_days,
        store: store.clone(),
        rules: rules.clone(),
    });

    info!(dns_bind = %dns_bind, "starting dns server");
    info!(admin_bind = %admin_bind, "starting admin web server");

    let mut dns_task = tokio::spawn({
        let shutdown_rx = shutdown_rx.clone();
        async move { dns_server.run(shutdown_rx).await }
    });
    let mut web_task = tokio::spawn({
        let shutdown_rx = shutdown_rx.clone();
        async move { web_server.run(shutdown_rx).await }
    });

    let mut dns_res: Option<Result<anyhow::Result<()>, tokio::task::JoinError>> = None;
    let mut web_res: Option<Result<anyhow::Result<()>, tokio::task::JoinError>> = None;

    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            info!("shutdown requested");
            let _ = shutdown_tx.send(true);
        }
        res = (&mut dns_task) => {
            let _ = shutdown_tx.send(true);
            dns_res = Some(res);
        }
        res = (&mut web_task) => {
            let _ = shutdown_tx.send(true);
            web_res = Some(res);
        }
    }

    if dns_res.is_none() {
        dns_res = Some(dns_task.await);
    }
    if web_res.is_none() {
        web_res = Some(web_task.await);
    }

    if let Some(Err(join_err)) = dns_res {
        error!(error = %join_err, "dns task join error");
    } else if let Some(Ok(Err(run_err))) = dns_res {
        error!(error = %run_err, "dns server error");
    }

    if let Some(Err(join_err)) = web_res {
        error!(error = %join_err, "web task join error");
    } else if let Some(Ok(Err(run_err))) = web_res {
        error!(error = %run_err, "web server error");
    }

    Ok(())
}

async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}
