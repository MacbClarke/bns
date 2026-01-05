//! DNS server implementation (UDP + TCP) with:
//! - forwarding to upstream resolvers,
//! - in-memory caching,
//! - rule-based local answers (A/AAAA/CNAME),
//! - query logging (async to SQLite),
//! - singleflight to de-duplicate concurrent upstream fetches,
//! - optional stale-while-revalidate for expired cache entries.
//!
//! Design notes:
//! - The hot path (`handle_query`) is fully async; the only blocking work
//!   (SQLite writes) is pushed onto a background channel + `spawn_blocking`.
//! - Cache keys are `(qname_normalized, qtype)` and do not include EDNS/ECS/etc.
//! - Singleflight ensures that when the cache is cold, N concurrent identical
//!   queries produce only one upstream request; the rest await the shared result.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, RecordType},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, watch},
    time::{timeout, Duration, Instant},
};
use tracing::{debug, warn};

use crate::{
    cache::{CacheKey, DnsCache},
    config::{Config, UpstreamPolicy},
    inflight::InFlight,
    rules::{RuleAnswer, RuleSet, RuleType},
    store::{QueryLogEntry, Store},
};

/// Dependencies shared by all DNS handlers.
///
/// This is passed into each UDP packet task / TCP connection task and cloned
/// (cheaply) using `Arc` references.
pub struct DnsServerDeps {
    pub config: Config,
    pub cache: Arc<DnsCache>,
    pub rules: Arc<RuleSet>,
    pub store: Arc<Store>,
    pub(crate) inflight: Arc<InFlight<CacheKey, Arc<UpstreamResult>>>,
}

/// DNS server entrypoint: binds UDP/TCP sockets and spawns request handlers.
pub struct DnsServer {
    deps: DnsServerDeps,
    /// Counter used to choose upstream in round-robin mode.
    rr_counter: Arc<AtomicUsize>,
}

impl DnsServer {
    /// Create a new DNS server instance.
    pub fn new(deps: DnsServerDeps) -> Self {
        Self {
            deps,
            rr_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Run the server until shutdown is requested.
    ///
    /// This spawns:
    /// - one UDP receive loop (if enabled),
    /// - one TCP accept loop (if enabled),
    /// - one background log worker.
    ///
    /// Each UDP packet is handled in its own task; each TCP connection is
    /// handled in its own task.
    pub async fn run(self, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let (log_tx, log_rx) = mpsc::channel::<LogEvent>(50_000);
        self.spawn_log_worker(log_rx, shutdown.clone());

        let mut tasks = Vec::new();

        if self.deps.config.listen.udp {
            let udp = Arc::new(UdpSocket::bind(self.deps.config.listen.addr).await?);
            tasks.push(tokio::spawn(run_udp(
                udp,
                self.deps.clone(),
                log_tx.clone(),
                self.rr_counter.clone(),
                shutdown.clone(),
            )));
        }

        if self.deps.config.listen.tcp {
            let tcp = TcpListener::bind(self.deps.config.listen.addr).await?;
            tasks.push(tokio::spawn(run_tcp(
                tcp,
                self.deps.clone(),
                log_tx.clone(),
                self.rr_counter.clone(),
                shutdown.clone(),
            )));
        }

        for t in tasks {
            let _ = t.await?;
        }
        Ok(())
    }

    /// Spawn a background worker that writes query logs to SQLite.
    ///
    /// Important:
    /// - Request handlers only do a `try_send` into the channel. If the channel
    ///   is full, the log entry is dropped (to avoid impacting DNS latency).
    /// - SQLite work runs in `spawn_blocking` to keep the async runtime responsive.
    /// - Cleanup (retention) is executed at most once per hour.
    fn spawn_log_worker(
        &self,
        mut log_rx: mpsc::Receiver<LogEvent>,
        shutdown: watch::Receiver<bool>,
    ) {
        let store = self.deps.store.clone();
        let retention_days = self.deps.config.storage.retention_days;
        tokio::spawn(async move {
            let mut last_cleanup = Instant::now();
            let shutdown = shutdown;
            loop {
                tokio::select! {
                    _ = crate::shutdown::wait(shutdown.clone()) => break,
                    ev = log_rx.recv() => {
                        let Some(ev) = ev else { break };
                        let store_for_insert = store.clone();
                        tokio::task::spawn_blocking(move || store_for_insert.insert_query_log(ev.as_entry()))
                            .await
                            .ok();

                        if last_cleanup.elapsed() > Duration::from_secs(3600) {
                            last_cleanup = Instant::now();
                            let store_for_cleanup = store.clone();
                            tokio::task::spawn_blocking(move || store_for_cleanup.cleanup_query_logs(retention_days))
                                .await
                                .ok();
                        }
                    }
                }
            }
        });
    }
}

impl Clone for DnsServerDeps {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cache: self.cache.clone(),
            rules: self.rules.clone(),
            store: self.store.clone(),
            inflight: self.inflight.clone(),
        }
    }
}

/// UDP receive loop.
///
/// Reads datagrams, then spawns a per-packet task that:
/// - parses the query,
/// - answers from rules / cache / upstream,
/// - sends the response back to the client.
async fn run_udp(
    socket: Arc<UdpSocket>,
    deps: DnsServerDeps,
    log_tx: mpsc::Sender<LogEvent>,
    rr_counter: Arc<AtomicUsize>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65_535];
    let shutdown = shutdown;
    loop {
        let (n, peer) = tokio::select! {
            _ = crate::shutdown::wait(shutdown.clone()) => break,
            res = socket.recv_from(&mut buf) => res?,
        };
        let packet = buf[..n].to_vec();
        let socket = socket.clone();
        let deps = deps.clone();
        let log_tx = log_tx.clone();
        let rr_counter = rr_counter.clone();
        tokio::spawn(async move {
            if let Some(resp) =
                handle_query(packet, peer, "udp", deps, log_tx, rr_counter).await
            {
                let _ = socket.send_to(&resp, peer).await;
            }
        });
    }
    Ok(())
}

/// TCP accept loop.
///
/// Accepts connections and spawns a per-connection task. The connection task
/// reads length-prefixed DNS messages and answers them sequentially.
async fn run_tcp(
    listener: TcpListener,
    deps: DnsServerDeps,
    log_tx: mpsc::Sender<LogEvent>,
    rr_counter: Arc<AtomicUsize>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let shutdown = shutdown;
    loop {
        let (stream, peer) = tokio::select! {
            _ = crate::shutdown::wait(shutdown.clone()) => break,
            res = listener.accept() => res?,
        };
        let deps = deps.clone();
        let log_tx = log_tx.clone();
        let rr_counter = rr_counter.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_tcp_client(stream, peer, deps, log_tx, rr_counter).await
            {
                debug!(error = %e, "tcp client error");
            }
        });
    }
    Ok(())
}

/// Handle a single TCP client connection (multiple DNS messages).
///
/// DNS-over-TCP uses a 2-byte length prefix. We keep reading messages until
/// EOF or parse/read error.
async fn handle_tcp_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    deps: DnsServerDeps,
    log_tx: mpsc::Sender<LogEvent>,
    rr_counter: Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; len];
        stream.read_exact(&mut msg_buf).await?;

        if let Some(resp) =
            handle_query(msg_buf, peer, "tcp", deps.clone(), log_tx.clone(), rr_counter.clone())
                .await
        {
            let resp_len: u16 = resp.len().try_into().unwrap_or(u16::MAX);
            stream.write_all(&resp_len.to_be_bytes()).await?;
            stream.write_all(&resp[..resp_len as usize]).await?;
        } else {
            return Ok(());
        }
    }
}

/// Handle one DNS query message and produce a wire-format response.
///
/// Core behavior:
/// 1) Parse request and extract `(qname, qtype)`.
/// 2) If a local rule matches, synthesize a response (no caching).
/// 3) Else, try cache (fresh hit).
/// 4) Else, if SWR is enabled, try "stale" cache; if present, return it
///    immediately and refresh the cache in background.
/// 5) Else, perform an upstream fetch. This is protected by `inflight` to
///    de-duplicate concurrent cache misses for the same key.
///
/// Notes:
/// - Cache hits rewrite the response ID and TTLs.
/// - Upstream results are shared across waiting callers; each caller rewrites
///   the response ID to match its request.
async fn handle_query(
    packet: Vec<u8>,
    peer: SocketAddr,
    transport: &'static str,
    deps: DnsServerDeps,
    log_tx: mpsc::Sender<LogEvent>,
    rr_counter: Arc<AtomicUsize>,
) -> Option<Vec<u8>> {
    let start = Instant::now();
    let client_ip = match peer.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    };

    let req = match Message::from_vec(&packet) {
        Ok(m) => m,
        Err(_) => return None,
    };
    let id = req.id();
    let Some(query) = req.queries().first() else {
        return None;
    };
    let qname = query.name().to_utf8();
    let qtype = query.query_type();

    let mut cache_hit = false;
    let mut rule_hit = false;
    let mut upstream_used: Option<String> = None;

    let response = if let Some((_rule_id, ans)) = rule_match(&deps.rules, &qname, qtype) {
        rule_hit = true;
        build_rule_response(&req, ans).ok()
    } else {
        let key = CacheKey {
            qname: crate::rules::normalize_name(&qname),
            qtype: qtype.into(),
        };

        if let Some(cached) = deps.cache.get(&key, id) {
            cache_hit = true;
            Some(cached)
        } else if let Some(stale) = deps.cache.get_stale(&key, id) {
            cache_hit = true;
            // refresh in background (singleflight de-dupes)
            let deps2 = deps.clone();
            let inflight2 = deps2.inflight.clone();
            let key2 = key.clone();
            let packet2 = packet.clone();
            let rr_counter2 = rr_counter.clone();
            tokio::spawn(async move {
                inflight2
                    .run_if_absent(key2.clone(), || async move {
                        fetch_and_cache(&deps2, key2, transport, packet2, rr_counter2).await
                    })
                    .await;
            });
            Some(stale)
        } else {
            match deps
                .inflight
                .run_or_join(key.clone(), || async {
                    fetch_and_cache(&deps, key, transport, packet.clone(), rr_counter.clone()).await
                })
                .await
            {
                Ok(res) => {
                    upstream_used = Some(res.upstream.clone());
                    rewrite_response_id(res.response.as_slice(), id).ok()
                }
                Err(_) => None,
            }
        }
    }?;

    let latency_ms: i64 = start.elapsed().as_millis().try_into().unwrap_or(i64::MAX);
    let now = OffsetDateTime::now_utc();
    let ts = now.format(&Rfc3339).ok();
    let ts_unix_ms: i64 = (now.unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .unwrap_or(i64::MAX);
    if let (Some(ts), Ok(msg)) = (ts, Message::from_vec(&response)) {
        let rcode = format!("{:?}", msg.response_code());
        let answers_json = summarize_answers_json(&msg).ok();
        let ev = LogEvent {
            ts,
            ts_unix_ms,
            client_ip,
            transport,
            qname: crate::rules::normalize_name(&qname),
            qtype: format!("{:?}", qtype),
            rcode,
            latency_ms,
            cache_hit,
            rule_hit,
            upstream: upstream_used,
            answers_json,
        };
        let _ = log_tx.try_send(ev);
    }

    Some(response)
}

/// Result of a single upstream fetch, shared across concurrent waiters.
///
/// `response` is the raw wire message received from upstream. Callers must
/// rewrite the DNS ID for their own request before sending it to clients.
#[derive(Debug, Clone)]
pub(crate) struct UpstreamResult {
    upstream: String,
    response: Arc<Vec<u8>>,
}

/// Fetch from upstream and populate cache (if eligible).
///
/// - Uses configured upstream policy (failover/round-robin/random).
/// - Parses the response to compute TTL for caching.
/// - `SERVFAIL` is intentionally *not* cached (to avoid extending transient failures).
///
/// Returned value is an `Arc` so multiple callers (singleflight waiters) can
/// cheaply share the same bytes.
async fn fetch_and_cache(
    deps: &DnsServerDeps,
    key: CacheKey,
    transport: &'static str,
    packet: Vec<u8>,
    rr_counter: Arc<AtomicUsize>,
) -> anyhow::Result<Arc<UpstreamResult>> {
    let (upstream, resp) =
        forward_to_upstream(deps, transport, &packet, rr_counter.as_ref()).await
            .ok_or_else(|| anyhow::anyhow!("upstream failed"))?;

    if let Ok(msg) = Message::from_vec(&resp) {
        if msg.response_code() != ResponseCode::ServFail {
            let ttl = ttl_for_cache(&deps.cache, &msg);
            deps.cache.put(key, &resp, ttl);
        }
    }

    Ok(Arc::new(UpstreamResult {
        upstream,
        response: Arc::new(resp),
    }))
}

/// Rewrite the DNS ID of a wire response.
///
/// This is required when a cached or shared upstream response is reused for a
/// different request: DNS uses the message ID to match responses to requests.
fn rewrite_response_id(response: &[u8], request_id: u16) -> anyhow::Result<Vec<u8>> {
    let mut msg = Message::from_vec(response)?;
    msg.set_id(request_id);
    Ok(msg.to_vec()?)
}

/// Map a DNS question into the internal rule type.
///
/// We only support rules for A/AAAA/CNAME. All other qtypes return `None`,
/// which means "no local rule match possible, continue with cache/upstream".
fn rule_match(rules: &RuleSet, qname: &str, qtype: RecordType) -> Option<(i64, RuleAnswer)> {
    let rt = match qtype {
        RecordType::A => RuleType::A,
        RecordType::AAAA => RuleType::AAAA,
        RecordType::CNAME => RuleType::CNAME,
        _ => return None,
    };
    rules.find_answer(qname, rt)
}

/// Build a synthetic DNS response from a local rule answer.
///
/// Important details:
/// - Sets QR=Response, Opcode=Query.
/// - Marks recursion available (RA=true) to behave like a normal resolver.
/// - Copies the original question section.
/// - Adds exactly one answer record.
fn build_rule_response(req: &Message, ans: RuleAnswer) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_available(true);
    resp.set_recursion_desired(req.recursion_desired());
    resp.set_response_code(ResponseCode::NoError);

    if let Some(q) = req.queries().first() {
        resp.add_query(q.clone());
        let name = q.name().clone();
        let record = match ans {
            RuleAnswer::A { addr, ttl } => Record::from_rdata(
                name,
                ttl,
                RData::A(hickory_proto::rr::rdata::A(addr)),
            ),
            RuleAnswer::AAAA { addr, ttl } => Record::from_rdata(
                name,
                ttl,
                RData::AAAA(hickory_proto::rr::rdata::AAAA(addr)),
            ),
            RuleAnswer::CNAME { name: cname, ttl } => {
                let cname = Name::from_utf8(&cname)?;
                Record::from_rdata(
                    name,
                    ttl,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(cname)),
                )
            }
        };
        resp.add_answer(record);
    }

    Ok(resp.to_vec()?)
}

/// Try upstream resolvers in configured order and return the first success.
///
/// Selection behavior:
/// - `failover`: start from the first upstream and try sequentially.
/// - `round_robin`: choose a rotating start index to spread load.
/// - `random`: choose a pseudo-random start index.
///
/// Reliability behavior:
/// - Each attempt is bounded by `timeout_ms`.
/// - On error, tries the next upstream.
async fn forward_to_upstream(
    deps: &DnsServerDeps,
    transport: &'static str,
    packet: &[u8],
    rr_counter: &AtomicUsize,
) -> Option<(String, Vec<u8>)> {
    let upstreams = &deps.config.upstreams;
    if upstreams.is_empty() {
        return None;
    }
    let timeout_dur = Duration::from_millis(deps.config.timeout_ms);

    let start_idx = match deps.config.upstream_policy {
        UpstreamPolicy::Failover => 0,
        UpstreamPolicy::RoundRobin => rr_counter.fetch_add(1, Ordering::Relaxed) % upstreams.len(),
        UpstreamPolicy::Random => {
            let n = OffsetDateTime::now_utc().unix_timestamp_nanos() as usize;
            n % upstreams.len()
        }
    };

    for i in 0..upstreams.len() {
        let idx = (start_idx + i) % upstreams.len();
        let upstream = upstreams[idx];
        let upstream_str = upstream.to_string();
        let res = match transport {
            "tcp" => {
                timeout(timeout_dur, forward_tcp(upstream, packet)).await.ok()?
            }
            _ => timeout(timeout_dur, forward_udp(upstream, packet)).await.ok()?,
        };
        match res {
            Ok(resp) => return Some((upstream_str, resp)),
            Err(e) => {
                warn!(upstream = %upstream_str, error = %e, "upstream failed");
                continue;
            }
        }
    }
    None
}

/// Forward a DNS query to an upstream over UDP and read the response.
async fn forward_udp(upstream: SocketAddr, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(packet, upstream).await?;

    let mut buf = vec![0u8; 65_535];
    let (n, _) = socket.recv_from(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Forward a DNS query to an upstream over TCP and read the response.
///
/// DNS-over-TCP uses a 2-byte big-endian length prefix.
async fn forward_tcp(upstream: SocketAddr, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(upstream).await?;
    let len: u16 = packet.len().try_into().unwrap_or(u16::MAX);
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&packet[..len as usize]).await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

/// Derive a cache TTL (seconds) from an upstream response.
///
/// Current policy:
/// - If rcode is `NOERROR` or `NXDOMAIN`:
///   - If there are answers, take the minimum TTL across the answer section.
///   - If there are no answers, treat as negative caching and use `negative_ttl`.
/// - For other rcodes (SERVFAIL, REFUSED, etc.): use `negative_ttl`.
///
/// Note that `SERVFAIL` is later filtered to *not* be cached at all.
fn ttl_for_cache(cache: &DnsCache, msg: &Message) -> u64 {
    let rcode = msg.response_code();
    if rcode != ResponseCode::NoError && rcode != ResponseCode::NXDomain {
        return cache.negative_ttl();
    }

    let mut min: Option<u32> = None;
    for r in msg.answers() {
        min = Some(match min {
            Some(m) => m.min(r.ttl()),
            None => r.ttl(),
        });
    }
    if let Some(m) = min {
        (m as u64).max(1)
    } else {
        cache.negative_ttl()
    }
}

/// Create a small JSON representation of the answer section for UI/logging.
///
/// Only A/AAAA/CNAME are included; other RR types are ignored.
fn summarize_answers_json(msg: &Message) -> anyhow::Result<String> {
    #[derive(serde::Serialize)]
    struct Answer {
        rr_type: String,
        value: String,
        ttl: u32,
    }
    let mut out = Vec::new();
    for r in msg.answers() {
        let ttl = r.ttl();
        match r.data() {
            RData::A(a) => out.push(Answer {
                rr_type: "A".into(),
                value: a.0.to_string(),
                ttl,
            }),
            RData::AAAA(a) => out.push(Answer {
                rr_type: "AAAA".into(),
                value: a.0.to_string(),
                ttl,
            }),
            RData::CNAME(c) => out.push(Answer {
                rr_type: "CNAME".into(),
                value: c.to_utf8(),
                ttl,
            }),
            _ => {}
        }
    }
    Ok(serde_json::to_string(&out)?)
}

/// A single query log event sent from the request path to the background log worker.
///
/// The `ts_unix_ms` field is used for stable numeric range filtering.
struct LogEvent {
    ts: String,
    ts_unix_ms: i64,
    client_ip: String,
    transport: &'static str,
    qname: String,
    qtype: String,
    rcode: String,
    latency_ms: i64,
    cache_hit: bool,
    rule_hit: bool,
    upstream: Option<String>,
    answers_json: Option<String>,
}

impl LogEvent {
    /// Convert to the SQLite insertion struct (borrowed fields).
    fn as_entry(&self) -> QueryLogEntry<'_> {
        QueryLogEntry {
            ts: &self.ts,
            ts_unix_ms: self.ts_unix_ms,
            client_ip: &self.client_ip,
            transport: self.transport,
            qname: &self.qname,
            qtype: &self.qtype,
            rcode: &self.rcode,
            latency_ms: self.latency_ms,
            cache_hit: self.cache_hit,
            rule_hit: self.rule_hit,
            upstream: self.upstream.as_deref(),
            answers_json: self.answers_json.as_deref(),
        }
    }
}
