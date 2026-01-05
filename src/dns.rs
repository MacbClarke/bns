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
    rules::{RuleAnswer, RuleSet, RuleType},
    store::{QueryLogEntry, Store},
};

pub struct DnsServerDeps {
    pub config: Config,
    pub cache: Arc<DnsCache>,
    pub rules: Arc<RuleSet>,
    pub store: Arc<Store>,
}

pub struct DnsServer {
    deps: DnsServerDeps,
    rr_counter: Arc<AtomicUsize>,
}

impl DnsServer {
    pub fn new(deps: DnsServerDeps) -> Self {
        Self {
            deps,
            rr_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

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
        }
    }
}

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
                handle_query(packet, peer, "udp", deps, log_tx, rr_counter.as_ref()).await
            {
                let _ = socket.send_to(&resp, peer).await;
            }
        });
    }
    Ok(())
}

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
                handle_tcp_client(stream, peer, deps, log_tx, rr_counter.as_ref()).await
            {
                debug!(error = %e, "tcp client error");
            }
        });
    }
    Ok(())
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    deps: DnsServerDeps,
    log_tx: mpsc::Sender<LogEvent>,
    rr_counter: &AtomicUsize,
) -> anyhow::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; len];
        stream.read_exact(&mut msg_buf).await?;

        if let Some(resp) = handle_query(msg_buf, peer, "tcp", deps.clone(), log_tx.clone(), rr_counter).await {
            let resp_len: u16 = resp.len().try_into().unwrap_or(u16::MAX);
            stream.write_all(&resp_len.to_be_bytes()).await?;
            stream.write_all(&resp[..resp_len as usize]).await?;
        } else {
            return Ok(());
        }
    }
}

async fn handle_query(
    packet: Vec<u8>,
    peer: SocketAddr,
    transport: &'static str,
    deps: DnsServerDeps,
    log_tx: mpsc::Sender<LogEvent>,
    rr_counter: &AtomicUsize,
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
        } else {
            let (upstream, resp) =
                forward_to_upstream(&deps, transport, &packet, rr_counter).await?;
            upstream_used = Some(upstream);

            if let Ok(msg) = Message::from_vec(&resp) {
                let ttl = ttl_for_cache(&deps.cache, &msg);
                deps.cache.put(key, &resp, ttl);
            }
            Some(resp)
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

fn rule_match(rules: &RuleSet, qname: &str, qtype: RecordType) -> Option<(i64, RuleAnswer)> {
    let rt = match qtype {
        RecordType::A => RuleType::A,
        RecordType::AAAA => RuleType::AAAA,
        RecordType::CNAME => RuleType::CNAME,
        _ => return None,
    };
    rules.find_answer(qname, rt)
}

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

async fn forward_udp(upstream: SocketAddr, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(packet, upstream).await?;

    let mut buf = vec![0u8; 65_535];
    let (n, _) = socket.recv_from(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

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
