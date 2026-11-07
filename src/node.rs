//! The packet pump. Three threads around one Mutex<Node>:
//!   TUN -> (route to peer) -> seal -> UDP
//!   UDP -> handshake/data -> open -> TUN
//!   timer -> rekey, keepalive, pending-init retransmit

use crate::keys;
use crate::proto::{self, *};
use rand::RngCore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Peer {
    pub static_pub: PublicKey,
    pub tun_ip: Option<IpAddr>, // server side: which tunnel IP this peer owns
    pub endpoint: Option<SocketAddr>,
    pub sessions: Vec<Session>, // newest first; keep up to 2 for rekey overlap
    pub pending: Option<PendingInit>,
    pub last_tx: Instant,
    pub last_rx: Instant,      // any valid authenticated traffic inbound
    pub last_tx_data: Instant, // real payload outbound (not keepalives)
    pub last_init: Instant,
}

pub struct Node {
    pub is_client: bool,
    pub own_static: StaticSecret,
    pub peers: Vec<Peer>,
    pub by_pub: HashMap<[u8; 32], usize>,
    pub by_tunip: HashMap<IpAddr, usize>,
    pub by_endpoint: HashMap<SocketAddr, usize>,
    pub next_idx: u32,
    pub server_public: Option<PublicKey>, // client only
    pub endpoint_hint: Option<SocketAddr>, // client only
}

impl Node {
    fn session_for(&mut self, peer: usize, idx: u32) -> Option<usize> {
        self.peers[peer].sessions.iter().position(|s| s.idx == idx)
    }

    fn peer_by_endpoint(&mut self, addr: SocketAddr) -> Option<usize> {
        self.by_endpoint.get(&addr).copied()
    }

    fn adopt_endpoint(&mut self, peer: usize, addr: SocketAddr) {
        if self.peers[peer].endpoint != Some(addr) {
            if let Some(old) = self.peers[peer].endpoint {
                self.by_endpoint.remove(&old);
            }
            self.peers[peer].endpoint = Some(addr);
            self.by_endpoint.insert(addr, peer);
        }
    }

    fn set_session(&mut self, peer: usize, sess: Session) {
        let p = &mut self.peers[peer];
        p.sessions.insert(0, sess);
        p.sessions.truncate(2);
    }
}

fn dst_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            Some(IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])))
        }
        6 if packet.len() >= 40 => {
            let a: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

pub fn run(mut node: Node, mut tun: std::fs::File, sock: UdpSocket) -> ! {
    sock.set_nonblocking(false).expect("sock");
    let node = Arc::new(Mutex::new({
        if node.is_client {
            node.peers[0].endpoint = node.endpoint_hint;
            if let Some(ep) = node.endpoint_hint {
                node.by_endpoint.insert(ep, 0);
            }
            kick_handshake(&mut node, &sock);
        }
        node
    }));

    // --- UDP -> TUN -------------------------------------------------------
    {
        let sock = sock.try_clone().expect("sock clone");
        let node = Arc::clone(&node);
        let mut tun_w = tun.try_clone().expect("tun clone");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut plain = Vec::with_capacity(2048);
            loop {
                let (len, src) = match sock.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                if len == 0 {
                    continue;
                }
                let dg = &buf[..len];
                let mut n = node.lock().unwrap();
                match dg[0] {
                    T_INIT if !n.is_client => {
                        let lookup = |k: &PublicKey| n.by_pub.get(k.as_bytes()).copied();
                        if let Some((pid, sess, resp)) = proto::accept_init(
                            dg,
                            &n.own_static,
                            &lookup,
                            n.next_idx,
                        ) {
                            n.next_idx = n.next_idx.wrapping_add(1);
                            n.adopt_endpoint(pid, src);
                            n.set_session(pid, sess);
                            let _ = sock.send_to(&resp, src);
                            eprintln!("[rustun] handshake #{:?} with {}", n.next_idx - 1, src);
                        }
                        // garbage/forged init: silent drop, like WireGuard
                    }
                    T_RESP if n.is_client => {
                        if let Some(pend) = n.peers[0].pending.take() {
                            let sp = n.server_public.unwrap();
                            if let Some(sess) =
                                proto::accept_resp(dg, &pend, &n.own_static, &sp)
                            {
                                n.adopt_endpoint(0, src);
                                n.peers[0].last_rx = Instant::now();
                                n.set_session(0, sess);
                                eprintln!("[rustun] session up (idx {})", dg[1]);
                            } else {
                                n.peers[0].pending = Some(pend);
                            }
                        }
                    }
                    T_DATA => {
                        // fast path by endpoint, else try every peer's sessions
                        let idx = u32::from_le_bytes(
                            dg.get(1..5).map(|b| b.try_into().unwrap()).unwrap_or([0; 4]),
                        );
                        let mut candidates: Vec<usize> =
                            n.peer_by_endpoint(src).into_iter().collect();
                        if candidates.is_empty() {
                            candidates = (0..n.peers.len()).collect();
                        }
                        let mut done = false;
                        'outer: for pid in candidates {
                            if let Some(spos) = n.session_for(pid, idx) {
                                match n.peers[pid].sessions[spos].open(dg, &mut plain) {
                                    Ok(()) => {
                                        n.adopt_endpoint(pid, src); // roaming
                                        n.peers[pid].last_rx = Instant::now();
                                        let _ = tun_w.write_all(&plain);
                                        done = true;
                                        break 'outer;
                                    }
                                    Err(_) => continue,
                                }
                            }
                        }
                        if !done {
                            // not for us / replay / forged — silent drop
                        }
                    }
                    _ => {} // unknown type: silent drop
                }
            }
        });
    }

    // --- TUN -> UDP -------------------------------------------------------
    {
        let sock = sock.try_clone().expect("sock clone");
        let node = Arc::clone(&node);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut wire = Vec::with_capacity(2048);
            loop {
                let len = match tun.read(&mut buf) {
                    Ok(0) | Err(_) => continue,
                    Ok(l) => l,
                };
                let pkt = &buf[..len];
                let mut n = node.lock().unwrap();
                let pid = if n.is_client {
                    0
                } else {
                    match dst_ip(pkt).and_then(|d| n.by_tunip.get(&d).copied()) {
                        Some(p) => p,
                        None => continue, // no peer owns this dst
                    }
                };
                let ep = match n.peers[pid].endpoint {
                    Some(e) => e,
                    None => continue,
                };
                if let Some(sess) = n.peers[pid].sessions.first_mut() {
                    sess.seal(pkt, &mut wire);
                    if sock.send_to(&wire, ep).is_ok() {
                        n.peers[pid].last_tx = Instant::now();
                        n.peers[pid].last_tx_data = Instant::now();
                    }
                }
            }
        });
    }

    // --- timers -----------------------------------------------------------
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let mut n = node.lock().unwrap();
        if n.is_client {
            let p = &mut n.peers[0];
            let need_init = match p.sessions.first() {
                None => {
                    p.pending.is_none()
                        || p.last_init.elapsed() > Duration::from_secs(5)
                }
                Some(s) => {
                    s.born.elapsed() > Duration::from_secs(REKEY_AFTER_SECS)
                        // dead-peer: we sent real payload but nothing valid came
                        // back for DEAD_PEER_SECS -> peer is gone, re-handshake
                        || (p.last_rx < p.last_tx_data
                            && p.last_rx.elapsed() > Duration::from_secs(DEAD_PEER_SECS))
                }
            };
            if need_init {
                if p.endpoint.is_some() {
                    kick_handshake(&mut n, &sock);
                }
            } else if p.last_tx.elapsed() > Duration::from_secs(KEEPALIVE_SECS) {
                if let (Some(sess), Some(ep)) = (p.sessions.first_mut(), p.endpoint) {
                    let mut wire = Vec::with_capacity(DATA_HDR + TAG);
                    sess.seal(&[], &mut wire);
                    let _ = sock.send_to(&wire, ep);
                    p.last_tx = Instant::now();
                }
            }
        }
    }
}

fn kick_handshake(n: &mut Node, sock: &UdpSocket) {
    let p = &mut n.peers[0];
    let ep = match p.endpoint.or(n.endpoint_hint) {
        Some(e) => e,
        None => return,
    };
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let pending = PendingInit {
        nonce,
        eph: StaticSecret::random_from_rng(rand::rngs::OsRng),
        static_pub: PublicKey::from(&n.own_static),
        sent: Instant::now(),
    };
    let mut init = Vec::with_capacity(INIT_LEN);
    build_init(&pending, &n.own_static, &n.server_public.unwrap(), &mut init);
    let _ = sock.send_to(&init, ep);
    p.pending = Some(pending);
    p.last_init = Instant::now();
}

#[allow(dead_code)]
pub fn parse_peer(arg: &str) -> Result<(PublicKey, Option<IpAddr>), String> {
    // base64 keys end in '=' padding — the separator must be the LAST '='
    if let Some((k, ip)) = arg.rsplit_once('=') {
        if !ip.is_empty() {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                return Ok((keys::decode_public(k)?, Some(addr)));
            }
        }
    }
    Ok((keys::decode_public(arg)?, None))
}
