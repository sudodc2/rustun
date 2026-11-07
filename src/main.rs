mod keys;
mod node;
mod proto;
mod syslinux;

use node::{Node, Peer};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn on_sig(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

const USAGE: &str = "rustun — self-contained encrypted VPN (custom protocol)

  rustun genkey
  rustun server --key <b64> --listen <ip:port> --addr <tun/prefix>
                --peer <b64pub>=<tunip> [--peer ...] [--nat <out-iface>]
  rustun client --key <b64> --server-pub <b64> --endpoint <ip:port>
                --addr <tun/prefix> [--route all] [--killswitch]
                [--ifname rustun0] [--mtu 1420]
";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("genkey") => {
            keys::cmd_genkey();
            Ok(())
        }
        Some("server") => server(&args[1..]),
        Some("client") => client(&args[1..]),
        _ => Err(USAGE.to_string()),
    };
    if let Err(e) = r {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

fn server(args: &[String]) -> Result<(), String> {
    let own = keys::decode_secret(&need(args, "--key")?)?;
    let listen: SocketAddr = need(args, "--listen")?.parse().map_err(|_| "bad --listen")?;
    let addr = need(args, "--addr")?;
    let ifname = flag(args, "--ifname").unwrap_or_else(|| "rustun0".into());
    let mtu: u32 = flag(args, "--mtu").and_then(|m| m.parse().ok()).unwrap_or(1420);

    let mut peers = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--peer" {
            let (pubk, tunip) = node::parse_peer(&args[i + 1])?;
            peers.push(Peer {
                static_pub: pubk,
                tun_ip: tunip,
                endpoint: None,
                sessions: vec![],
                pending: None,
                last_tx: Instant::now(),
                last_rx: Instant::now(),
                last_tx_data: Instant::now(),
                last_init: Instant::now(),
            });
            i += 2;
        } else {
            i += 1;
        }
    }
    if peers.is_empty() {
        return Err("server needs at least one --peer".into());
    }

    let sock = UdpSocket::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    let tun = syslinux::open_tun(&ifname).map_err(|e| format!("tun: {e}"))?;
    syslinux::setup_iface(&ifname, &addr, mtu)?;
    if let Some(out) = flag(args, "--nat") {
        syslinux::server_nat(&out)?;
    }
    install_sighandlers();
    eprintln!("[rustun] server on {listen}, tunnel {addr} dev {ifname}");

    let node = Node {
        is_client: false,
        own_static: own,
        by_pub: peers
            .iter()
            .enumerate()
            .map(|(i, p)| (*p.static_pub.as_bytes(), i))
            .collect(),
        by_tunip: peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.tun_ip.map(|ip| (ip, i)))
            .collect(),
        by_endpoint: Default::default(),
        peers,
        next_idx: 1,
        server_public: None,
        endpoint_hint: None,
    };
    // teardown thread
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if SHUTDOWN.load(Ordering::SeqCst) {
            syslinux::server_nat_off();
            std::process::exit(0);
        }
    });
    node::run(node, tun, sock)
}

fn client(args: &[String]) -> Result<(), String> {
    let own = keys::decode_secret(&need(args, "--key")?)?;
    let server_pub = keys::decode_public(&need(args, "--server-pub")?)?;
    let endpoint: SocketAddr = need(args, "--endpoint")?.parse().map_err(|_| "bad --endpoint")?;
    let addr = need(args, "--addr")?;
    let ifname = flag(args, "--ifname").unwrap_or_else(|| "rustun0".into());
    let mtu: u32 = flag(args, "--mtu").and_then(|m| m.parse().ok()).unwrap_or(1420);
    let full = flag(args, "--route").as_deref() == Some("all");
    let ks = has(args, "--killswitch");

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let tun = syslinux::open_tun(&ifname).map_err(|e| format!("tun: {e}"))?;
    syslinux::setup_iface(&ifname, &addr, mtu)?;
    if full {
        syslinux::client_routes(&ifname, &endpoint.ip().to_string())?;
    }
    if ks {
        syslinux::killswitch_on(&ifname, &endpoint.ip().to_string(), endpoint.port())?;
    }
    install_sighandlers();
    eprintln!("[rustun] client up, tunnel {addr} dev {ifname} -> {endpoint}");

    let endpoint_ip = endpoint.ip();
    let peers = vec![Peer {
        static_pub: server_pub,
        tun_ip: None,
        endpoint: Some(endpoint),
        sessions: vec![],
        pending: None,
        last_tx: Instant::now(),
        last_rx: Instant::now(),
        last_tx_data: Instant::now(),
        last_init: Instant::now() - std::time::Duration::from_secs(60),
    }];
    let node = Node {
        is_client: true,
        own_static: own,
        by_pub: [(*server_pub.as_bytes(), 0)].into(),
        by_tunip: Default::default(),
        by_endpoint: [(endpoint, 0)].into(),
        peers,
        next_idx: 1,
        server_public: Some(server_pub),
        endpoint_hint: Some(endpoint),
    };
    let eip = endpoint_ip.to_string();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if SHUTDOWN.load(Ordering::SeqCst) {
            if ks {
                syslinux::killswitch_off();
            }
            if full {
                syslinux::client_routes_teardown(&eip);
            }
            std::process::exit(0);
        }
    });
    node::run(node, tun, sock)
}

fn install_sighandlers() {
    unsafe {
        libc::signal(libc::SIGINT, on_sig as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_sig as libc::sighandler_t);
    }
}
