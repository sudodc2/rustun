//! Linux plumbing: TUN device (raw ioctl — no external crate), routes,
//! nftables kill switch. Everything shells to `ip`/`nft`/`sysctl` so the
//! system stays the source of truth.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::process::Command;

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

pub fn open_tun(name: &str) -> io::Result<File> {
    let f = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
    let mut ifr = [0u8; 40]; // struct ifreq: name[16] + union (flags land at 16)
    let n = name.as_bytes();
    if n.len() >= 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ifname too long"));
    }
    ifr[..n.len()].copy_from_slice(n);
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF, ifr.as_mut_ptr() as *mut libc::c_void) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(f)
}

fn sh(cmd: &str) -> Result<(), String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("`{cmd}`: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn sh_out(cmd: &str) -> Result<String, String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!("`{cmd}`: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

pub fn setup_iface(name: &str, addr_prefix: &str, mtu: u32) -> Result<(), String> {
    sh(&format!("ip addr replace {addr_prefix} dev {name}"))?;
    sh(&format!("ip link set dev {name} mtu {mtu} up"))
}

/// Client full-tunnel routing: pin the endpoint to the real gateway, then
/// cover default with two /1 routes via the tunnel (wg-quick trick — avoids
/// replacing the existing default).
pub fn client_routes(tun: &str, endpoint_ip: &str) -> Result<(), String> {
    let route = sh_out(&format!("ip route get {endpoint_ip}"))?;
    let dev = route
        .split_whitespace()
        .skip_while(|t| *t != "dev")
        .nth(1)
        .ok_or_else(|| format!("no dev in `{route}`"))?;
    // direct route (no gateway) vs routed via a gateway
    let pin = match route.split_whitespace().skip_while(|t| *t != "via").nth(1) {
        Some(gw) => format!("{endpoint_ip}/32 via {gw} dev {dev}"),
        None => format!("{endpoint_ip}/32 dev {dev}"),
    };
    sh(&format!("ip route replace {pin}"))?;
    sh(&format!("ip route replace 0.0.0.0/1 dev {tun}"))?;
    sh(&format!("ip route replace 128.0.0.0/1 dev {tun}"))
}

pub fn client_routes_teardown(endpoint_ip: &str) {
    let _ = sh(&format!("ip route del {endpoint_ip}/32"));
    let _ = sh("ip route del 0.0.0.0/1");
    let _ = sh("ip route del 128.0.0.0/1");
}

/// Kill switch, Mullvad-style: nft `inet` table covers IPv4 AND IPv6 — so
/// v6 can't leak either. Only tun egress + the endpoint socket pass.
pub fn killswitch_on(tun: &str, endpoint_ip: &str, endpoint_port: u16) -> Result<(), String> {
    killswitch_off(); // idempotent
    sh("nft add table inet rustun")?;
    sh("nft add chain inet rustun output '{ type filter hook output priority 0; policy drop; }'")?;
    sh("nft add rule inet rustun output oif lo accept")?;
    sh(&format!("nft add rule inet rustun output oifname \"{tun}\" accept"))?;
    sh(&format!(
        "nft add rule inet rustun output ip daddr {endpoint_ip} udp dport {endpoint_port} accept"
    ))
}

pub fn killswitch_off() {
    let _ = sh("nft delete table inet rustun");
}

/// Server: let tunnel clients reach the outside world (masquerade).
pub fn server_nat(out_iface: &str) -> Result<(), String> {
    sh("sysctl -qw net.ipv4.ip_forward=1")?;
    sh("nft add table ip rustun_nat")?;
    sh("nft add chain ip rustun_nat post '{ type nat hook postrouting priority 100; }'")?;
    sh(&format!("nft add rule ip rustun_nat post oifname \"{out_iface}\" masquerade"))
}

pub fn server_nat_off() {
    let _ = sh("nft delete table ip rustun_nat");
}
