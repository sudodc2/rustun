#!/usr/bin/env bash
# rustun E2E + attack scenarios — real kernel namespaces, real wire capture.
#
#   rtA "VPN server"  10.200.0.1  <--veth-->  10.200.0.2  rtB "client"
#                       |  veth2 (10.210.0.1)                |
#                    rtC "internet" 10.210.0.2  <-------------+ tunneled traffic exits here
#
set -u
cd "$(dirname "$0")/.."
BIN=./target/debug/rustun
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS  $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }

cleanup() {
  sudo pkill -f 'target/debug/rustun' 2>/dev/null
  sudo ip netns del rtA 2>/dev/null; sudo ip netns del rtB 2>/dev/null; sudo ip netns del rtC 2>/dev/null
}
trap cleanup EXIT; cleanup

# ---------- topology ----------
sudo ip netns add rtA; sudo ip netns add rtB; sudo ip netns add rtC
sudo ip link add va0 type veth peer name vb0
sudo ip link set va0 netns rtA; sudo ip link set vb0 netns rtB
sudo ip link add va1 type veth peer name vc0
sudo ip link set va1 netns rtA; sudo ip link set vc0 netns rtC
sudo ip netns exec rtA ip addr add 10.200.0.1/24 dev va0
sudo ip netns exec rtA ip addr add 10.210.0.1/24 dev va1
sudo ip netns exec rtA ip link set va0 up; sudo ip netns exec rtA ip link set va1 up; sudo ip netns exec rtA ip link set lo up
sudo ip netns exec rtB ip addr add 10.200.0.2/24 dev vb0
sudo ip netns exec rtB ip link set vb0 up; sudo ip netns exec rtB ip link set lo up
sudo ip netns exec rtB ip route add default via 10.200.0.1
sudo ip netns exec rtC ip addr add 10.210.0.2/24 dev vc0
sudo ip netns exec rtC ip link set vc0 up; sudo ip netns exec rtC ip link set lo up
sudo ip netns exec rtC ip route add default via 10.210.0.1
# "internet" side needs a route back to the tunnel net via A's masquerade — NAT covers it

read -r SKEY SPUB < <($BIN genkey | awk '{print $2}' | paste -sd' ')
read -r CKEY CPUB < <($BIN genkey | awk '{print $2}' | paste -sd' ')

# ---------- bring up ----------
sudo ip netns exec rtA $BIN server --key "$SKEY" --listen 10.200.0.1:51820 \
  --addr 10.99.0.1/24 --peer "$CPUB=10.99.0.2" --nat va1 >/tmp/rtA.log 2>&1 &
sleep 1
sudo ip netns exec rtB $BIN client --key "$CKEY" --server-pub "$SPUB" \
  --endpoint 10.200.0.1:51820 --addr 10.99.0.2/24 --route all --killswitch \
  >/tmp/rtB.log 2>&1 &
sleep 2

echo "== T1: handshake + encrypted ping across tunnel =="
if sudo ip netns exec rtB ping -c3 -W2 10.99.0.1 >/dev/null 2>&1; then
  ok "client pinged server tunnel IP 10.99.0.1"
else bad "tunnel ping failed"; fi

echo "== T2: everything on the wire is ciphertext to :51820 only =="
sudo ip netns exec rtB timeout 4 tcpdump -i vb0 -n -c 200 \
  'not (udp and port 51820) and not arp and not icmp6 and not igmp' \
  >/tmp/leak.pcap 2>/dev/null &
CAP=$!
sudo ip netns exec rtB ping -c8 -i0.2 10.99.0.1 >/dev/null 2>&1
sleep 4.5; sudo kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
if grep -qE "^\S+ IP6? " /tmp/leak.pcap 2>/dev/null; then
  bad "non-tunnel packet seen on client wire: $(head -1 /tmp/leak.pcap)"
else ok "zero non-tunnel IP packets escaped onto the wire"; fi

echo "== T3: killswitch blocks direct egress (bypass attempt) =="
# try to reach A's udp/9999 directly — killswitch must drop it
sudo ip netns exec rtB timeout 4 tcpdump -i va0 -n 'udp port 9999' -c 5 >/tmp/bypass.pcap 2>/dev/null &
BP=$!; sleep 0.5
sudo ip netns exec rtA timeout 4 tcpdump -i va0 -n 'udp port 9999' -c 5 >/tmp/bypassA.pcap 2>/dev/null &
BA=$!; sleep 0.5
if sudo ip netns exec rtB python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b"pwn",("10.200.0.1",9999))' 2>/dev/null; then
  SENT=1
else
  SENT=0
fi
sleep 4; kill $BP $BA 2>/dev/null; wait $BP $BA 2>/dev/null
if grep -q "10.200.0.2" /tmp/bypassA.pcap 2>/dev/null; then
  bad "leak: direct packet reached server iface"
elif [ "$SENT" = 0 ]; then
  ok "killswitch refused the write outright (EPERM) — nothing left the box"
else
  ok "packet sent but never reached the server iface (dropped in-flight)"
fi

echo "== T4: fuzz — 1000 garbage datagrams at the server, tunnel must survive =="
sudo ip netns exec rtB python3 - <<'PY'
import socket, os, random
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(1000):
    s.sendto(os.urandom(random.randint(1, 1400)), ("10.200.0.1", 51820))
# corrupted INIT-looking packets too
for _ in range(200):
    s.sendto(b"\x01" + os.urandom(112), ("10.200.0.1", 51820))
PY
sleep 0.5
if sudo ip netns exec rtB ping -c3 -W2 10.99.0.1 >/dev/null 2>&1; then
  ok "tunnel alive after 1200 garbage/corrupted datagrams"
else bad "tunnel broke under fuzz"; fi
if grep -q "handshake" /tmp/rtA.log; then ok "legit handshake logged (server still discriminates)"; fi

echo "== T5: real-IP masking — 'internet' host sees only server IP =="
sudo ip netns exec rtC timeout 5 tcpdump -i vc0 -n icmp -c 3 >/tmp/srcip.pcap 2>/dev/null &
TC=$!; sleep 0.5
sudo ip netns exec rtB ping -c3 -W2 10.210.0.2 >/dev/null 2>&1
sleep 5; kill $TC 2>/dev/null; wait $TC 2>/dev/null
if grep -q "10.200.0.2" /tmp/srcip.pcap; then
  bad "REAL IP LEAKED: internet saw client's underlay IP"
elif grep -q "10.210.0.1" /tmp/srcip.pcap; then
  ok "internet host saw only server NAT IP (10.210.0.1)"
else bad "no traffic reached internet host (NAT path broken?)"; fi

echo "== T6: DNS-port leak — udp/53 must ride the tunnel, not the wire =="
sudo ip netns exec rtB timeout 4 tcpdump -i vb0 -n 'udp port 53' -c 3 >/tmp/dns.pcap 2>/dev/null &
DP=$!; sleep 0.5
sudo ip netns exec rtB python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b"Q",("8.8.8.8",53))'
sleep 4.5; kill $DP 2>/dev/null; wait $DP 2>/dev/null
if grep -q "IP " /tmp/dns.pcap 2>/dev/null; then
  bad "dns leak: plaintext udp/53 on the wire"
else ok "no plaintext udp/53 on the wire (went through tunnel)"; fi

echo "== T7: kill server -> auto-reconnect =="
sudo pkill -f 'rustun server' ; sleep 1
sudo ip netns exec rtA $BIN server --key "$SKEY" --listen 10.200.0.1:51820 \
  --addr 10.99.0.1/24 --peer "$CPUB=10.99.0.2" --nat va1 >>/tmp/rtA.log 2>&1 &
# keep pinging: dead-peer detect (~10s) + re-init (5s interval)
sudo ip netns exec rtB ping -c20 -i1 -W1 10.99.0.1 >/tmp/recon.log 2>&1 &
RP=$!; sleep 18; wait $RP 2>/dev/null
if grep -q "bytes from 10.99.0.1" /tmp/recon.log; then
  ok "client re-handshook and tunnel restored ($(grep -c 'bytes from' /tmp/recon.log) pings through)"
else bad "no reconnect"; fi

echo "== T8: server port is silent to nmap (UDP fingerprint) =="
OUT=$(sudo ip netns exec rtB nmap -sU -p 51820 --max-retries 1 -Pn 10.200.0.1 2>/dev/null | grep -E "open|filtered" | head -1)
echo "  nmap: $OUT"
echo "$OUT" | grep -q "filtered" && ok "port invisible/silent to scanner" || bad "port answered scanner"

echo
echo "===== $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
