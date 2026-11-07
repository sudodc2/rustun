//! rustun/1 wire protocol — all custom, no borrowed VPN stacks.
//!
//! INIT: [0x01][nonce:16][eph_pub:32][static_pub:32][mac:32]
//!   mac  = blake2s256(nonce||eph||static, DH(c_static, s_static)) — proves client
//!          knows its static key; BLAKE2's HAIFA design resists length extension.
//! RESP: [0x02][idx:4][nonce:16][eph_pub:32][mac:32]
//!   mac  = blake2s256(idx||nonce||eph, DH(s_static, c_static)) — proves server
//!          knows its static key; echoes client nonce to bind the exchange.
//! DATA: [0x04][idx:4][ctr:8][ciphertext][poly1305 tag:16]
//!   aead nonce = 4 zero bytes || ctr (little-endian), one per direction.
//!
//! session keys = blake2s256(DH(e_i,e_r)||DH(s_i,e_r)||DH(e_i,s_r)||label)
//! — ephemeral-ephemeral DH gives forward secrecy; both static bindings give
//! mutual authentication. Rekey = new handshake.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};

pub const T_INIT: u8 = 0x01;
pub const T_RESP: u8 = 0x02;
pub const T_DATA: u8 = 0x04;
pub const INIT_LEN: usize = 1 + 16 + 32 + 32 + 32;
pub const RESP_LEN: usize = 1 + 4 + 16 + 32 + 32;
pub const DATA_HDR: usize = 1 + 4 + 8;
pub const TAG: usize = 16;
pub const REKEY_AFTER_SECS: u64 = 120;
pub const KEEPALIVE_SECS: u64 = 25;
pub const DEAD_PEER_SECS: u64 = 10;
const WINDOW: usize = 2048;

fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(key);
    h.update(msg);
    h.finalize().into()
}

fn aead(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

fn nonce12(ctr: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_le_bytes());
    *Nonce::from_slice(&n)
}

pub struct ReplayWindow {
    hi: u64,
    bmp: [u64; WINDOW / 64],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { hi: 0, bmp: [0; WINDOW / 64] }
    }

    /// Accept-and-mark. Returns false for replays / too-old counters.
    pub fn accept(&mut self, ctr: u64) -> bool {
        if ctr + WINDOW as u64 <= self.hi {
            return false;
        }
        if ctr > self.hi {
            let shift = ctr - self.hi;
            if shift >= WINDOW as u64 {
                self.bmp = [0; WINDOW / 64];
            } else {
                for i in 0..WINDOW / 64 {
                    let s = shift as usize;
                    self.bmp[i] = if i + s / 64 + 1 <= WINDOW / 64 {
                        let lo = self.bmp[i + s / 64] << (s % 64);
                        let hi = if s % 64 == 0 || i + s / 64 + 1 >= WINDOW / 64 {
                            0
                        } else {
                            self.bmp[i + s / 64 + 1] >> (64 - s % 64)
                        };
                        lo | hi
                    } else {
                        0
                    };
                }
            }
            self.hi = ctr;
            self.bmp[0] |= 1;
            return true;
        }
        let back = self.hi - ctr;
        let bit = 1u64 << (back % 64);
        let w = (back / 64) as usize;
        if self.bmp[w] & bit != 0 {
            return false;
        }
        self.bmp[w] |= bit;
        true
    }
}

pub struct Session {
    pub idx: u32,
    pub tx: ChaCha20Poly1305,
    pub rx: ChaCha20Poly1305,
    pub tx_ctr: u64,
    pub win: ReplayWindow,
    pub born: Instant,
}

impl Session {
    pub fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(&[T_DATA]);
        out.extend_from_slice(&self.idx.to_le_bytes());
        out.extend_from_slice(&self.tx_ctr.to_le_bytes());
        let ct = self.tx.encrypt(&nonce12(self.tx_ctr), plaintext).expect("seal");
        out.extend_from_slice(&ct);
        self.tx_ctr += 1;
    }

    pub fn open(&mut self, datagram: &[u8], out: &mut Vec<u8>) -> Result<(), &'static str> {
        if datagram.len() < DATA_HDR + TAG {
            return Err("short");
        }
        let ctr = u64::from_le_bytes(datagram[5..13].try_into().unwrap());
        // verify tag BEFORE touching the window — a forged counter must not
        // slide the window past legitimate packets
        match self.rx.decrypt(&nonce12(ctr), &datagram[DATA_HDR..]) {
            Ok(pt) => {
                if !self.win.accept(ctr) {
                    return Err("replay");
                }
                out.clear();
                out.extend_from_slice(&pt);
                Ok(())
            }
            Err(_) => Err("auth"),
        }
    }
}

/// Initiator side: pending state between sending INIT and getting RESP.
pub struct PendingInit {
    pub nonce: [u8; 16],
    pub eph: StaticSecret,
    pub static_pub: PublicKey,
    pub sent: Instant,
}

pub fn build_init(
    pending: &PendingInit,
    client_static: &StaticSecret,
    server_public: &PublicKey,
    out: &mut Vec<u8>,
) {
    out.clear();
    out.push(T_INIT);
    out.extend_from_slice(&pending.nonce);
    out.extend_from_slice(PublicKey::from(&pending.eph).as_bytes());
    out.extend_from_slice(pending.static_pub.as_bytes());
    let proof = client_static.diffie_hellman(server_public);
    let m = mac(proof.as_bytes(), &out[1..]);
    out.extend_from_slice(&m);
}

/// Responder side: validate INIT against our static + peer's static.
/// Returns (session, RESP datagram) or None — silently drops garbage.
pub fn accept_init(
    datagram: &[u8],
    own_static: &StaticSecret,
    peer_lookup: &dyn Fn(&PublicKey) -> Option<usize>,
    next_idx: u32,
) -> Option<(usize, Session, Vec<u8>)> {
    if datagram.len() != INIT_LEN || datagram[0] != T_INIT {
        return None;
    }
    let static_pub = PublicKey::from(<[u8; 32]>::try_from(&datagram[49..81]).ok()?);
    let peer_id = peer_lookup(&static_pub)?;
    let proof = own_static.diffie_hellman(&static_pub);
    if mac(proof.as_bytes(), &datagram[1..81])[..] != datagram[81..113] {
        return None; // forged init
    }
    let c_eph = PublicKey::from(<[u8; 32]>::try_from(&datagram[17..49]).ok()?);
    let r_eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let idx = next_idx;

    let keymat = derive_keymat(&r_eph, &c_eph, own_static, &static_pub, true);
    let sess = make_session(idx, keymat);

    let mut resp = vec![T_RESP];
    resp.extend_from_slice(&idx.to_le_bytes());
    resp.extend_from_slice(&datagram[1..17]); // echo nonce
    resp.extend_from_slice(PublicKey::from(&r_eph).as_bytes());
    let m = mac(proof.as_bytes(), &resp[1..]);
    resp.extend_from_slice(&m);
    Some((peer_id, sess, resp))
}

/// Initiator side: validate RESP, produce the session.
pub fn accept_resp(
    datagram: &[u8],
    pending: &PendingInit,
    client_static: &StaticSecret,
    server_public: &PublicKey,
) -> Option<Session> {
    if datagram.len() != RESP_LEN || datagram[0] != T_RESP {
        return None;
    }
    if datagram[5..21] != pending.nonce[..] {
        return None;
    }
    let proof = client_static.diffie_hellman(server_public);
    if mac(proof.as_bytes(), &datagram[1..53])[..] != datagram[53..85] {
        return None;
    }
    let idx = u32::from_le_bytes(datagram[1..5].try_into().ok()?);
    let r_eph = PublicKey::from(<[u8; 32]>::try_from(&datagram[21..53]).ok()?);
    let keymat = derive_keymat(&pending.eph, &r_eph, client_static, server_public, false);
    Some(make_session(idx, keymat))
}

fn derive_keymat(
    own_eph: &StaticSecret,
    peer_eph: &PublicKey,
    own_static: &StaticSecret,
    peer_static: &PublicKey,
    i_am_responder: bool,
) -> [u8; 64] {
    let mut km = [0u8; 96];
    km[0..32].copy_from_slice(own_eph.diffie_hellman(peer_eph).as_bytes());
    // key material must be ordered by ROLE, not by self — otherwise each side
    // puts the static×ephemeral DHs in different slots and derives different keys
    let (d2, d3) = if i_am_responder {
        // responder: eph_i is peer's, so own_eph×peer_static = DH(e_i,s_r)
        (own_eph.diffie_hellman(peer_static), own_static.diffie_hellman(peer_eph))
    } else {
        // initiator: own_static×peer_eph = DH(s_i,e_r), own_eph×peer_static = DH(e_i,s_r)
        (own_static.diffie_hellman(peer_eph), own_eph.diffie_hellman(peer_static))
    };
    km[32..64].copy_from_slice(d2.as_bytes()); // DH(s_i, e_r)
    km[64..96].copy_from_slice(d3.as_bytes()); // DH(e_i, s_r)
    // label order differs per role so tx/rx keys are swapped correctly
    let mut out = [0u8; 64];
    let mut h = Blake2s256::new();
    h.update(km);
    h.update([1u8]);
    let k1: [u8; 32] = h.finalize().into();
    let mut h = Blake2s256::new();
    h.update(km);
    h.update([2u8]);
    let k2: [u8; 32] = h.finalize().into();
    // initiator sends on k1, receives on k2; responder the reverse
    if i_am_responder {
        out[..32].copy_from_slice(&k2); // tx
        out[32..].copy_from_slice(&k1); // rx
    } else {
        out[..32].copy_from_slice(&k1);
        out[32..].copy_from_slice(&k2);
    }
    out
}

fn make_session(idx: u32, keymat: [u8; 64]) -> Session {
    let mut tx = [0u8; 32];
    let mut rx = [0u8; 32];
    tx.copy_from_slice(&keymat[..32]);
    rx.copy_from_slice(&keymat[32..]);
    Session {
        idx,
        tx: aead(&tx),
        rx: aead(&rx),
        tx_ctr: 0,
        win: ReplayWindow::new(),
        born: Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    fn pair() -> (StaticSecret, PublicKey, StaticSecret, PublicKey) {
        let a = keys::generate();
        let b = keys::generate();
        (a.secret, a.public, b.secret, b.public)
    }

    fn handshake() -> (Session, Session) {
        let (cs, cp, ss, sp) = pair();
        let pending = PendingInit {
            nonce: [7u8; 16],
            eph: StaticSecret::random_from_rng(rand::rngs::OsRng),
            static_pub: cp,
            sent: Instant::now(),
        };
        let mut init = Vec::new();
        build_init(&pending, &cs, &sp, &mut init);
        assert_eq!(init.len(), INIT_LEN);
        let lookup = |p: &PublicKey| if p.as_bytes() == cp.as_bytes() { Some(0) } else { None };
        let (pid, mut s_sess, resp) =
            accept_init(&init, &ss, &lookup, 9).expect("init accepted");
        assert_eq!(pid, 0);
        let mut c_sess = accept_resp(&resp, &pending, &cs, &sp).expect("resp accepted");
        // prove keys line up both directions
        let mut wire = Vec::new();
        let mut pt = Vec::new();
        c_sess.seal(b"hello", &mut wire);
        s_sess.open(&wire, &mut pt).unwrap();
        assert_eq!(pt, b"hello");
        (c_sess, s_sess)
    }

    #[test]
    fn full_handshake_and_data() {
        handshake();
    }

    #[test]
    fn forged_init_dropped() {
        let (cs, cp, ss, sp) = pair();
        let (evil_s, _evil_p, _x, _y) = pair();
        let pending = PendingInit {
            nonce: [1u8; 16],
            eph: StaticSecret::random_from_rng(rand::rngs::OsRng),
            static_pub: cp,
            sent: Instant::now(),
        };
        let mut init = Vec::new();
        // build_init with a different private key than static_pub claims → bad mac
        build_init(&pending, &evil_s, &sp, &mut init);
        let lookup = |p: &PublicKey| if p.as_bytes() == cp.as_bytes() { Some(0) } else { None };
        assert!(accept_init(&init, &ss, &lookup, 1).is_none());
        let _ = cs;
    }

    #[test]
    fn unknown_peer_dropped() {
        let (cs, cp, ss, sp) = pair();
        let pending = PendingInit {
            nonce: [2u8; 16],
            eph: StaticSecret::random_from_rng(rand::rngs::OsRng),
            static_pub: cp,
            sent: Instant::now(),
        };
        let mut init = Vec::new();
        build_init(&pending, &cs, &sp, &mut init);
        let lookup = |_: &PublicKey| None;
        assert!(accept_init(&init, &ss, &lookup, 1).is_none());
    }

    #[test]
    fn replay_rejected() {
        let (mut c, mut s) = handshake();
        let mut wire = Vec::new();
        let mut pt = Vec::new();
        c.seal(b"pkt", &mut wire);
        s.open(&wire, &mut pt).unwrap();
        assert!(s.open(&wire, &mut pt).is_err()); // same datagram again
    }

    #[test]
    fn tampered_data_rejected() {
        let (mut c, mut s) = handshake();
        let mut wire = Vec::new();
        let mut pt = Vec::new();
        c.seal(b"pkt", &mut wire);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert_eq!(s.open(&wire, &mut pt), Err("auth"));
    }

    #[test]
    fn window_accepts_out_of_order() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(1));
        assert!(w.accept(10));
        assert!(w.accept(5)); // within window, unseen
        assert!(!w.accept(5)); // replay
        assert!(!w.accept(1)); // old+seen
    }
}
