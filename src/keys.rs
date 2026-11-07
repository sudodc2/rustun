use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Keypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

pub fn generate() -> Keypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Keypair { secret, public }
}

pub fn encode(bytes: &[u8; 32]) -> String {
    B64.encode(bytes)
}

pub fn decode_secret(s: &str) -> Result<StaticSecret, String> {
    let raw = decode_32(s)?;
    Ok(StaticSecret::from(raw))
}

pub fn decode_public(s: &str) -> Result<PublicKey, String> {
    let raw = decode_32(s)?;
    Ok(PublicKey::from(raw))
}

fn decode_32(s: &str) -> Result<[u8; 32], String> {
    let v = B64.decode(s.trim()).map_err(|e| format!("bad base64: {e}"))?;
    v.try_into().map_err(|_| "key must decode to 32 bytes".to_string())
}

pub fn cmd_genkey() {
    let kp = generate();
    println!("private: {}", encode(&kp.secret.to_bytes()));
    println!("public:  {}", encode(kp.public.as_bytes()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let kp = generate();
        let sec = decode_secret(&encode(&kp.secret.to_bytes())).unwrap();
        let publ = decode_public(&encode(kp.public.as_bytes())).unwrap();
        assert_eq!(sec.to_bytes(), kp.secret.to_bytes());
        assert_eq!(publ.as_bytes(), kp.public.as_bytes());
    }

    #[test]
    fn bad_base64_rejected() {
        assert!(decode_secret("!!!notbase64!!!").is_err());
        assert!(decode_secret(&B64.encode([0u8; 16])).is_err()); // wrong length
    }

    #[test]
    fn dh_symmetric() {
        let a = generate();
        let b = generate();
        assert_eq!(
            a.secret.diffie_hellman(&b.public).to_bytes(),
            b.secret.diffie_hellman(&a.public).to_bytes()
        );
    }
}
