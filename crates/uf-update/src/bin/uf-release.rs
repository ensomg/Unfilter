//! Maintainer tool for signed releases (not shipped).
//!
//! ```text
//! uf-release keygen <key-file>               new signing key; prints the public key
//! uf-release sign <key-file> <version> <exe>  writes <exe>.sig for the release
//! uf-release pubkey <key-file>               prints the public key again
//! ```
//!
//! The key file is a hex PKCS#8 Ed25519 key. Keep it out of the repository;
//! paste the printed public key into `uf_update::PUBLIC_KEY`.

use std::process::ExitCode;

use ring::signature::{Ed25519KeyPair, KeyPair};
use uf_update::{Version, from_hex, signed_message, to_hex, verify};

fn load(path: &str) -> Result<Ed25519KeyPair, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let pkcs8 = from_hex(&text).ok_or("anahtar dosyası hex değil")?;
    Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|e| format!("anahtar okunamadı: {e}"))
}

fn print_public(kp: &Ed25519KeyPair) {
    let pk = kp.public_key().as_ref();
    let list: Vec<String> = pk.iter().map(|b| format!("0x{b:02x}")).collect();
    println!("public key: {}", to_hex(pk));
    println!("pub const PUBLIC_KEY: [u8; 32] = [{}];", list.join(", "));
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, key] if cmd == "keygen" => {
            if std::path::Path::new(key).exists() {
                return Err(format!("{key} zaten var, üzerine yazılmadı"));
            }
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| e.to_string())?;
            std::fs::write(key, to_hex(pkcs8.as_ref())).map_err(|e| format!("{key}: {e}"))?;
            print_public(&load(key)?);
            Ok(())
        }
        [cmd, key] if cmd == "pubkey" => {
            print_public(&load(key)?);
            Ok(())
        }
        [cmd, key, version, exe] if cmd == "sign" => {
            let kp = load(key)?;
            let v = Version::parse(version).ok_or("sürüm 1.2.3 biçiminde olmalı")?;
            let bytes = std::fs::read(exe).map_err(|e| format!("{exe}: {e}"))?;
            let sig = to_hex(kp.sign(&signed_message(v, &bytes)).as_ref());
            if !verify(v, &bytes, sig.as_bytes(), kp.public_key().as_ref()) {
                return Err("imza kendi kendini doğrulamadı".into());
            }
            let out = format!("{exe}.sig");
            std::fs::write(&out, &sig).map_err(|e| format!("{out}: {e}"))?;
            println!("{out} yazıldı (sürüm {v})");
            Ok(())
        }
        _ => Err("kullanım: uf-release keygen <anahtar> | sign <anahtar> <sürüm> <exe> | pubkey <anahtar>".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("uf-release: {e}");
            ExitCode::FAILURE
        }
    }
}
