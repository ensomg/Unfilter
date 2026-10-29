//! Signed self-update from GitHub Releases.
//!
//! The latest release is accepted only when it carries [`SIG_ASSET`]: an
//! Ed25519 signature, made with the maintainer's key (`uf-release sign`), over
//! [`signed_message`] — the release version plus the SHA-256 of the exe. The
//! version is part of the signed bytes, so an older signed build cannot be
//! re-served under a newer tag (no rollback), and a compromised GitHub account
//! alone cannot ship code: it would also need the signing key.
//!
//! Installing swaps the running exe on disk (rename, then move the new file
//! in); the new version starts with the next launch.

use std::fmt;

use serde::Deserialize;

pub mod apply;
#[cfg(windows)]
pub mod elevate;
#[cfg(windows)]
mod http;

/// GitHub repository the releases come from.
pub const REPO: &str = "ensomg/Unfilter";
/// Release asset holding the executable.
pub const EXE_ASSET: &str = "unfilter.exe";
/// Release asset holding the hex Ed25519 signature.
pub const SIG_ASSET: &str = "unfilter.exe.sig";
/// Upper bound for a downloaded exe.
pub const MAX_EXE_BYTES: usize = 64 << 20;
/// Ed25519 public key of the release signing key (`uf-release keygen`).
pub const PUBLIC_KEY: [u8; 32] = [
    0xe8, 0x8e, 0xd1, 0x4f, 0x5d, 0x42, 0xff, 0x42, 0xd4, 0x63, 0x64, 0x7c, 0xa1, 0x44, 0x17, 0x8e,
    0xee, 0x73, 0xa9, 0xda, 0x6f, 0x7a, 0x66, 0xdc, 0xb8, 0x62, 0x7a, 0x36, 0x06, 0x52, 0xee, 0xb2,
];

/// `--update` exit codes.
pub mod exit {
    /// A new version was installed (applies on next launch).
    pub const INSTALLED: u8 = 0;
    /// Something failed.
    pub const FAILED: u8 = 1;
    /// Already on the latest version.
    pub const UP_TO_DATE: u8 = 2;
    /// An installed update waits for a restart.
    pub const RESTART_PENDING: u8 = 3;
}

/// `major.minor.patch`; pre-release and build suffixes are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u64, pub u64, pub u64);

impl Version {
    /// Parses `1.2.3` or `v1.2.3` (with an optional `-pre`/`+build` suffix).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let core = s.split(['-', '+']).next()?;
        let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
        let v = Self(it.next()??, it.next()??, it.next()??);
        it.next().is_none().then_some(v)
    }

    /// The version of this build.
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Self(0, 0, 0))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The latest published release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Version from the tag.
    pub version: Version,
    /// Download URL of [`EXE_ASSET`], if attached.
    pub exe_url: Option<String>,
    /// Download URL of [`SIG_ASSET`], if attached.
    pub sig_url: Option<String>,
}

/// Parses GitHub's `releases/latest` JSON. `None` for drafts, pre-releases
/// and unparsable tags. Asset URLs outside this repository's release
/// downloads are ignored.
pub fn parse_release(json: &[u8]) -> Option<Release> {
    #[derive(Deserialize)]
    struct Asset {
        name: String,
        browser_download_url: String,
    }
    #[derive(Deserialize)]
    struct Rel {
        tag_name: String,
        #[serde(default)]
        draft: bool,
        #[serde(default)]
        prerelease: bool,
        #[serde(default)]
        assets: Vec<Asset>,
    }
    let rel: Rel = serde_json::from_slice(json).ok()?;
    if rel.draft || rel.prerelease {
        return None;
    }
    let prefix = format!("https://github.com/{REPO}/releases/download/");
    let url = |name: &str| {
        rel.assets
            .iter()
            .find(|a| a.name == name && a.browser_download_url.starts_with(&prefix))
            .map(|a| a.browser_download_url.clone())
    };
    Some(Release {
        version: Version::parse(&rel.tag_name)?,
        exe_url: url(EXE_ASSET),
        sig_url: url(SIG_ASSET),
    })
}

/// Lower-case hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes hex (surrounding whitespace allowed).
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().as_bytes();
    if s.len() % 2 != 0 {
        return None;
    }
    s.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// The bytes a release signature covers.
pub fn signed_message(version: Version, exe: &[u8]) -> Vec<u8> {
    let digest = ring::digest::digest(&ring::digest::SHA256, exe);
    format!("unfilter-update\n{version}\n{}\n", to_hex(digest.as_ref())).into_bytes()
}

/// Whether `sig_file` (hex) is a valid signature of `exe` as `version`.
pub fn verify(version: Version, exe: &[u8], sig_file: &[u8], public_key: &[u8]) -> bool {
    let Some(sig) = std::str::from_utf8(sig_file).ok().and_then(from_hex) else {
        return false;
    };
    sig.len() == 64
        && ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
            .verify(&signed_message(version, exe), &sig)
            .is_ok()
}

/// Why an update step failed.
#[derive(Debug)]
pub enum Error {
    /// Network or HTTP failure.
    Network(String),
    /// The release JSON could not be read.
    BadRelease,
    /// The newer release has no exe or no signature attached.
    Unsigned(Version),
    /// The signature does not match.
    BadSignature,
    /// An installed update waits for a restart.
    RestartPending,
    /// Writing the new exe failed.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "ağ hatası ({e})"),
            Self::BadRelease => f.write_str("sürüm bilgisi okunamadı"),
            Self::Unsigned(v) => write!(f, "{v} imzasız yayınlanmış, kurulmadı"),
            Self::BadSignature => f.write_str("imza doğrulanamadı, güncelleme reddedildi"),
            Self::RestartPending => f.write_str("önceki güncelleme yeniden başlatma bekliyor"),
            Self::Io(e) => write!(f, "dosya yazılamadı ({e})"),
        }
    }
}

impl std::error::Error for Error {}

/// Result of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// Nothing newer.
    UpToDate,
    /// A newer, signed release exists.
    Available(Release),
    /// An update is installed and applies on the next launch.
    RestartPending,
}

/// Asks GitHub for the latest release (no elevation needed).
#[cfg(windows)]
pub fn check() -> Result<Check, Error> {
    if apply::restart_pending() {
        return Ok(Check::RestartPending);
    }
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = http::get(&url, "application/vnd.github+json", 1 << 20)?;
    let rel = parse_release(&body).ok_or(Error::BadRelease)?;
    if rel.version <= Version::current() {
        return Ok(Check::UpToDate);
    }
    if rel.exe_url.is_none() || rel.sig_url.is_none() {
        return Err(Error::Unsigned(rel.version));
    }
    Ok(Check::Available(rel))
}

/// Downloads and verifies `rel`, then swaps it in. Needs write access to the
/// exe's folder (administrator for Program Files).
#[cfg(windows)]
pub fn install(rel: &Release) -> Result<(), Error> {
    let (Some(exe_url), Some(sig_url)) = (&rel.exe_url, &rel.sig_url) else {
        return Err(Error::Unsigned(rel.version));
    };
    let sig = http::get(sig_url, "application/octet-stream", 1024)?;
    let exe = http::get(exe_url, "application/octet-stream", MAX_EXE_BYTES)?;
    if !verify(rel.version, &exe, &sig, &PUBLIC_KEY) {
        return Err(Error::BadSignature);
    }
    let target = std::env::current_exe().map_err(Error::Io)?;
    apply::swap(&target, &exe)
}

/// Check and, when a newer signed release exists, install it.
#[cfg(windows)]
pub fn update() -> Result<Check, Error> {
    let found = check()?;
    if let Check::Available(rel) = &found {
        install(rel)?;
    }
    Ok(found)
}

/// The `--update` mode; returns an [`exit`] code.
#[cfg(windows)]
pub fn run_cli() -> u8 {
    match update() {
        Ok(Check::Available(_)) => exit::INSTALLED,
        Ok(Check::UpToDate) => exit::UP_TO_DATE,
        Ok(Check::RestartPending) | Err(Error::RestartPending) => exit::RESTART_PENDING,
        Err(e) => {
            eprintln!("güncelleme: {e}");
            exit::FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    #[test]
    fn versions_parse_and_order() {
        assert_eq!(Version::parse("v1.2.3"), Some(Version(1, 2, 3)));
        assert_eq!(Version::parse("1.10.0-rc.1"), Some(Version(1, 10, 0)));
        assert_eq!(Version::parse("1.2"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse("vX"), None);
        assert!(Version(1, 10, 0) > Version(1, 9, 9));
        assert_eq!(Version::current().to_string(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(to_hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(from_hex(" 00AB10\n"), Some(vec![0, 0xab, 0x10]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }

    fn release_json(tag: &str, prerelease: bool, host: &str) -> String {
        format!(
            r#"{{"tag_name":"{tag}","draft":false,"prerelease":{prerelease},"assets":[
                {{"name":"unfilter.exe","browser_download_url":"https://{host}/{REPO}/releases/download/{tag}/unfilter.exe"}},
                {{"name":"unfilter.exe.sig","browser_download_url":"https://{host}/{REPO}/releases/download/{tag}/unfilter.exe.sig"}},
                {{"name":"notes.txt","browser_download_url":"https://github.com/x"}}]}}"#
        )
    }

    #[test]
    fn release_json_is_parsed() {
        let r = parse_release(release_json("v1.1.0", false, "github.com").as_bytes()).unwrap();
        assert_eq!(r.version, Version(1, 1, 0));
        assert!(r.exe_url.unwrap().ends_with("/v1.1.0/unfilter.exe"));
        assert!(r.sig_url.unwrap().ends_with("/v1.1.0/unfilter.exe.sig"));
    }

    #[test]
    fn prereleases_and_foreign_urls_are_rejected() {
        assert!(parse_release(release_json("v1.1.0", true, "github.com").as_bytes()).is_none());
        let r = parse_release(release_json("v1.1.0", false, "evil.example").as_bytes()).unwrap();
        assert_eq!((r.exe_url, r.sig_url), (None, None));
        assert!(parse_release(b"not json").is_none());
    }

    #[test]
    fn signatures_bind_version_and_bytes() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk = kp.public_key().as_ref();
        let exe = b"MZ fake exe";
        let v = Version(1, 1, 0);
        let sig = to_hex(kp.sign(&signed_message(v, exe)).as_ref());
        assert!(verify(v, exe, sig.as_bytes(), pk));
        // another version (rollback under a newer tag), other bytes, other key
        assert!(!verify(Version(1, 2, 0), exe, sig.as_bytes(), pk));
        assert!(!verify(v, b"MZ evil", sig.as_bytes(), pk));
        assert!(!verify(v, exe, sig.as_bytes(), &[7; 32]));
        assert!(!verify(v, exe, b"zz", pk));
    }
}
