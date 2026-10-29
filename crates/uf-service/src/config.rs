//! Service configuration: the schema of `config/default.toml` plus the load
//! order (per-user override first, then the installed default, then built-in
//! defaults). Parsing is pure and fully unit-tested; the zero-config promise
//! (§2) means an empty or missing file still yields a working configuration.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Schema version; bumped on a breaking change.
    pub schema: u32,
    /// General behaviour.
    pub general: General,
    /// DNS resolution.
    pub dns: Dns,
    /// Engine / prober.
    pub engine: EngineCfg,
    /// Logging.
    pub logging: Logging,
}

/// General behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    /// Connect automatically when the tray starts.
    pub autostart: bool,
    /// Operating mode.
    pub mode: Mode,
}

/// Operating mode (mirrors [`uf_ipc::Mode`] but is the config's own type so the
/// file format is independent of the wire protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Normal. (`"game"` from older configs is accepted as Normal.)
    #[default]
    #[serde(alias = "game")]
    Normal,
}

impl From<Mode> for uf_ipc::Mode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Normal => uf_ipc::Mode::Normal,
        }
    }
}

/// DNS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dns {
    /// Whether packet-level DNS redirection is on.
    pub enabled: bool,
    /// Trusted upstreams, in preference order.
    pub upstreams: Vec<Upstream>,
    /// Positive/negative cache entry limit.
    pub cache_entries: usize,
}

/// One trusted upstream resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    /// `"doh"` or `"dot"`.
    pub kind: String,
    /// TLS server name (SNI / certificate validation).
    pub host: String,
    /// Pinned bootstrap IP to connect to.
    pub ip: String,
}

/// Engine / prober configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineCfg {
    /// Automatically probe for a working strategy on blocked targets.
    pub auto_probe: bool,
    /// Force a fixed strategy by name; empty means "let the prober choose".
    pub strategy: String,
}

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Logging {
    /// Log level (`"error"`, `"warn"`, `"info"`, `"debug"`).
    pub level: String,
    /// Whether to write logs to disk (off by default for privacy, §5.9).
    pub to_file: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema: 1,
            general: General::default(),
            dns: Dns::default(),
            engine: EngineCfg::default(),
            logging: Logging::default(),
        }
    }
}

impl Default for General {
    fn default() -> Self {
        General {
            autostart: true,
            mode: Mode::Normal,
        }
    }
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            enabled: true,
            upstreams: vec![
                Upstream {
                    kind: "doh".into(),
                    host: "cloudflare-dns.com".into(),
                    ip: "1.1.1.1".into(),
                },
                Upstream {
                    kind: "dot".into(),
                    host: "dns.google".into(),
                    ip: "8.8.8.8".into(),
                },
            ],
            cache_entries: 4096,
        }
    }
}

impl Default for EngineCfg {
    fn default() -> Self {
        EngineCfg {
            auto_probe: true,
            strategy: String::new(),
        }
    }
}

impl Default for Logging {
    fn default() -> Self {
        Logging {
            level: "info".into(),
            to_file: false,
        }
    }
}

impl Config {
    /// Parse a TOML string. An empty string yields the defaults.
    pub fn parse(toml_str: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Load the effective config: the first readable of `user_path` then
    /// `default_path`, falling back to built-in defaults if neither exists or
    /// parses. Never fails — a broken file degrades to defaults (zero-config).
    pub fn load(user_path: &Path, default_path: &Path) -> Config {
        for p in [user_path, default_path] {
            if let Ok(text) = std::fs::read_to_string(p) {
                if let Ok(cfg) = Config::parse(&text) {
                    return cfg;
                }
            }
        }
        Config::default()
    }

    /// Validate semantic constraints, returning the list of problems (empty =
    /// OK). Used by the `Repair` path and tests.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.dns.enabled && self.dns.upstreams.is_empty() {
            out.push("DNS açık ama güvenilir upstream tanımlı değil".into());
        }
        for u in &self.dns.upstreams {
            if u.kind != "doh" && u.kind != "dot" {
                out.push(format!("bilinmeyen upstream türü: {}", u.kind));
            }
            if u.ip.parse::<std::net::IpAddr>().is_err() {
                out.push(format!("geçersiz bootstrap IP: {}", u.ip));
            }
        }
        if self.dns.cache_entries == 0 {
            out.push("DNS cache boyutu sıfır olamaz".into());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_TOML: &str = include_str!("../../../config/default.toml");

    #[test]
    fn empty_is_defaults() {
        let c = Config::parse("").unwrap();
        assert_eq!(c, Config::default());
        assert!(c.problems().is_empty());
    }

    #[test]
    fn shipped_default_toml_parses_and_is_valid() {
        let c = Config::parse(DEFAULT_TOML).unwrap();
        assert_eq!(c.schema, 1);
        assert!(c.general.autostart);
        assert_eq!(c.dns.upstreams.len(), 2);
        assert_eq!(c.dns.upstreams[0].kind, "doh");
        assert!(c.problems().is_empty(), "{:?}", c.problems());
    }

    #[test]
    fn partial_file_fills_gaps_with_defaults() {
        let c = Config::parse("[general]\nmode = \"game\"\n").unwrap();
        assert_eq!(c.general.mode, Mode::Normal); // legacy "game" → Normal
        assert!(c.general.autostart); // default kept
        assert_eq!(c.dns.cache_entries, 4096); // default kept
    }

    #[test]
    fn problems_flag_bad_values() {
        let c = Config::parse(
            "[dns]\nupstreams = [{ kind = \"x\", host = \"h\", ip = \"not-an-ip\" }]\ncache_entries = 0\n",
        )
        .unwrap();
        let p = c.problems();
        assert!(p.iter().any(|s| s.contains("bilinmeyen upstream")));
        assert!(p.iter().any(|s| s.contains("geçersiz bootstrap")));
        assert!(p.iter().any(|s| s.contains("cache")));
    }

    #[test]
    fn load_falls_back_to_defaults_when_missing() {
        let missing = Path::new("does/not/exist/a.toml");
        let c = Config::load(missing, missing);
        assert_eq!(c, Config::default());
    }
}
