//! Pure mapping from service state to what the main screen shows (Turkish
//! copy from the mockup). No slint types, so it is unit-tested directly.

use uf_ipc::{BlockKind, ConnState, Mode, ProtocolError, Request, SiteTest, Status};

/// Visual style of the status ring / title.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visual {
    /// Service unreachable.
    Offline,
    /// HAZIR.
    Ready,
    /// TARANIYOR.
    Scanning,
    /// BAĞLI.
    Connected,
    /// Driver/service fault.
    Fault,
}

/// Why the UI is offline (mirrors `uf_ipc::pipe::OfflineReason` without
/// depending on the Windows-only type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offline {
    /// Service not running / pipe missing.
    NotRunning,
    /// Connection dropped.
    Lost,
    /// Protocol version mismatch (service version).
    Incompatible(u32),
}

/// Connection phase as the UI sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conn {
    /// Not connected to the service.
    Offline(Offline),
    /// Connected, waiting for the first status snapshot.
    Waiting,
    /// Connected with a status snapshot.
    Online(Status),
}

/// Everything the main screen shows for a [`Conn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewModel {
    /// Ring/title style.
    pub visual: Visual,
    /// Big status word.
    pub title: &'static str,
    /// Line under the title.
    pub subtitle: String,
    /// Primary button label.
    pub button: &'static str,
    /// Primary button uses the outlined "active" style.
    pub button_outline: bool,
    /// Primary button clickable.
    pub button_enabled: bool,
    /// Game mode selected.
    pub game_mode: bool,
    /// Mode switch, Onar, Yeniden tara, Test et usable.
    pub controls_enabled: bool,
}

/// `350 µs` → `"0.4 ms"`.
pub fn format_latency(us: u32) -> String {
    // round half up in integer tenths of a millisecond (no float surprises)
    let tenths = (u64::from(us) + 50) / 100;
    format!("{}.{} ms", tenths / 10, tenths % 10)
}

/// Label used in the subtitle (`"… · Oyun Mod"`, as in the mockup).
pub fn mode_word(mode: Mode) -> &'static str {
    match mode {
        Mode::Normal => "Normal",
        Mode::Game => "Oyun",
    }
}

/// Builds the main-screen view model.
pub fn view_for(conn: &Conn) -> ViewModel {
    match conn {
        Conn::Offline(why) => ViewModel {
            visual: Visual::Offline,
            title: "SERVİS YOK",
            subtitle: match why {
                Offline::NotRunning => "Unfilter servisi çalışmıyor. Yeniden deneniyor…".into(),
                Offline::Lost => "Servis bağlantısı koptu. Yeniden bağlanılıyor…".into(),
                Offline::Incompatible(v) => {
                    format!("Servis sürümü uyumsuz (protokol {v}). Unfilter'ı güncelleyin.")
                }
            },
            button: "BAĞLAN",
            button_outline: false,
            button_enabled: false,
            game_mode: false,
            controls_enabled: false,
        },
        Conn::Waiting => ViewModel {
            visual: Visual::Ready,
            title: "HAZIR",
            subtitle: "Durum alınıyor…".into(),
            button: "BAĞLAN",
            button_outline: false,
            button_enabled: false,
            game_mode: false,
            controls_enabled: false,
        },
        Conn::Online(st) => {
            let game_mode = st.mode == Mode::Game;
            let base = ViewModel {
                visual: Visual::Ready,
                title: "HAZIR",
                subtitle: "Engelleri aşmak için bağlan.".into(),
                button: "BAĞLAN",
                button_outline: false,
                button_enabled: true,
                game_mode,
                controls_enabled: true,
            };
            match st.state {
                ConnState::Ready => base,
                ConnState::Scanning => ViewModel {
                    visual: Visual::Scanning,
                    title: "TARANIYOR",
                    subtitle: "Ağına uygun yöntem seçiliyor…".into(),
                    button: "İPTAL",
                    button_outline: true,
                    ..base
                },
                ConnState::Connected => ViewModel {
                    visual: Visual::Connected,
                    title: "BAĞLI",
                    subtitle: format!(
                        "{} · {} · {} Mod",
                        st.strategy.as_deref().unwrap_or("otomatik"),
                        format_latency(st.added_latency_us),
                        mode_word(st.mode)
                    ),
                    button: "BAĞLANTIYI KES",
                    button_outline: true,
                    ..base
                },
                ConnState::Fault => ViewModel {
                    visual: Visual::Fault,
                    title: "HATA",
                    subtitle: "Sürücü veya servis sorunu. Onar'ı deneyin.".into(),
                    ..base
                },
            }
        }
    }
}

/// What the primary button sends, if anything.
pub fn primary_request(conn: &Conn) -> Option<Request> {
    match conn {
        Conn::Online(st) => Some(match st.state {
            ConnState::Ready | ConnState::Fault => Request::Connect,
            ConnState::Scanning | ConnState::Connected => Request::Disconnect,
        }),
        _ => None,
    }
}

/// Toast shown when a request is sent (immediate feedback).
pub fn sent_toast(req: &Request) -> Option<&'static str> {
    match req {
        Request::Repair => Some("Sürücü ve ağ ayarları kontrol ediliyor…"),
        Request::Rescan => Some("Ağ yeniden taranıyor…"),
        _ => None,
    }
}

/// Toast for a plain `Ok` response to `req`.
pub fn ok_toast(req: &Request) -> Option<&'static str> {
    match req {
        Request::Repair => Some("Onarım tamamlandı."),
        _ => None,
    }
}

/// Toast for an error response.
pub fn error_toast(err: &ProtocolError) -> &'static str {
    match err {
        ProtocolError::VersionMismatch { .. } => "Servis sürümü uyumsuz.",
        ProtocolError::BadRequest => "Servis isteği reddetti.",
        ProtocolError::NotReady => "Servis henüz hazır değil, biraz sonra deneyin.",
        _ => "Servis bir hata döndürdü.",
    }
}

/// Toast when a request cannot be sent at all.
pub const OFFLINE_TOAST: &str = "Servise ulaşılamıyor.";

/// Whether a log outcome is shown in the success colour.
pub fn log_ok(outcome: &str) -> bool {
    outcome.trim().eq_ignore_ascii_case("ok")
}

/// Maximum log lines kept in the Loglar panel (mockup: 40).
pub const MAX_LOG_LINES: usize = 40;

/// One result row of the site test: (label, value, ok).
pub type TestRow = (String, String, bool);

/// Rows for the site test result, in mockup order DNS → TCP → TLS/SNI → method.
pub fn site_test_rows(t: &SiteTest) -> Vec<TestRow> {
    let dns = match (t.dns_ok, t.block) {
        (true, Some(BlockKind::Dns)) => ("sahte yanıt, DoH ile düzeltildi", true),
        (true, _) => ("çözüldü", true),
        (false, _) => ("çözülemedi", false),
    };
    let tcp = if t.tcp_ok {
        ("bağlandı", true)
    } else if t.block == Some(BlockKind::Ip) {
        ("IP engeli", false)
    } else {
        ("bağlanamadı", false)
    };
    let tls = if t.tls_ok {
        ("el sıkışma tamam", true)
    } else if t.block == Some(BlockKind::Dpi) {
        ("DPI tarafından kesiliyor", false)
    } else {
        ("başarısız", false)
    };
    let mut rows = vec![
        ("DNS".to_owned(), dns.0.to_owned(), dns.1),
        ("TCP".to_owned(), tcp.0.to_owned(), tcp.1),
        ("TLS/SNI".to_owned(), tls.0.to_owned(), tls.1),
    ];
    match &t.via {
        Some(via) => rows.push((format!("Yöntem: {via}"), "açıldı".to_owned(), true)),
        None if t.block.is_some() => {
            rows.push(("Yöntem".to_owned(), "bulunamadı".to_owned(), false));
        }
        None => {}
    }
    rows
}

/// Summary toast after a site test.
pub fn site_test_summary(t: &SiteTest) -> String {
    match t.block {
        None => format!("{}: engel yok", t.host),
        Some(kind) => {
            let kind = match kind {
                BlockKind::Dns => "DNS",
                BlockKind::Dpi => "DPI",
                BlockKind::Ip => "IP",
            };
            format!("{}: engel türü {kind}", t.host)
        }
    }
}

/// Normalises the host typed into the test box: trims, drops a scheme, path
/// and port. `None` if nothing usable remains.
pub fn normalize_host(input: &str) -> Option<String> {
    let s = input.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit_once(':').map_or(s, |(h, p)| {
        if p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            s
        }
    });
    let s = s.trim_end_matches('.').to_ascii_lowercase();
    let valid = !s.is_empty()
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    valid.then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: ConnState) -> Status {
        Status {
            state,
            strategy: Some("split+disorder".into()),
            added_latency_us: 350,
            mode: Mode::Normal,
        }
    }

    #[test]
    fn latency_format() {
        assert_eq!(format_latency(350), "0.4 ms");
        assert_eq!(format_latency(0), "0.0 ms");
        assert_eq!(format_latency(12_345), "12.3 ms");
    }

    #[test]
    fn ready_view_matches_mockup() {
        let v = view_for(&Conn::Online(status(ConnState::Ready)));
        assert_eq!(
            (v.visual, v.title, v.button),
            (Visual::Ready, "HAZIR", "BAĞLAN")
        );
        assert_eq!(v.subtitle, "Engelleri aşmak için bağlan.");
        assert!(v.button_enabled && !v.button_outline && v.controls_enabled);
    }

    #[test]
    fn scanning_view() {
        let v = view_for(&Conn::Online(status(ConnState::Scanning)));
        assert_eq!(
            (v.visual, v.title, v.button),
            (Visual::Scanning, "TARANIYOR", "İPTAL")
        );
        assert!(v.button_outline);
    }

    #[test]
    fn connected_view_shows_strategy_latency_mode() {
        let mut st = status(ConnState::Connected);
        st.mode = Mode::Game;
        let v = view_for(&Conn::Online(st));
        assert_eq!(v.title, "BAĞLI");
        assert_eq!(v.button, "BAĞLANTIYI KES");
        assert_eq!(v.subtitle, "split+disorder · 0.4 ms · Oyun Mod");
        assert!(v.game_mode && v.button_outline);
        let mut st = status(ConnState::Connected);
        st.strategy = None;
        assert!(
            view_for(&Conn::Online(st))
                .subtitle
                .starts_with("otomatik · ")
        );
    }

    #[test]
    fn fault_view_allows_connect() {
        let c = Conn::Online(status(ConnState::Fault));
        let v = view_for(&c);
        assert_eq!((v.visual, v.title), (Visual::Fault, "HATA"));
        assert_eq!(primary_request(&c), Some(Request::Connect));
    }

    #[test]
    fn offline_and_waiting_disable_everything() {
        for c in [
            Conn::Offline(Offline::NotRunning),
            Conn::Offline(Offline::Lost),
            Conn::Offline(Offline::Incompatible(3)),
            Conn::Waiting,
        ] {
            let v = view_for(&c);
            assert!(!v.button_enabled && !v.controls_enabled, "{c:?}");
            assert_eq!(primary_request(&c), None);
        }
        let v = view_for(&Conn::Offline(Offline::Incompatible(3)));
        assert!(v.subtitle.contains("protokol 3"));
        assert_eq!(v.visual, Visual::Offline);
    }

    #[test]
    fn primary_button_toggles() {
        let p = |s| primary_request(&Conn::Online(status(s)));
        assert_eq!(p(ConnState::Ready), Some(Request::Connect));
        assert_eq!(p(ConnState::Scanning), Some(Request::Disconnect));
        assert_eq!(p(ConnState::Connected), Some(Request::Disconnect));
    }

    #[test]
    fn toasts() {
        assert!(sent_toast(&Request::Repair).is_some());
        assert!(sent_toast(&Request::Connect).is_none());
        assert_eq!(ok_toast(&Request::Repair), Some("Onarım tamamlandı."));
        assert!(error_toast(&ProtocolError::NotReady).contains("hazır değil"));
    }

    #[test]
    fn log_outcome_colour() {
        assert!(log_ok("OK") && log_ok(" ok "));
        assert!(!log_ok("fallback") && !log_ok(""));
    }

    fn test(dns_ok: bool, tcp_ok: bool, tls_ok: bool, block: Option<BlockKind>) -> SiteTest {
        SiteTest {
            host: "discord.com".into(),
            dns_ok,
            tcp_ok,
            tls_ok,
            block,
            via: None,
        }
    }

    #[test]
    fn site_test_rows_mockup_case() {
        let mut t = test(true, true, false, Some(BlockKind::Dpi));
        t.via = Some("split+disorder".into());
        let rows = site_test_rows(&t);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0], ("DNS".into(), "çözüldü".into(), true));
        assert_eq!(
            rows[2],
            ("TLS/SNI".into(), "DPI tarafından kesiliyor".into(), false)
        );
        assert_eq!(
            rows[3],
            ("Yöntem: split+disorder".into(), "açıldı".into(), true)
        );
        assert_eq!(site_test_summary(&t), "discord.com: engel türü DPI");
    }

    #[test]
    fn site_test_rows_dns_and_ip() {
        let rows = site_test_rows(&test(true, true, true, Some(BlockKind::Dns)));
        assert_eq!(rows[0].1, "sahte yanıt, DoH ile düzeltildi");
        assert_eq!(rows[3], ("Yöntem".into(), "bulunamadı".into(), false));
        let rows = site_test_rows(&test(true, false, false, Some(BlockKind::Ip)));
        assert_eq!(rows[1].1, "IP engeli");
        let clean = test(true, true, true, None);
        assert_eq!(site_test_rows(&clean).len(), 3);
        assert_eq!(site_test_summary(&clean), "discord.com: engel yok");
    }

    #[test]
    fn host_normalisation() {
        assert_eq!(
            normalize_host(" Discord.com ").as_deref(),
            Some("discord.com")
        );
        assert_eq!(
            normalize_host("https://www.youtube.com/watch?v=1").as_deref(),
            Some("www.youtube.com")
        );
        assert_eq!(normalize_host("x.com:443").as_deref(), Some("x.com"));
        assert_eq!(
            normalize_host("example.org.").as_deref(),
            Some("example.org")
        );
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("bad host"), None);
        assert_eq!(normalize_host("a\"b"), None);
    }
}
