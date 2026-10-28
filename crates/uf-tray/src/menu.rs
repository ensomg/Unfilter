//! Pure tray logic: state → icon / tooltip / menu, menu id → action.

use uf_ipc::{ConnState, Request, ResponsePayload, ServerMessage, Status};

/// What the tray shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrayState {
    /// Service not reachable.
    #[default]
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

impl From<ConnState> for TrayState {
    fn from(s: ConnState) -> Self {
        match s {
            ConnState::Ready => Self::Ready,
            ConnState::Scanning => Self::Scanning,
            ConnState::Connected => Self::Connected,
            ConnState::Fault => Self::Fault,
        }
    }
}

/// Latest service snapshot as the tray sees it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    /// Tray state.
    pub state: TrayState,
    /// Active strategy, if any.
    pub strategy: Option<String>,
}

impl Snapshot {
    fn from_status(st: &Status) -> Self {
        Self {
            state: st.state.into(),
            strategy: st.strategy.clone(),
        }
    }

    /// Applies a service message; returns `true` if the snapshot changed.
    pub fn apply(&mut self, msg: &ServerMessage) -> bool {
        let next = match msg {
            ServerMessage::Response {
                payload: ResponsePayload::Status { status },
                ..
            } => Self::from_status(status),
            ServerMessage::Event {
                event: uf_ipc::Event::Status { status },
            } => Self::from_status(status),
            _ => return false,
        };
        let changed = *self != next;
        *self = next;
        changed
    }
}

/// Resource ids in `uf-tray.rc`.
pub mod icon {
    // id 1 is the app icon (Explorer); not loaded at runtime.
    /// Offline glyph.
    pub const OFFLINE: u16 = 101;
    /// Ready glyph.
    pub const READY: u16 = 102;
    /// Scanning glyph.
    pub const SCANNING: u16 = 103;
    /// Connected glyph.
    pub const CONNECTED: u16 = 104;
    /// Fault glyph.
    pub const FAULT: u16 = 105;
}

/// Icon resource for a state.
pub fn icon_for(state: TrayState) -> u16 {
    match state {
        TrayState::Offline => icon::OFFLINE,
        TrayState::Ready => icon::READY,
        TrayState::Scanning => icon::SCANNING,
        TrayState::Connected => icon::CONNECTED,
        TrayState::Fault => icon::FAULT,
    }
}

/// Max tooltip length in UTF-16 units including the NUL (`NOTIFYICONDATAW::szTip`).
pub const TIP_CAP: usize = 128;

/// Tooltip text, truncated to fit [`TIP_CAP`].
pub fn tooltip(s: &Snapshot) -> String {
    let text = match (s.state, s.strategy.as_deref()) {
        (TrayState::Offline, _) => "Unfilter — servis çalışmıyor".to_owned(),
        (TrayState::Ready, _) => "Unfilter — Hazır".to_owned(),
        (TrayState::Scanning, _) => "Unfilter — Taranıyor…".to_owned(),
        (TrayState::Connected, Some(m)) => format!("Unfilter — Bağlı ({m})"),
        (TrayState::Connected, None) => "Unfilter — Bağlı".to_owned(),
        (TrayState::Fault, _) => "Unfilter — Hata: Onar'ı deneyin".to_owned(),
    };
    let mut out = String::new();
    let mut units = 0;
    for c in text.chars() {
        units += c.len_utf16();
        if units > TIP_CAP - 1 {
            break;
        }
        out.push(c);
    }
    out
}

/// Context menu command ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Cmd {
    /// Bağlan.
    Connect = 1,
    /// Bağlantıyı kes.
    Disconnect = 2,
    /// Arayüzü aç.
    OpenUi = 3,
    /// Çıkış.
    Exit = 4,
}

impl Cmd {
    /// Parses a `WM_COMMAND` id.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Connect),
            2 => Some(Self::Disconnect),
            3 => Some(Self::OpenUi),
            4 => Some(Self::Exit),
            _ => None,
        }
    }

    /// The service request this command sends, if any.
    pub fn request(self) -> Option<Request> {
        match self {
            Self::Connect => Some(Request::Connect),
            Self::Disconnect => Some(Request::Disconnect),
            Self::OpenUi | Self::Exit => None,
        }
    }
}

/// One context menu entry: `None` is a separator.
pub type MenuEntry = Option<(Cmd, &'static str, bool /* enabled */)>;

/// The context menu for a state (top to bottom).
pub fn menu(state: TrayState) -> Vec<MenuEntry> {
    let (connect, disconnect) = match state {
        TrayState::Offline => (false, false),
        TrayState::Ready | TrayState::Fault => (true, false),
        TrayState::Scanning | TrayState::Connected => (false, true),
    };
    vec![
        Some((Cmd::Connect, "Bağlan", connect)),
        Some((Cmd::Disconnect, "Bağlantıyı kes", disconnect)),
        None,
        Some((Cmd::OpenUi, "Arayüzü aç", true)),
        None,
        Some((Cmd::Exit, "Çıkış", true)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use uf_ipc::{Event, Mode};

    fn status(state: ConnState, strategy: Option<&str>) -> Status {
        Status {
            state,
            strategy: strategy.map(Into::into),
            added_latency_us: 0,
            mode: Mode::Normal,
        }
    }

    fn enabled(state: TrayState, cmd: Cmd) -> bool {
        menu(state)
            .into_iter()
            .flatten()
            .find(|(c, _, _)| *c == cmd)
            .map(|(_, _, e)| e)
            .unwrap()
    }

    #[test]
    fn menu_enables_the_right_action() {
        assert!(enabled(TrayState::Ready, Cmd::Connect));
        assert!(!enabled(TrayState::Ready, Cmd::Disconnect));
        assert!(enabled(TrayState::Fault, Cmd::Connect));
        assert!(!enabled(TrayState::Connected, Cmd::Connect));
        assert!(enabled(TrayState::Connected, Cmd::Disconnect));
        assert!(enabled(TrayState::Scanning, Cmd::Disconnect));
        assert!(!enabled(TrayState::Offline, Cmd::Connect));
        assert!(!enabled(TrayState::Offline, Cmd::Disconnect));
        for s in [TrayState::Offline, TrayState::Connected] {
            assert!(enabled(s, Cmd::OpenUi) && enabled(s, Cmd::Exit));
        }
    }

    #[test]
    fn menu_labels_and_order() {
        let labels: Vec<_> = menu(TrayState::Ready)
            .into_iter()
            .map(|e| e.map(|(_, l, _)| l))
            .collect();
        assert_eq!(
            labels,
            vec![
                Some("Bağlan"),
                Some("Bağlantıyı kes"),
                None,
                Some("Arayüzü aç"),
                None,
                Some("Çıkış")
            ]
        );
    }

    #[test]
    fn command_ids_roundtrip() {
        for c in [Cmd::Connect, Cmd::Disconnect, Cmd::OpenUi, Cmd::Exit] {
            assert_eq!(Cmd::from_id(c as u16), Some(c));
        }
        assert_eq!(Cmd::from_id(0), None);
        assert_eq!(Cmd::Connect.request(), Some(Request::Connect));
        assert_eq!(Cmd::Exit.request(), None);
    }

    #[test]
    fn icons_are_distinct_per_state() {
        let ids: std::collections::HashSet<_> = [
            TrayState::Offline,
            TrayState::Ready,
            TrayState::Scanning,
            TrayState::Connected,
            TrayState::Fault,
        ]
        .into_iter()
        .map(icon_for)
        .collect();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn tooltip_text_and_cap() {
        let s = Snapshot {
            state: TrayState::Connected,
            strategy: Some("split+disorder".into()),
        };
        assert_eq!(tooltip(&s), "Unfilter — Bağlı (split+disorder)");
        assert_eq!(
            tooltip(&Snapshot::default()),
            "Unfilter — servis çalışmıyor"
        );
        let long = Snapshot {
            state: TrayState::Connected,
            strategy: Some("x".repeat(500)),
        };
        assert!(tooltip(&long).encode_utf16().count() < TIP_CAP);
    }

    #[test]
    fn snapshot_tracks_status_messages() {
        let mut snap = Snapshot::default();
        let ev = ServerMessage::Event {
            event: Event::Status {
                status: status(ConnState::Scanning, None),
            },
        };
        assert!(snap.apply(&ev));
        assert_eq!(snap.state, TrayState::Scanning);
        assert!(!snap.apply(&ev), "same status is not a change");
        let resp = ServerMessage::Response {
            id: 3,
            payload: ResponsePayload::Status {
                status: status(ConnState::Connected, Some("fake ttl=4")),
            },
        };
        assert!(snap.apply(&resp));
        assert_eq!(snap.strategy.as_deref(), Some("fake ttl=4"));
        let log = ServerMessage::Event {
            event: Event::Log {
                time: String::new(),
                host: String::new(),
                method: String::new(),
                outcome: String::new(),
            },
        };
        assert!(!snap.apply(&log));
        assert_eq!(snap.state, TrayState::Connected);
    }
}
