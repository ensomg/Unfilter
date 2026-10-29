//! Unfilter's single executable. One binary runs in three modes, chosen by a
//! command-line flag, so the installer ships and signs exactly one file:
//!
//! - `--service` : the privileged background that serves the control-plane pipe.
//! - `--tray`    : the always-on notification-area icon (the default).
//! - `--ui`      : the settings/status window (launched by the tray on demand).
//!
//! Each mode owns its own event/message loop and runs as its own process (the
//! Slint UI needs the main thread; the tray runs its own Win32 loop), so the
//! tray opens the UI by re-executing this same binary with `--ui`.
#![cfg_attr(not(test), windows_subsystem = "windows")]

use std::process::ExitCode;

/// Which mode this process runs in.
enum Mode {
    Service,
    Ui,
    Tray,
}

/// First recognised flag wins; with none, run the tray (the user-facing default
/// used by autostart).
fn mode_from_args() -> Mode {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--service" => return Mode::Service,
            "--ui" => return Mode::Ui,
            "--tray" => return Mode::Tray,
            _ => {}
        }
    }
    Mode::Tray
}

fn main() -> ExitCode {
    match mode_from_args() {
        Mode::Service => {
            uf_service::run();
            ExitCode::SUCCESS
        }
        Mode::Ui => match uf_ui::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("uf-ui hata: {e}");
                ExitCode::FAILURE
            }
        },
        Mode::Tray => {
            uf_tray::run();
            ExitCode::SUCCESS
        }
    }
}
