//! Unfilter's single executable. One binary runs in three modes, chosen by a
//! command-line flag, so the installer ships and signs exactly one file:
//!
//! - `--service` : the privileged background that serves the control-plane pipe.
//! - `--tray`    : the always-on notification-area icon (installer autostart).
//! - `--ui`      : the settings/status window (launched by the tray on demand).
//! - no flag     : double-click start-up ([`launch`]): elevate, start the
//!   service as a tied child process, open the window and run the tray.
//!
//! Each mode owns its own event/message loop and runs as its own process (the
//! Slint UI needs the main thread; the tray runs its own Win32 loop), so the
//! tray opens the UI by re-executing this same binary with `--ui`.
#![cfg_attr(not(test), windows_subsystem = "windows")]

use std::process::ExitCode;

#[cfg(windows)]
mod launch;

/// Which mode this process runs in.
enum Mode {
    Service,
    Ui,
    Tray,
    App,
}

/// First recognised flag wins; with none, run the double-click start-up.
fn mode_from_args() -> Mode {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--service" => return Mode::Service,
            "--ui" => return Mode::Ui,
            "--tray" => return Mode::Tray,
            _ => {}
        }
    }
    Mode::App
}

fn main() -> ExitCode {
    match mode_from_args() {
        Mode::Service => {
            #[cfg(windows)]
            launch::prepare_windivert();
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
        Mode::App => {
            #[cfg(windows)]
            launch::run_app();
            #[cfg(not(windows))]
            uf_tray::run();
            ExitCode::SUCCESS
        }
    }
}
