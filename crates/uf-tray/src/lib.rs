//! Always-on tray process: pure Win32 (`Shell_NotifyIconW` + hidden window),
//! no GUI toolkit (ADR 004). Service talk runs on `ServiceLink` worker threads
//! that post `WM_APP_STATE` to the window thread; nothing polls.
//!
//! This is a library: the single `unfilter` binary runs it in `--tray` mode (the
//! default). The `windows` subsystem is set by that binary, not here.

mod menu;
#[cfg(windows)]
mod tray;

/// Run the always-on tray icon. Returns when the tray is exited.
#[cfg(windows)]
pub fn run() {
    tray::run();
}

/// Non-Windows stub: the tray only runs on Windows.
#[cfg(not(windows))]
pub fn run() {
    eprintln!("uf-tray only runs on Windows");
}
