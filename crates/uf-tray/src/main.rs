//! Always-on tray process: pure Win32 (`Shell_NotifyIconW` + hidden window),
//! no GUI toolkit (ADR 004). Service talk runs on `ServiceLink` worker threads
//! that post `WM_APP_STATE` to the window thread; nothing polls.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod menu;
#[cfg(windows)]
mod tray;

#[cfg(windows)]
fn main() {
    tray::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("uf-tray only runs on Windows");
}
