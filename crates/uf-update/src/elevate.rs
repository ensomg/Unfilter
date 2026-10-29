//! Running `--update` with administrator rights from an unelevated process
//! (the window or tray of an installed copy cannot write Program Files).
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// Starts this exe as `--update` through UAC and waits for it. Returns its
/// [`crate::exit`] code, or `None` when it did not start (e.g. UAC declined).
/// Blocks: call it off the UI thread.
pub fn run_update_elevated() -> Option<u8> {
    let exe = std::env::current_exe().ok()?;
    let (verb, file, params) = (
        wide(OsStr::new("runas")),
        wide(exe.as_os_str()),
        wide(OsStr::new("--update")),
    );
    // SAFETY: zero is a valid "unset" value for every SHELLEXECUTEINFOW field.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: `info` is initialised and its strings outlive the call.
    if unsafe { ShellExecuteExW(&raw mut info) } == 0 || info.hProcess.is_null() {
        return None;
    }
    let mut code = u32::from(crate::exit::FAILED);
    // SAFETY: `hProcess` is a live process handle we own (NOCLOSEPROCESS);
    // closed once below.
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &raw mut code);
        CloseHandle(info.hProcess);
    }
    Some(u8::try_from(code).unwrap_or(crate::exit::FAILED))
}
