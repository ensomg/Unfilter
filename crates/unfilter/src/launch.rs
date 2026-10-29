//! Double-click start-up: makes the single exe usable with no installer.
//!
//! Started without a mode flag, the exe asks for administrator rights (UAC),
//! extracts its embedded WinDivert files to an admin-only folder, starts the
//! service as a child process tied to this one by a kill-on-close job object
//! (closing the app always stops capture: fail-open), then opens the window and
//! runs the tray. When an installed service already serves the pipe, it only
//! opens the window and the tray; when the app is already running, it only
//! opens the window.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SEM_TIMEOUT, GetLastError, HANDLE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenMutexW, OpenProcessToken, SYNCHRONIZATION_SYNCHRONIZE,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MB_ICONWARNING, MB_OK, MessageBoxW, SW_SHOWNORMAL,
};

/// Names the running app (one tray per session).
const INSTANCE_MUTEX: &str = "Local\\UnfilterApp";

#[cfg(embedded_windivert)]
const WINDIVERT_DLL: &[u8] = include_bytes!("../../../assets/windivert/WinDivert.dll");
#[cfg(embedded_windivert)]
const WINDIVERT_SYS: &[u8] = include_bytes!("../../../assets/windivert/WinDivert64.sys");

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Show a warning dialog (the exe has no console).
fn message(text: &str) {
    let text = wide(text);
    let title = wide("Unfilter");
    // SAFETY: both strings are NUL-terminated UTF-16 buffers alive for the call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONWARNING,
        );
    }
}

/// Whether this process runs with an elevated (administrator) token.
fn is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle from `GetCurrentProcess` is always valid;
    // `token` receives a handle we close below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: `token` is open with TOKEN_QUERY; the buffer is a TOKEN_ELEVATION
    // of the size we pass.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: `token` was opened above and is closed exactly once.
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Re-run this exe elevated (UAC prompt). `false` if it could not be started
/// (e.g. the user declined).
fn relaunch_elevated() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    // SAFETY: all strings are NUL-terminated UTF-16 buffers alive for the call;
    // null parameters/directory are allowed.
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    r as isize > 32
}

/// Whether the app is already running in this session.
fn instance_exists() -> bool {
    let name = wide(INSTANCE_MUTEX);
    // SAFETY: `name` is a NUL-terminated UTF-16 string alive for the call.
    let h = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr()) };
    if !h.is_null() {
        // SAFETY: `h` was just opened and is closed exactly once.
        unsafe { CloseHandle(h) };
        return true;
    }
    // An elevated instance's mutex may deny a non-elevated opener: still there.
    // SAFETY: thread-local last-error right after the failed call.
    unsafe { GetLastError() == ERROR_ACCESS_DENIED }
}

/// Claim the single-instance mutex for this process's lifetime (the handle is
/// intentionally never closed). `false` if another instance got there first.
fn claim_instance() -> bool {
    let name = wide(INSTANCE_MUTEX);
    // SAFETY: `name` is a NUL-terminated UTF-16 string; a null security
    // descriptor means the default.
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    // SAFETY: thread-local last-error right after the call.
    !h.is_null() && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
}

/// Whether a service is serving the control pipe (installed or ours).
fn service_running() -> bool {
    let name = wide(uf_ipc::PIPE_NAME);
    // SAFETY: `name` is a NUL-terminated UTF-16 string alive for the call.
    if unsafe { WaitNamedPipeW(name.as_ptr(), 1) } != 0 {
        return true;
    }
    // Every instance busy (a client connected) still means it exists.
    // SAFETY: thread-local last-error right after the failed call.
    unsafe { GetLastError() == ERROR_SEM_TIMEOUT }
}

/// A job that kills its processes when its last handle closes: the handle is
/// held for this process's lifetime, so the service child dies with us.
fn kill_on_close_job() -> Option<HANDLE> {
    // SAFETY: null attributes and name create an anonymous job.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return None;
    }
    // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is valid.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `job` is open; the buffer has exactly the size we pass.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    (ok != 0).then_some(job)
}

fn spawn(args: &[&str]) -> Option<Child> {
    let exe = std::env::current_exe().ok()?;
    Command::new(exe).args(args).spawn().ok()
}

/// Start the service child and tie it to this process.
fn spawn_service() -> bool {
    use std::os::windows::io::AsRawHandle;
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    // The exe has no console: keep the service's diagnostics in a log file.
    let log = std::env::var_os("ProgramData").and_then(|d| {
        let dir = PathBuf::from(d).join("Unfilter");
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::File::create(dir.join("service.log")).ok()
    });
    let mut cmd = Command::new(exe);
    cmd.args(["--service", "--connect"]);
    if let Some(log) = log {
        cmd.stderr(log);
    }
    let Ok(child) = cmd.spawn() else {
        return false;
    };
    if let Some(job) = kill_on_close_job() {
        // SAFETY: `job` is open and `child`'s handle is a live process handle.
        unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) };
    }
    // Wait (≤ 10 s) for the pipe; it binds right after the config loads.
    for _ in 0..100 {
        if service_running() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Where the embedded WinDivert files go: Program Files, which only
/// administrators can write, so nobody can plant a DLL the service loads.
#[cfg(embedded_windivert)]
fn windivert_dir() -> Option<PathBuf> {
    let base = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles"))?;
    Some(PathBuf::from(base).join("Unfilter"))
}

/// Make WinDivert loadable for the service: use the copy beside the exe when
/// present (installer layout), else extract the embedded one.
pub fn prepare_windivert() {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("WinDivert.dll")));
    if !beside.is_some_and(|p| p.is_file()) {
        extract_embedded();
    }
}

/// Extract the embedded WinDivert files (when this build has them).
#[cfg(embedded_windivert)]
fn extract_embedded() {
    let Some(dir) = windivert_dir() else {
        return;
    };
    let write = |name: &str, bytes: &[u8]| -> std::io::Result<()> {
        let path = dir.join(name);
        if std::fs::read(&path).is_ok_and(|cur| cur == bytes) {
            return Ok(());
        }
        std::fs::write(path, bytes)
    };
    // Use the folder even if a rewrite failed (e.g. the driver has the .sys
    // open): an identical copy from an earlier run is already there.
    let _ = std::fs::create_dir_all(&dir)
        .and_then(|()| write("WinDivert.dll", WINDIVERT_DLL))
        .and_then(|()| write("WinDivert64.sys", WINDIVERT_SYS));
    uf_capture::windivert::set_dll_dir(dir);
}

#[cfg(not(embedded_windivert))]
fn extract_embedded() {}

/// The no-flag start-up. Returns once the tray exits.
pub fn run_app() {
    if instance_exists() {
        // Already running: just bring up the window.
        let _ = spawn(&["--ui"]);
        return;
    }
    let need_service = !service_running();
    if need_service && !is_elevated() {
        if !relaunch_elevated() {
            message(
                "Unfilter'ın trafiği düzenleyebilmesi için yönetici izni gerekiyor.\n\
                 Lütfen tekrar açıp izin isteğine \"Evet\" deyin.",
            );
        }
        return;
    }
    if !claim_instance() {
        let _ = spawn(&["--ui"]);
        return;
    }
    if need_service && !spawn_service() {
        message(
            "Unfilter servisi başlatılamadı. Ayrıntılar:\n%ProgramData%\\Unfilter\\service.log",
        );
    }
    let _ = spawn(&["--ui"]);
    if is_elevated() {
        auto_update();
    }
    uf_tray::run();
}

/// Elevated app: install signed releases in the background (they apply on the
/// next launch). Checks shortly after start-up, then twice a day.
fn auto_update() {
    uf_update::apply::cleanup();
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(30));
        loop {
            if let Err(e) = uf_update::update() {
                eprintln!("güncelleme: {e}");
            }
            std::thread::sleep(Duration::from_secs(12 * 3600));
        }
    });
}
