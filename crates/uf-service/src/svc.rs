//! The Windows service wrapper: registers with the Service Control Manager
//! (`StartServiceCtrlDispatcherW`), reports Running, and stops on
//! Stop/Shutdown. When the process was not started by the SCM (run from a
//! console for development), the dispatcher call fails with
//! `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` and the service body simply runs
//! in the foreground instead.
//!
//! Stopping is deliberately blunt: report StopPending, then Stopped, then exit
//! the process. Exiting closes every WinDivert handle, which removes the
//! driver filters (fail-open), so no orderly teardown is needed for safety.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::{
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, GetLastError, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

/// The installed service name (`installer/unfilter.iss`, `ServiceName`).
pub const SERVICE_NAME: &str = "Unfilter";

/// The service body, run on the SCM's service thread (or in the foreground).
static BODY: OnceLock<fn()> = OnceLock::new();
/// The status handle from `RegisterServiceCtrlHandlerExW`.
static STATUS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn report(state: u32, wait_hint_ms: u32) {
    let handle = STATUS.load(Ordering::Acquire);
    if handle.is_null() {
        return;
    }
    let accepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    // SAFETY: `handle` came from `RegisterServiceCtrlHandlerExW` and stays
    // valid for the life of the process; `status` is a fully initialised
    // struct that outlives the call.
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 3000);
            report(SERVICE_STOPPED, 0);
            // Closing the process closes the WinDivert handles (fail-open).
            std::process::exit(0);
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => NO_ERROR,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(SERVICE_NAME);
    // SAFETY: `name` is a NUL-terminated UTF-16 string alive for the call;
    // the handler is a valid `extern "system"` fn with the expected signature.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), std::ptr::null())
    };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle, Ordering::Release);
    report(SERVICE_START_PENDING, 5000);
    report(SERVICE_RUNNING, 0);
    if let Some(body) = BODY.get() {
        body();
    }
    report(SERVICE_STOPPED, 0);
}

/// Run `body` as the Windows service when started by the SCM, otherwise in the
/// foreground (console/development).
pub fn dispatch(body: fn()) {
    let _ = BODY.set(body);
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` is a NULL-terminated array of valid entries whose name
    // buffer outlives the call (it blocks until the service stops).
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        // SAFETY: plain thread-local error query right after the failed call.
        let err = unsafe { GetLastError() };
        if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            body(); // not started by the SCM: run in the foreground
        } else {
            eprintln!("uf-service: SCM dispatcher hatası (os code {err})");
        }
    }
}
