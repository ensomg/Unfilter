//! Win32 side of the tray. All `unsafe` here is direct Win32 calls on the
//! window thread with arguments valid for the duration of each call.
#![allow(unsafe_code)]

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use uf_ipc::PIPE_NAME;
use uf_ipc::pipe::{LinkEvent, ServiceLink};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION,
    NIN_SELECT, NINF_KEY, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, FindWindowW, GetCursorPos, GetMessageW, GetSystemMetrics, HICON, IMAGE_ICON,
    IsIconic, LR_DEFAULTCOLOR, LoadImageW, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, PostMessageW,
    PostQuitMessage, RegisterClassExW, RegisterWindowMessageW, SM_CXSMICON, SM_CYSMICON,
    SW_RESTORE, SetForegroundWindow, SetMenuDefaultItem, ShowWindow, TPM_NONOTIFY, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_CONTEXTMENU, WM_DESTROY,
    WM_LBUTTONDBLCLK, WM_NULL, WNDCLASSEXW, WS_OVERLAPPED,
};

use crate::menu::{self, Cmd, Snapshot, TrayState};

/// Shell callback for our icon.
const WM_TRAY: u32 = WM_APP + 1;
/// Posted by the link threads when the snapshot changed.
const WM_APP_STATE: u32 = WM_APP + 2;
const TRAY_UID: u32 = 1;
/// `NIN_KEYSELECT` (not exported by windows-sys 0.59).
const NIN_KEYSELECT: u32 = NIN_SELECT | NINF_KEY;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct App {
    hwnd: HWND,
    link: ServiceLink,
    snapshot: Arc<Mutex<Snapshot>>,
    shown: Snapshot,
    icons: [HICON; 5],
    taskbar_created: u32,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

fn load_icon(id: u16) -> HICON {
    // SAFETY: resource ids come from uf-tray.rc (MAKEINTRESOURCE); null module = this exe.
    unsafe {
        LoadImageW(
            GetModuleHandleW(std::ptr::null()),
            id as usize as *const u16,
            IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON),
            GetSystemMetrics(SM_CYSMICON),
            LR_DEFAULTCOLOR,
        )
    }
}

fn icon_index(s: TrayState) -> usize {
    match s {
        TrayState::Offline => 0,
        TrayState::Ready => 1,
        TrayState::Scanning => 2,
        TrayState::Connected => 3,
        TrayState::Fault => 4,
    }
}

fn notify_data(app: &App) -> NOTIFYICONDATAW {
    // SAFETY: NOTIFYICONDATAW is a plain C struct; zero is a valid initial state.
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = app.hwnd;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = app.icons[icon_index(app.shown.state)];
    let tip: Vec<u16> = menu::tooltip(&app.shown).encode_utf16().collect();
    nid.szTip[..tip.len()].copy_from_slice(&tip);
    nid
}

fn add_icon(app: &App) {
    let mut nid = notify_data(app);
    // SAFETY: `nid` is fully initialised and lives across the calls.
    unsafe {
        Shell_NotifyIconW(NIM_ADD, &nid);
        nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
}

fn update_icon(app: &App) {
    let nid = notify_data(app);
    // SAFETY: as above.
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
}

fn remove_icon(app: &App) {
    let nid = notify_data(app);
    // SAFETY: as above.
    unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
}

/// Brings an open uf-ui window forward, or starts `uf-ui.exe` next to us.
fn open_ui() {
    // winit's default window class + our window title.
    let (class, title) = (wide("Window Class"), wide("Unfilter"));
    // SAFETY: NUL-terminated strings.
    let existing = unsafe { FindWindowW(class.as_ptr(), title.as_ptr()) };
    if !existing.is_null() {
        // SAFETY: `existing` is a window handle just returned by FindWindowW.
        unsafe {
            if IsIconic(existing) != 0 {
                ShowWindow(existing, SW_RESTORE);
            }
            SetForegroundWindow(existing);
        }
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe.with_file_name("uf-ui.exe")).spawn();
    }
}

fn show_menu(app: &App) {
    // SAFETY: the menu is created, tracked and destroyed on this thread; strings
    // outlive AppendMenuW (it copies them).
    unsafe {
        let hmenu = CreatePopupMenu();
        if hmenu.is_null() {
            return;
        }
        for entry in menu::menu(app.shown.state) {
            match entry {
                None => {
                    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
                }
                Some((cmd, label, enabled)) => {
                    let w = wide(label);
                    let flags = if enabled {
                        MF_STRING
                    } else {
                        MF_STRING | MF_GRAYED
                    };
                    AppendMenuW(hmenu, flags, cmd as usize, w.as_ptr());
                }
            }
        }
        SetMenuDefaultItem(hmenu, Cmd::OpenUi as u32, 0);
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        // Required so the menu closes when the user clicks elsewhere.
        SetForegroundWindow(app.hwnd);
        let id = TrackPopupMenu(
            hmenu,
            TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
            pt.x,
            pt.y,
            0,
            app.hwnd,
            std::ptr::null(),
        );
        PostMessageW(app.hwnd, WM_NULL, 0, 0);
        DestroyMenu(hmenu);
        if let Some(cmd) = u16::try_from(id).ok().and_then(Cmd::from_id) {
            run_command(app, cmd);
        }
    }
}

fn run_command(app: &App, cmd: Cmd) {
    if let Some(req) = cmd.request() {
        let _ = app.link.send(req);
        return;
    }
    match cmd {
        Cmd::OpenUi => open_ui(),
        Cmd::Exit => {
            // SAFETY: our own window, on its thread.
            unsafe { DestroyWindow(app.hwnd) };
        }
        Cmd::Connect | Cmd::Disconnect => {}
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let handled = APP.with(|cell| {
        let Ok(mut guard) = cell.try_borrow_mut() else {
            return false;
        };
        let Some(app) = guard.as_mut() else {
            return false;
        };
        match msg {
            WM_TRAY => {
                // NOTIFYICON_VERSION_4: LOWORD(lParam) is the event.
                match (lparam & 0xffff) as u32 {
                    WM_CONTEXTMENU => show_menu(app),
                    NIN_SELECT | NIN_KEYSELECT | WM_LBUTTONDBLCLK => open_ui(),
                    _ => {}
                }
                true
            }
            WM_APP_STATE => {
                let snap = app.snapshot.lock().map(|s| s.clone()).unwrap_or_default();
                if snap != app.shown {
                    app.shown = snap;
                    update_icon(app);
                }
                true
            }
            WM_DESTROY => {
                remove_icon(app);
                // SAFETY: no preconditions.
                unsafe { PostQuitMessage(0) };
                true
            }
            m if m == app.taskbar_created && m != 0 => {
                add_icon(app); // Explorer restarted
                true
            }
            _ => false,
        }
    });
    if handled {
        0
    } else {
        // SAFETY: forwarding the message we were given.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }
}

/// Entry point: single instance, window, icon, link, message loop.
pub fn run() {
    // SAFETY: plain Win32 calls with valid, NUL-terminated arguments.
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let mutex_name = wide("Local\\UnfilterTray");
        let mutex = CreateMutexW(std::ptr::null(), 1, mutex_name.as_ptr());
        if mutex.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
            return; // another tray already runs in this session
        }
        // The mutex handle is intentionally kept open for the process lifetime.
    }

    let class = wide("UnfilterTrayWindow");
    // SAFETY: class/title strings outlive registration and creation.
    let hwnd = unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        if RegisterClassExW(&wc) == 0 {
            return;
        }
        let title = wide("UnfilterTray");
        // A hidden top-level window (not HWND_MESSAGE) so it receives the
        // broadcast "TaskbarCreated" after an Explorer restart.
        CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return;
    }
    let taskbar_created = {
        let w = wide("TaskbarCreated");
        // SAFETY: NUL-terminated string.
        unsafe { RegisterWindowMessageW(w.as_ptr()) }
    };

    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
    let link = {
        let snapshot = Arc::clone(&snapshot);
        let hwnd_bits = hwnd as isize;
        ServiceLink::spawn(PIPE_NAME, move |ev| {
            let changed = match snapshot.lock() {
                Ok(mut s) => match &ev {
                    LinkEvent::Message(m) => s.apply(m),
                    LinkEvent::Offline(_) => {
                        let was = s.state;
                        *s = Snapshot::default();
                        was != TrayState::Offline
                    }
                    // GetStatus is already in flight; its reply updates the icon.
                    LinkEvent::Connected => false,
                },
                Err(_) => false,
            };
            if changed {
                // SAFETY: posting to our window from another thread is allowed;
                // a stale handle after exit just makes the call fail.
                unsafe { PostMessageW(hwnd_bits as HWND, WM_APP_STATE, 0, 0) };
            }
        })
    };

    let icons = [
        TrayState::Offline,
        TrayState::Ready,
        TrayState::Scanning,
        TrayState::Connected,
        TrayState::Fault,
    ]
    .map(|s| load_icon(menu::icon_for(s)));
    let app = App {
        hwnd,
        link,
        snapshot,
        shown: Snapshot::default(),
        icons,
        taskbar_created,
    };
    add_icon(&app);
    APP.with(|cell| *cell.borrow_mut() = Some(app));

    // SAFETY: standard message loop on the thread that owns the window.
    unsafe {
        // SAFETY: MSG is a plain C struct; zero is a valid initial state.
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    APP.with(|cell| cell.borrow_mut().take());
}
