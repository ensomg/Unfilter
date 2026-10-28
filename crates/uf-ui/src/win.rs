//! Win32 window cosmetics: DWM dark title bar (ADR 004) and the embedded icon.
#![allow(unsafe_code)]

use std::ffi::c_void;

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Graphics::Dwm::{
    DWMWA_CAPTION_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR, LoadImageW, SM_CXICON,
    SM_CXSMICON, SM_CYICON, SM_CYSMICON, SendMessageW, WM_SETICON,
};

/// `#101114` as a COLORREF (0x00BBGGRR).
const CAPTION_BG: u32 = 0x0014_1110;

fn hwnd_of(window: &slint::Window) -> Option<HWND> {
    let handle = window.window_handle();
    let raw = handle.window_handle().ok()?.as_raw();
    match raw {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get() as HWND),
        _ => None,
    }
}

/// Applies the dark title bar, caption colour and window icon. Returns
/// `false` while the native window does not exist yet (call again later).
pub fn style_window(window: &slint::Window) -> bool {
    let Some(hwnd) = hwnd_of(window) else {
        return false;
    };
    let dark: i32 = 1;
    // SAFETY: valid HWND of our own window; pointer/size describe a live i32.
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as _,
            (&raw const dark).cast::<c_void>(),
            size_of::<i32>() as u32,
        );
    }
    // Windows 11 only; older systems ignore it (returns an error we don't need).
    let caption = CAPTION_BG;
    // SAFETY: as above, with a live u32.
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR as _,
            (&raw const caption).cast::<c_void>(),
            size_of::<u32>() as u32,
        );
    }
    // SAFETY: null module name = this executable; resource id 1 is the icon from
    // uf-ui.rc (MAKEINTRESOURCE). The icons live for the whole process.
    unsafe {
        let module = GetModuleHandleW(std::ptr::null());
        for (which, cx, cy) in [
            (ICON_BIG, SM_CXICON, SM_CYICON),
            (ICON_SMALL, SM_CXSMICON, SM_CYSMICON),
        ] {
            let icon = LoadImageW(
                module,
                1 as _,
                IMAGE_ICON,
                GetSystemMetrics(cx),
                GetSystemMetrics(cy),
                LR_DEFAULTCOLOR,
            );
            if !icon.is_null() {
                SendMessageW(hwnd, WM_SETICON, which as usize, icon as isize);
            }
        }
    }
    true
}
