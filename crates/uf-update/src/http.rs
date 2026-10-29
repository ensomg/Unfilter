//! Minimal HTTPS GET over WinHTTP: system proxy settings, Windows certificate
//! validation and redirects (GitHub serves assets from a CDN host) come free.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_FLAG_SECURE,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
};

use crate::Error;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// An open WinHTTP handle, closed on drop.
struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a non-null handle returned by WinHttpOpen/Connect/OpenRequest,
        // closed exactly once.
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

fn open(p: *mut c_void, what: &str) -> Result<Handle, Error> {
    if p.is_null() {
        Err(Error::Network(format!(
            "{what}: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(Handle(p))
    }
}

fn fail(what: &str) -> Error {
    Error::Network(format!("{what}: {}", std::io::Error::last_os_error()))
}

/// GETs an `https://` URL; the body must be at most `limit` bytes and the
/// final status 200.
pub fn get(url: &str, accept: &str, limit: usize) -> Result<Vec<u8>, Error> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| Error::Network("yalnızca https".into()))?;
    let (host, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_owned()),
    };
    let agent = wide(concat!("Unfilter-Updater/", env!("CARGO_PKG_VERSION")));
    // SAFETY: valid NUL-terminated wide strings; null proxy arguments are
    // allowed. AUTOMATIC_PROXY needs Windows 8.1, fall back to DEFAULT_PROXY.
    let session = unsafe {
        let s = WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        );
        if s.is_null() {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                null(),
                null(),
                0,
            )
        } else {
            s
        }
    };
    let session = open(session, "WinHttpOpen")?;
    // SAFETY: live session handle.
    unsafe { WinHttpSetTimeouts(session.0, 10_000, 10_000, 15_000, 30_000) };
    let host_w = wide(host);
    // SAFETY: live session handle, NUL-terminated host.
    let connect = open(
        unsafe { WinHttpConnect(session.0, host_w.as_ptr(), 443, 0) },
        "WinHttpConnect",
    )?;
    let (verb, path_w) = (wide("GET"), wide(&path));
    // SAFETY: live connect handle; null version/referrer/accept-types mean defaults.
    let request = open(
        unsafe {
            WinHttpOpenRequest(
                connect.0,
                verb.as_ptr(),
                path_w.as_ptr(),
                null(),
                null(),
                null(),
                WINHTTP_FLAG_SECURE,
            )
        },
        "WinHttpOpenRequest",
    )?;
    let headers = wide(&format!("Accept: {accept}\r\n"));
    // SAFETY: live request handle; `headers` is NUL-terminated (length -1 =
    // compute it); no request body.
    if unsafe { WinHttpSendRequest(request.0, headers.as_ptr(), u32::MAX, null(), 0, 0, 0) } == 0 {
        return Err(fail("WinHttpSendRequest"));
    }
    // SAFETY: live request handle, reserved argument must be null.
    if unsafe { WinHttpReceiveResponse(request.0, null_mut()) } == 0 {
        return Err(fail("WinHttpReceiveResponse"));
    }
    let mut status = 0u32;
    let mut len = size_of::<u32>() as u32;
    // SAFETY: the buffer is a live u32 and `len` its size; null name/index are allowed.
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&raw mut status).cast(),
            &raw mut len,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(fail("WinHttpQueryHeaders"));
    }
    if status != 200 {
        return Err(Error::Network(format!("HTTP {status}")));
    }
    let mut body = Vec::new();
    loop {
        let mut avail = 0u32;
        // SAFETY: live request handle, `avail` is a live u32.
        if unsafe { WinHttpQueryDataAvailable(request.0, &raw mut avail) } == 0 {
            return Err(fail("WinHttpQueryDataAvailable"));
        }
        if avail == 0 {
            return Ok(body);
        }
        let start = body.len();
        if start + avail as usize > limit {
            return Err(Error::Network("yanıt çok büyük".into()));
        }
        body.resize(start + avail as usize, 0);
        let mut read = 0u32;
        // SAFETY: the destination has `avail` writable bytes past `start`.
        let ok = unsafe {
            WinHttpReadData(
                request.0,
                body[start..].as_mut_ptr().cast(),
                avail,
                &raw mut read,
            )
        };
        if ok == 0 {
            return Err(fail("WinHttpReadData"));
        }
        body.truncate(start + read as usize);
        if read == 0 {
            return Ok(body);
        }
    }
}
