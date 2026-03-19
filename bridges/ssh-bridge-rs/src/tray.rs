//! Windows system tray icon — zero dependencies, raw Win32 FFI.
//!
//! Shows a tray icon with right-click menu: Open Logs, Quit.
//! Runs on a dedicated OS thread (Win32 message loop).

#[cfg(target_os = "windows")]
pub fn spawn_tray(logs_url: String) {
    std::thread::spawn(move || unsafe { win32::run_tray(&logs_url) });
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_tray(_logs_url: String) {
    // No tray on non-Windows — logs available at /logs
}

#[cfg(target_os = "windows")]
mod win32 {
    use std::mem::{size_of, zeroed};

    // ── Fundamental types (match Win32 exactly) ──────────────
    #[allow(non_camel_case_types)]
    type HWND = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type HMENU = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type HICON = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type HINSTANCE = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type HBRUSH = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type HCURSOR = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type WPARAM = usize;
    #[allow(non_camel_case_types)]
    type LPARAM = isize;
    #[allow(non_camel_case_types)]
    type LRESULT = isize;
    #[allow(non_camel_case_types)]
    type ATOM = u16;
    #[allow(non_camel_case_types)]
    type WNDPROC = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;

    #[repr(C)]
    struct GUID {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct WNDCLASSEXW {
        cb_size: u32,
        style: u32,
        lpfn_wnd_proc: WNDPROC,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: HINSTANCE,
        h_icon: HICON,
        h_cursor: HCURSOR,
        hbr_background: HBRUSH,
        lpsz_menu_name: *const u16,
        lpsz_class_name: *const u16,
        h_icon_sm: HICON,
    }

    #[repr(C)]
    struct MSG {
        hwnd: HWND,
        message: u32,
        w_param: WPARAM,
        l_param: LPARAM,
        time: u32,
        pt: POINT,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct POINT {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct NOTIFYICONDATAW {
        cb_size: u32,
        h_wnd: HWND,
        u_id: u32,
        u_flags: u32,
        u_callback_message: u32,
        h_icon: HICON,
        sz_tip: [u16; 128],
        dw_state: u32,
        dw_state_mask: u32,
        sz_info: [u16; 256],
        u_timeout_or_version: u32,
        sz_info_title: [u16; 64],
        dw_info_flags: u32,
        guid_item: GUID,
        h_balloon_icon: HICON,
    }

    // ── Constants ────────────────────────────────────────────
    const WM_USER: u32 = 0x0400;
    const WM_TRAYICON: u32 = WM_USER + 1;
    const WM_COMMAND: u32 = 0x0111;
    const WM_DESTROY: u32 = 0x0002;
    const WM_RBUTTONUP: u32 = 0x0205;
    const WM_LBUTTONDBLCLK: u32 = 0x0203;

    const NIM_ADD: u32 = 0x00;
    const NIM_DELETE: u32 = 0x02;
    const NIF_MESSAGE: u32 = 0x01;
    const NIF_ICON: u32 = 0x02;
    const NIF_TIP: u32 = 0x04;

    const TPM_BOTTOMALIGN: u32 = 0x0020;
    const TPM_LEFTALIGN: u32 = 0x0000;
    const MF_STRING: u32 = 0x0000;
    const MF_SEPARATOR: u32 = 0x0800;

    const ID_OPEN_LOGS: usize = 1001;
    const ID_QUIT: usize = 1003;

    const HWND_MESSAGE: HWND = -3isize as HWND;

    // ── Win32 FFI ────────────────────────────────────────────
    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> HINSTANCE;
        fn GetLastError() -> u32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn RegisterClassExW(wc: *const WNDCLASSEXW) -> ATOM;
        fn CreateWindowExW(
            ex_style: u32, class: *const u16, title: *const u16,
            style: u32, x: i32, y: i32, w: i32, h: i32,
            parent: HWND, menu: HMENU, instance: HINSTANCE, param: *mut std::ffi::c_void,
        ) -> HWND;
        fn DefWindowProcW(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT;
        fn GetMessageW(msg: *mut MSG, hwnd: HWND, min: u32, max: u32) -> i32;
        fn TranslateMessage(msg: *const MSG) -> i32;
        fn DispatchMessageW(msg: *const MSG) -> LRESULT;
        fn PostQuitMessage(code: i32);
        fn LoadIconW(instance: HINSTANCE, name: *const u16) -> HICON;
        fn CreatePopupMenu() -> HMENU;
        fn AppendMenuW(menu: HMENU, flags: u32, id: usize, text: *const u16) -> i32;
        fn TrackPopupMenu(menu: HMENU, flags: u32, x: i32, y: i32, reserved: i32, hwnd: HWND, rect: *const std::ffi::c_void) -> i32;
        fn DestroyMenu(menu: HMENU) -> i32;
        fn GetCursorPos(point: *mut POINT) -> i32;
        fn SetForegroundWindow(hwnd: HWND) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn Shell_NotifyIconW(msg: u32, data: *mut NOTIFYICONDATAW) -> i32;
    }

    // ── Globals (single tray instance) ───────────────────────
    static mut LOGS_URL: Option<String> = None;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_into_array<const N: usize>(s: &str) -> [u16; N] {
        let mut arr = [0u16; N];
        for (i, c) in s.encode_utf16().take(N - 1).enumerate() {
            arr[i] = c;
        }
        arr
    }

    fn shell_open(url: &str) {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        match msg {
            WM_TRAYICON => {
                let event = (lp as u32) & 0xFFFF;
                if event == WM_RBUTTONUP {
                    show_context_menu(hwnd);
                } else if event == WM_LBUTTONDBLCLK {
                    if let Some(ref url) = LOGS_URL {
                        shell_open(url);
                    }
                }
                0
            }
            WM_COMMAND => {
                let id = wp & 0xFFFF;
                match id {
                    ID_OPEN_LOGS => {
                        if let Some(ref url) = LOGS_URL {
                            shell_open(url);
                        }
                    }
                    ID_QUIT => {
                        remove_tray_icon(hwnd);
                        PostQuitMessage(0);
                        std::process::exit(0);
                    }
                    _ => {}
                }
                0
            }
            WM_DESTROY => {
                remove_tray_icon(hwnd);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        let menu = CreatePopupMenu();
        let logs = to_wide("Open Logs");
        let quit = to_wide("Quit");

        AppendMenuW(menu, MF_STRING, ID_OPEN_LOGS, logs.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, ID_QUIT, quit.as_ptr());

        let mut pt: POINT = zeroed();
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, std::ptr::null());
        DestroyMenu(menu);
    }

    unsafe fn add_tray_icon(hwnd: HWND) -> bool {
        let h_instance = GetModuleHandleW(std::ptr::null());
        let icon = LoadIconW(h_instance, 1 as *const u16);
        let icon = if icon.is_null() {
            LoadIconW(std::ptr::null_mut() as HINSTANCE, 32512 as *const u16)
        } else {
            icon
        };
        eprintln!("[Tray] icon handle: {:?}", icon);

        let mut nid: NOTIFYICONDATAW = zeroed();
        nid.cb_size = size_of::<NOTIFYICONDATAW>() as u32;
        nid.h_wnd = hwnd;
        nid.u_id = 1;
        nid.u_flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.u_callback_message = WM_TRAYICON;
        nid.h_icon = icon;
        nid.sz_tip = wide_into_array::<128>("SSH Bridge");

        eprintln!("[Tray] NOTIFYICONDATAW size: {} bytes", nid.cb_size);

        let result = Shell_NotifyIconW(NIM_ADD, &mut nid);
        if result == 0 {
            let err = GetLastError();
            eprintln!("[Tray] Shell_NotifyIconW failed! GetLastError={err}");
            false
        } else {
            eprintln!("[Tray] Shell_NotifyIconW succeeded");
            true
        }
    }

    unsafe fn remove_tray_icon(hwnd: HWND) {
        let mut nid: NOTIFYICONDATAW = zeroed();
        nid.cb_size = size_of::<NOTIFYICONDATAW>() as u32;
        nid.h_wnd = hwnd;
        nid.u_id = 1;
        Shell_NotifyIconW(NIM_DELETE, &mut nid);
    }

    pub unsafe fn run_tray(logs_url: &str) {
        LOGS_URL = Some(logs_url.to_string());

        let class_name = to_wide("SshBridgeTray");
        let h_instance = GetModuleHandleW(std::ptr::null());

        let wc = WNDCLASSEXW {
            cb_size: size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfn_wnd_proc: wnd_proc,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance,
            h_icon: std::ptr::null_mut() as HICON,
            h_cursor: std::ptr::null_mut() as HCURSOR,
            hbr_background: std::ptr::null_mut() as HBRUSH,
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: class_name.as_ptr(),
            h_icon_sm: std::ptr::null_mut() as HICON,
        };

        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            eprintln!("[Tray] RegisterClassExW failed: {}", GetLastError());
            return;
        }

        let title = to_wide("SSH Bridge");
        let hwnd = CreateWindowExW(
            0, class_name.as_ptr(), title.as_ptr(),
            0, 0, 0, 0, 0,
            HWND_MESSAGE, std::ptr::null_mut() as HMENU, h_instance, std::ptr::null_mut(),
        );

        if hwnd.is_null() {
            eprintln!("[Tray] CreateWindowExW failed: {}", GetLastError());
            return;
        }
        eprintln!("[Tray] Hidden window created: {:?}", hwnd);

        add_tray_icon(hwnd);

        // Win32 message loop
        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut() as HWND, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
