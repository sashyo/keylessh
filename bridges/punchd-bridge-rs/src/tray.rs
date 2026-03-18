//! Windows system tray icon — zero dependencies, raw Win32 FFI.
//!
//! Shows a tray icon with right-click menu: Open Logs, Open Gateway, Quit.
//! Runs on a dedicated OS thread (Win32 message loop).

#[cfg(target_os = "windows")]
pub fn spawn_tray(logs_url: String, gateway_url: String) {
    std::thread::spawn(move || unsafe { win32::run_tray(&logs_url, &gateway_url) });
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_tray(_logs_url: String, _gateway_url: String) {
    // No tray on non-Windows — logs available at /logs
}

#[cfg(target_os = "windows")]
mod win32 {
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;

    // ── Types ────────────────────────────────────────────────
    type HWND = isize;
    type HMENU = isize;
    type HICON = isize;
    type HINSTANCE = isize;
    type WPARAM = usize;
    type LPARAM = isize;
    type LRESULT = isize;
    type UINT = u32;
    type WORD = u16;
    type DWORD = u32;
    type BOOL = i32;
    type WNDPROC = Option<unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT>;

    #[repr(C)]
    struct WNDCLASSEXW {
        cb_size: UINT,
        style: UINT,
        lpfn_wnd_proc: WNDPROC,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: HINSTANCE,
        h_icon: HICON,
        h_cursor: isize,
        hbr_background: isize,
        lpsz_menu_name: *const u16,
        lpsz_class_name: *const u16,
        h_icon_sm: HICON,
    }

    #[repr(C)]
    struct MSG {
        hwnd: HWND,
        message: UINT,
        w_param: WPARAM,
        l_param: LPARAM,
        time: DWORD,
        pt_x: i32,
        pt_y: i32,
    }

    #[repr(C)]
    struct NOTIFYICONDATAW {
        cb_size: DWORD,
        h_wnd: HWND,
        u_id: UINT,
        u_flags: UINT,
        u_callback_message: UINT,
        h_icon: HICON,
        sz_tip: [u16; 128],
        dw_state: DWORD,
        dw_state_mask: DWORD,
        sz_info: [u16; 256],
        u_version_or_timeout: UINT,
        sz_info_title: [u16; 64],
        dw_info_flags: DWORD,
        guid_item: [u8; 16],
        h_balloon_icon: HICON,
    }

    #[repr(C)]
    struct POINT {
        x: i32,
        y: i32,
    }

    // ── Constants ────────────────────────────────────────────
    const WM_USER: UINT = 0x0400;
    const WM_TRAYICON: UINT = WM_USER + 1;
    const WM_COMMAND: UINT = 0x0111;
    const WM_DESTROY: UINT = 0x0002;
    const WM_RBUTTONUP: UINT = 0x0205;
    const WM_LBUTTONDBLCLK: UINT = 0x0203;

    const NIM_ADD: DWORD = 0x00;
    const NIM_DELETE: DWORD = 0x02;
    const NIF_MESSAGE: UINT = 0x01;
    const NIF_ICON: UINT = 0x02;
    const NIF_TIP: UINT = 0x04;

    const IDI_APPLICATION: *const u16 = 32512 as *const u16;
    const TPM_BOTTOMALIGN: UINT = 0x0020;
    const TPM_LEFTALIGN: UINT = 0x0000;
    const MF_STRING: UINT = 0x0000;
    const MF_SEPARATOR: UINT = 0x0800;

    const ID_OPEN_LOGS: UINT = 1001;
    const ID_OPEN_GATEWAY: UINT = 1002;
    const ID_QUIT: UINT = 1003;

    // ── Win32 FFI ────────────────────────────────────────────
    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> HINSTANCE;
        fn RegisterClassExW(wc: *const WNDCLASSEXW) -> WORD;
        fn CreateWindowExW(
            ex_style: DWORD, class: *const u16, title: *const u16,
            style: DWORD, x: i32, y: i32, w: i32, h: i32,
            parent: HWND, menu: HMENU, instance: HINSTANCE, param: *mut (),
        ) -> HWND;
        fn DefWindowProcW(hwnd: HWND, msg: UINT, wp: WPARAM, lp: LPARAM) -> LRESULT;
        fn GetMessageW(msg: *mut MSG, hwnd: HWND, min: UINT, max: UINT) -> BOOL;
        fn TranslateMessage(msg: *const MSG) -> BOOL;
        fn DispatchMessageW(msg: *const MSG) -> LRESULT;
        fn PostQuitMessage(code: i32);
        fn Shell_NotifyIconW(msg: DWORD, data: *mut NOTIFYICONDATAW) -> BOOL;
        fn LoadIconW(instance: HINSTANCE, name: *const u16) -> HICON;
        fn CreatePopupMenu() -> HMENU;
        fn AppendMenuW(menu: HMENU, flags: UINT, id: usize, text: *const u16) -> BOOL;
        fn TrackPopupMenu(menu: HMENU, flags: UINT, x: i32, y: i32, reserved: i32, hwnd: HWND, rect: *const ()) -> BOOL;
        fn DestroyMenu(menu: HMENU) -> BOOL;
        fn GetCursorPos(point: *mut POINT) -> BOOL;
        fn SetForegroundWindow(hwnd: HWND) -> BOOL;
    }

    // ── Globals (single tray instance) ───────────────────────
    static mut LOGS_URL: Option<String> = None;
    static mut GATEWAY_URL: Option<String> = None;
    static mut TRAY_HWND: HWND = 0;

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

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: UINT, wp: WPARAM, lp: LPARAM) -> LRESULT {
        match msg {
            WM_TRAYICON => {
                let event = (lp as UINT) & 0xFFFF;
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
                let id = (wp & 0xFFFF) as UINT;
                match id {
                    ID_OPEN_LOGS => {
                        if let Some(ref url) = LOGS_URL {
                            shell_open(url);
                        }
                    }
                    ID_OPEN_GATEWAY => {
                        if let Some(ref url) = GATEWAY_URL {
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
        let gateway = to_wide("Open Gateway");
        let quit = to_wide("Quit");

        AppendMenuW(menu, MF_STRING, ID_OPEN_LOGS as usize, logs.as_ptr());
        AppendMenuW(menu, MF_STRING, ID_OPEN_GATEWAY as usize, gateway.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, null_mut());
        AppendMenuW(menu, MF_STRING, ID_QUIT as usize, quit.as_ptr());

        let mut pt: POINT = zeroed();
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, null_mut() as *const ());
        DestroyMenu(menu);
    }

    unsafe fn add_tray_icon(hwnd: HWND) {
        let icon = LoadIconW(0, IDI_APPLICATION);
        let mut nid: NOTIFYICONDATAW = zeroed();
        nid.cb_size = size_of::<NOTIFYICONDATAW>() as DWORD;
        nid.h_wnd = hwnd;
        nid.u_id = 1;
        nid.u_flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.u_callback_message = WM_TRAYICON;
        nid.h_icon = icon;
        nid.sz_tip = wide_into_array::<128>("KeyleSSH Gateway");
        Shell_NotifyIconW(NIM_ADD, &mut nid);
    }

    unsafe fn remove_tray_icon(hwnd: HWND) {
        let mut nid: NOTIFYICONDATAW = zeroed();
        nid.cb_size = size_of::<NOTIFYICONDATAW>() as DWORD;
        nid.h_wnd = hwnd;
        nid.u_id = 1;
        Shell_NotifyIconW(NIM_DELETE, &mut nid);
    }

    pub unsafe fn run_tray(logs_url: &str, gateway_url: &str) {
        LOGS_URL = Some(logs_url.to_string());
        GATEWAY_URL = Some(gateway_url.to_string());

        let class_name = to_wide("KeyleSSHTray");
        let h_instance = GetModuleHandleW(null_mut());

        let wc = WNDCLASSEXW {
            cb_size: size_of::<WNDCLASSEXW>() as UINT,
            style: 0,
            lpfn_wnd_proc: Some(wnd_proc),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance,
            h_icon: 0,
            h_cursor: 0,
            hbr_background: 0,
            lpsz_menu_name: null_mut(),
            lpsz_class_name: class_name.as_ptr(),
            h_icon_sm: 0,
        };
        RegisterClassExW(&wc);

        let title = to_wide("KeyleSSH");
        let hwnd = CreateWindowExW(
            0, class_name.as_ptr(), title.as_ptr(),
            0, 0, 0, 0, 0,
            0, 0, h_instance, null_mut(),
        );
        TRAY_HWND = hwnd;

        add_tray_icon(hwnd);
        eprintln!("[Gateway] System tray icon active");

        // Win32 message loop
        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
