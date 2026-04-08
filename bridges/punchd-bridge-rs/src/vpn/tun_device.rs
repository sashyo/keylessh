///! Cross-platform TUN device abstraction.
///!
///! Linux: uses the `tun` crate with async support.
///! Windows: uses the `wintun` crate (WireGuard's Wintun driver).

use std::io;
use std::net::Ipv4Addr;

/// Configuration for creating a TUN device.
pub struct TunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

// ── Linux implementation ────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use tun::AsyncDevice;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub struct TunDevice {
        dev: AsyncDevice,
    }

    impl TunDevice {
        pub fn create(config: &TunConfig) -> io::Result<Self> {
            let mut tun_config = tun::Configuration::default();
            tun_config
                .tun_name(&config.name)
                .address(config.address)
                .netmask(config.netmask)
                .mtu(config.mtu)
                .up();

            #[cfg(target_os = "linux")]
            tun_config.platform_config(|p| {
                p.ensure_root_privileges(true);
            });

            let dev = tun::create_as_async(&tun_config)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            Ok(Self { dev })
        }

        pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.dev.read(buf).await
        }

        pub async fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
            self.dev.write(packet).await
        }
    }
}

// ── macOS implementation (utun via tun crate) ──────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use tun::AsyncDevice;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub struct TunDevice {
        dev: AsyncDevice,
    }

    impl TunDevice {
        pub fn create(config: &TunConfig) -> io::Result<Self> {
            let mut tun_config = tun::Configuration::default();
            // macOS uses utun — name is auto-assigned (utun0, utun1, etc.)
            tun_config
                .address(config.address)
                .netmask(config.netmask)
                .mtu(config.mtu)
                .up();
            let dev = tun::create_as_async(&tun_config)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Ok(Self { dev })
        }

        pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.dev.read(buf).await
        }

        pub async fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
            self.dev.write(packet).await
        }
    }
}

// ── Windows implementation ──────────────────────────────────────────

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::sync::Arc;

    /// Embedded wintun.dll for all architectures — included at compile time.
    #[cfg(target_arch = "x86_64")]
    static WINTUN_DLL_BYTES: &[u8] = include_bytes!("../../wintun/wintun_amd64.dll");

    #[cfg(target_arch = "x86")]
    static WINTUN_DLL_BYTES: &[u8] = include_bytes!("../../wintun/wintun_x86.dll");

    #[cfg(target_arch = "aarch64")]
    static WINTUN_DLL_BYTES: &[u8] = include_bytes!("../../wintun/wintun_arm64.dll");

    #[cfg(target_arch = "arm")]
    static WINTUN_DLL_BYTES: &[u8] = include_bytes!("../../wintun/wintun_arm.dll");

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "arm")))]
    static WINTUN_DLL_BYTES: &[u8] = &[];

    /// Extract embedded wintun.dll next to the running executable if not already present.
    fn ensure_wintun_dll() -> io::Result<std::path::PathBuf> {
        let exe_dir = std::env::current_exe()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()).ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no parent")))
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        let dll_path = exe_dir.join("wintun.dll");

        if !dll_path.exists() {
            if WINTUN_DLL_BYTES.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "wintun.dll not found and no embedded DLL for this architecture",
                ));
            }
            std::fs::write(&dll_path, WINTUN_DLL_BYTES)?;
        }
        Ok(dll_path)
    }

    pub struct TunDevice {
        pub session: Arc<wintun::Session>,
        _adapter: Arc<wintun::Adapter>,
        read_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        pub write_tx: std::sync::mpsc::SyncSender<Vec<u8>>,
    }

    impl TunDevice {
        pub fn create(config: &TunConfig) -> io::Result<Self> {
            // Auto-extract embedded wintun.dll if needed
            ensure_wintun_dll()?;

            let wintun_dll = unsafe {
                wintun::load()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to load wintun.dll: {e}")))?
            };

            // Clean up stale adapter with the same name (e.g. from a crashed previous run)
            if let Ok(stale) = wintun::Adapter::open(&wintun_dll, &config.name) {
                if let Ok(adapter) = Arc::try_unwrap(stale) {
                    let _ = adapter.delete();
                }
            }

            let adapter = wintun::Adapter::create(&wintun_dll, &config.name, "PunchdVPN", None)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create adapter: {e}")))?;

            // Set IP address via netsh
            let addr = config.address.to_string();
            let mask = config.netmask.to_string();
            let status = std::process::Command::new("netsh")
                .args(["interface", "ip", "set", "address", &config.name, "static", &addr, &mask])
                .status()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("netsh failed: {e}")))?;

            if !status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("netsh returned exit code: {:?}", status.code()),
                ));
            }

            // Set MTU
            let mtu_str = config.mtu.to_string();
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "set", "subinterface", &config.name, &format!("mtu={mtu_str}"), "store=active"])
                .status();

            // Enable IP forwarding on the TUN interface explicitly (by name)
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "set", "interface", &config.name, "forwarding=enabled"])
                .status();

            // Also enable on physical adapters (skip vEthernet to preserve Hyper-V NAT)
            let iface_output = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "show", "interfaces"])
                .output();
            if let Ok(out) = iface_output {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines().skip(3) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 && parts[3] == "connected" {
                        let iface_name = parts[4..].join(" ");
                        if iface_name.starts_with("vEthernet") || iface_name == config.name {
                            continue;
                        }
                        let _ = std::process::Command::new("netsh")
                            .args(["interface", "ipv4", "set", "interface", &iface_name, "forwarding=enabled"])
                            .status();
                    }
                }
            }

            // Firewall rules for VPN subnet (idempotent — netsh ignores duplicates)
            let subnet = format!("{}/{}", {
                let o = config.address.octets();
                let m = config.netmask.octets();
                format!("{}.{}.{}.{}", o[0] & m[0], o[1] & m[1], o[2] & m[2], o[3] & m[3])
            }, config.netmask.octets().iter().map(|b| b.count_ones()).sum::<u32>());

            for (name, dir, ip_param) in [
                ("PunchdVPN In", "in", "localip"),
                ("PunchdVPN Out", "out", "remoteip"),
            ] {
                let _ = std::process::Command::new("netsh")
                    .args(["advfirewall", "firewall", "add", "rule",
                        &format!("name={name}"), &format!("dir={dir}"),
                        "action=allow", &format!("{ip_param}={subnet}")])
                    .status();
            }

            let session = adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to start session: {e}")))?;
            let session = Arc::new(session);

            // Dedicated reader thread — avoids spawn_blocking per packet
            let (read_tx, read_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
            let reader_session = session.clone();
            std::thread::Builder::new()
                .name("tun-reader".into())
                .spawn(move || {
                    loop {
                        match reader_session.receive_blocking() {
                            Ok(packet) => {
                                let data = packet.bytes().to_vec();
                                if read_tx.blocking_send(data).is_err() {
                                    break; // receiver dropped
                                }
                            }
                            Err(_) => break,
                        }
                    }
                })
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reader thread: {e}")))?;

            // Dedicated writer thread
            let (write_tx, write_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(512);
            let writer_session = session.clone();
            std::thread::Builder::new()
                .name("tun-writer".into())
                .spawn(move || {
                    while let Ok(data) = write_rx.recv() {
                        if let Ok(mut pkt) = writer_session.allocate_send_packet(data.len() as u16) {
                            pkt.bytes_mut().copy_from_slice(&data);
                            writer_session.send_packet(pkt);
                        }
                    }
                })
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("writer thread: {e}")))?;

            Ok(Self {
                session,
                _adapter: adapter,
                read_rx,
                write_tx,
            })
        }

        pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.read_rx.recv().await {
                Some(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    Ok(len)
                }
                None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUN reader closed")),
            }
        }

        pub async fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
            let data = packet.to_vec();
            let len = data.len();
            self.write_tx.send(data)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN writer closed"))?;
            Ok(len)
        }
    }
}

// ── Re-export ───────────────────────────────────────────────────────

pub use platform::TunDevice;
