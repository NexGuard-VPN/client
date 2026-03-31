use std::net::Ipv4Addr;

pub struct TunDevice {
    #[cfg(unix)]
    fd: i32,
    name: String,
}

impl TunDevice {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_address_v6(&self, ip: &str, prefix: u8) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("ip")
                .args(["addr", "add", &format!("{}/{}", ip, prefix), "dev", &self.name])
                .status();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("ifconfig")
                .args([&self.name, "inet6", &format!("{}/{}", ip, prefix)])
                .status();
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    const TUNSETIFF: u64 = 0x400454CA;

    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; 16],
        ifr_flags: i16,
        _pad: [u8; 22],
    }

    #[repr(C)]
    struct MtuReq {
        name: [u8; 16],
        mtu: i32,
        _pad: [u8; 20],
    }

    impl TunDevice {
        pub fn create(mtu: usize) -> Self {
            let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
            if fd < 0 {
                panic!("failed to open /dev/net/tun: {}", std::io::Error::last_os_error());
            }

            let mut ifr = IfReq {
                ifr_name: [0u8; 16],
                ifr_flags: (libc::IFF_TUN | libc::IFF_NO_PI) as i16,
                _pad: [0u8; 22],
            };

            if unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut _) } < 0 {
                unsafe { libc::close(fd); }
                panic!("TUNSETIFF failed: {}", std::io::Error::last_os_error());
            }

            let name_end = ifr.ifr_name.iter().position(|&b| b == 0).unwrap_or(16);
            let name = String::from_utf8_lossy(&ifr.ifr_name[..name_end]).into_owned();

            set_mtu(&name, mtu);
            set_nonblocking(fd);

            Self { fd, name }
        }

        pub fn set_address(&self, ip: Ipv4Addr, prefix: u8) {
            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if sock < 0 {
                return;
            }

            let mut ifr = [0u8; 40];
            copy_ifname(&mut ifr, &self.name);

            let o = ip.octets();
            ifr[16] = libc::AF_INET as u8;
            ifr[20] = o[0]; ifr[21] = o[1]; ifr[22] = o[2]; ifr[23] = o[3];
            unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr as *const _); }

            let mask = prefix_to_mask(prefix);
            let m = mask.to_be_bytes();
            ifr[20] = m[0]; ifr[21] = m[1]; ifr[22] = m[2]; ifr[23] = m[3];
            unsafe {
                libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr as *const _);
                libc::close(sock);
            }
        }

        pub fn set_up(&self) {
            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if sock < 0 {
                return;
            }

            let mut ifr = [0u8; 40];
            copy_ifname(&mut ifr, &self.name);

            unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr as *mut _); }
            let flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
            let new_flags = flags | libc::IFF_UP as i16 | libc::IFF_RUNNING as i16;
            ifr[16..18].copy_from_slice(&new_flags.to_ne_bytes());
            unsafe {
                libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _);
                libc::close(sock);
            }
        }

        pub fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        pub fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
            let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const _, buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    fn set_mtu(name: &str, mtu: usize) {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return;
        }
        let mut r = MtuReq { name: [0; 16], mtu: mtu as i32, _pad: [0; 20] };
        copy_ifname(&mut r.name, name);
        unsafe {
            libc::ioctl(sock, libc::SIOCSIFMTU as _, &r as *const _);
            libc::close(sock);
        }
    }

    fn copy_ifname(dst: &mut [u8], name: &str) {
        let nb = name.as_bytes();
        let len = nb.len().min(15);
        dst[..len].copy_from_slice(&nb[..len]);
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    const SYSPROTO_CONTROL: i32 = 2;
    const AF_SYS_CONTROL: u16 = 2;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
    const CTLIOCGINFO: u64 = 0xc0644e03;
    const AF_INET: [u8; 4] = [0, 0, 0, 2];
    const AF_INET6: [u8; 4] = [0, 0, 0, 30];

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    impl TunDevice {
        pub fn create(mtu: usize) -> Self {
            let fd = unsafe {
                libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL)
            };
            if fd < 0 {
                panic!("failed to create utun socket: {}", std::io::Error::last_os_error());
            }

            let mut info = CtlInfo { ctl_id: 0, ctl_name: [0u8; 96] };
            info.ctl_name[..UTUN_CONTROL_NAME.len()]
                .copy_from_slice(UTUN_CONTROL_NAME);

            if unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut _) } < 0 {
                unsafe { libc::close(fd); }
                panic!("CTLIOCGINFO failed: {}", std::io::Error::last_os_error());
            }

            let mut name = String::new();
            for unit in 0..256u32 {
                let addr = SockaddrCtl {
                    sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                    sc_family: libc::AF_SYSTEM as u8,
                    ss_sysaddr: AF_SYS_CONTROL,
                    sc_id: info.ctl_id,
                    sc_unit: unit + 1,
                    sc_reserved: [0; 5],
                };
                let ret = unsafe {
                    libc::connect(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<SockaddrCtl>() as u32,
                    )
                };
                if ret == 0 {
                    name = format!("utun{}", unit);
                    break;
                }
            }

            if name.is_empty() {
                unsafe { libc::close(fd); }
                panic!("failed to create utun device");
            }

            set_nonblocking(fd);
            set_mtu_cmd(&name, mtu);

            Self { fd, name }
        }

        pub fn set_address(&self, ip: Ipv4Addr, prefix: u8) {
            let mask = prefix_to_mask(prefix);
            let mask_ip = Ipv4Addr::from(mask);
            let _ = std::process::Command::new("ifconfig")
                .args([
                    &self.name,
                    &ip.to_string(),
                    &ip.to_string(),
                    "netmask",
                    &mask_ip.to_string(),
                    "up",
                ])
                .status();
        }

        pub fn set_up(&self) {
            let _ = std::process::Command::new("ifconfig")
                .args([&self.name, "up"])
                .status();
        }

        pub fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut hdr_buf = vec![0u8; buf.len() + 4];
            let n = unsafe { libc::read(self.fd, hdr_buf.as_mut_ptr() as *mut _, hdr_buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let n = n as usize;
            if n <= 4 {
                return Ok(0);
            }
            let payload = n - 4;
            buf[..payload].copy_from_slice(&hdr_buf[4..n]);
            Ok(payload)
        }

        pub fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
            let af = if !buf.is_empty() && (buf[0] >> 4) == 6 {
                AF_INET6
            } else {
                AF_INET
            };
            let mut pkt = Vec::with_capacity(4 + buf.len());
            pkt.extend_from_slice(&af);
            pkt.extend_from_slice(buf);
            let n = unsafe { libc::write(self.fd, pkt.as_ptr() as *const _, pkt.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(if (n as usize) > 4 { n as usize - 4 } else { 0 })
        }
    }

    fn set_mtu_cmd(name: &str, mtu: usize) {
        let _ = std::process::Command::new("ifconfig")
            .args([name, "mtu", &mtu.to_string()])
            .status();
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;

    impl TunDevice {
        pub fn create(_mtu: usize) -> Self {
            eprintln!("Windows native TUN support coming soon. Please use WSL2.");
            std::process::exit(1);
        }

        pub fn set_address(&self, _ip: Ipv4Addr, _prefix: u8) {}
        pub fn set_up(&self) {}

        pub fn read_packet(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("unsupported"))
        }

        pub fn write_packet(&self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("unsupported"))
        }
    }
}

#[cfg(unix)]
impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

#[cfg(unix)]
fn set_nonblocking(fd: i32) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
    }
}

fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { !0u32 << (32 - prefix) }
}
