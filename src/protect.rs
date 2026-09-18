//! Android routes every socket this process owns into our own tunnel as soon as
//! the host installs a default route, so the sockets that carry the mesh — the
//! ones that must reach the relay and the peers — have to be pulled back out
//! through `VpnService.protect` before they are used. Only the host can do that,
//! so it registers the hook here; where no host registers one, a socket is used
//! exactly as it was bound.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

pub type Descriptor = i32;
pub type Protector = Box<dyn Fn(Descriptor) -> bool + Send + Sync>;

const REFUSED: &str = "the host refused to keep the socket off the tunnel";
const TIMED_OUT: &str = "connection timed out";

fn hook() -> &'static RwLock<Option<Protector>> {
    static HOOK: OnceLock<RwLock<Option<Protector>>> = OnceLock::new();
    HOOK.get_or_init(|| RwLock::new(None))
}

pub fn install(protector: Protector) {
    *hook().write().unwrap_or_else(|held| held.into_inner()) = Some(protector);
}

pub fn remove() {
    *hook().write().unwrap_or_else(|held| held.into_inner()) = None;
}

fn registered() -> bool {
    hook()
        .read()
        .unwrap_or_else(|held| held.into_inner())
        .is_some()
}

fn offer(descriptor: Descriptor) -> io::Result<()> {
    let hook = hook().read().unwrap_or_else(|held| held.into_inner());
    match hook.as_ref() {
        Some(protector) if !protector(descriptor) => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, REFUSED))
        }
        _ => Ok(()),
    }
}

/// Offers a socket the caller has already bound. Safe for UDP, where the route
/// is chosen per datagram, and for any socket that has not connected yet.
#[cfg(unix)]
pub fn hold<S: std::os::unix::io::AsRawFd>(socket: &S) -> io::Result<()> {
    offer(socket.as_raw_fd())
}

#[cfg(not(unix))]
pub fn hold<S>(_socket: &S) -> io::Result<()> {
    Ok(())
}

/// A TCP socket has to be off the tunnel *before* it connects: the kernel picks
/// the route then, and a connection already bound to our own tun cannot be
/// moved afterwards. With no protector registered this is `connect_timeout`.
pub fn connect_timeout(address: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    if registered() {
        return dial(address, timeout);
    }
    TcpStream::connect_timeout(address, timeout)
}

#[cfg(not(unix))]
fn dial(address: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(address, timeout)
}

#[cfg(unix)]
fn dial(address: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    use std::os::unix::io::FromRawFd;

    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let descriptor = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { TcpStream::from_raw_fd(descriptor) };
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    hold(&stream)?;
    stream.set_nonblocking(true)?;

    let (target, length) = raw_address(address);
    let started = unsafe {
        libc::connect(
            descriptor,
            &target as *const libc::sockaddr_storage as *const libc::sockaddr,
            length,
        )
    };
    if started < 0 {
        let reason = io::Error::last_os_error();
        if reason.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(reason);
        }
        await_connected(descriptor, timeout)?;
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(unix)]
fn raw_address(address: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = match address {
        SocketAddr::V4(v4) => {
            let target = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
            unsafe {
                (*target).sin_family = libc::AF_INET as libc::sa_family_t;
                (*target).sin_port = v4.port().to_be();
                (*target).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let target = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
            unsafe {
                (*target).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*target).sin6_port = v6.port().to_be();
                (*target).sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                };
                (*target).sin6_flowinfo = v6.flowinfo();
                (*target).sin6_scope_id = v6.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, length as libc::socklen_t)
}

#[cfg(unix)]
fn await_connected(descriptor: Descriptor, timeout: Duration) -> io::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, TIMED_OUT));
        }
        let mut waiting = libc::pollfd {
            fd: descriptor,
            events: libc::POLLOUT,
            revents: 0,
        };
        let millis = left.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        let ready = unsafe { libc::poll(&mut waiting, 1 as libc::nfds_t, millis) };
        if ready < 0 {
            let reason = io::Error::last_os_error();
            if reason.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(reason);
        }
        if ready == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, TIMED_OUT));
        }
        return match pending_error(descriptor)? {
            0 => Ok(()),
            code => Err(io::Error::from_raw_os_error(code)),
        };
    }
}

#[cfg(unix)]
fn pending_error(descriptor: Descriptor) -> io::Result<libc::c_int> {
    let mut code: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let read = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut code as *mut libc::c_int as *mut libc::c_void,
            &mut length,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(code)
}

/// The hook is process-wide, so the tests that register one take turns.
#[cfg(test)]
pub(crate) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    static TURN: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    TURN.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|held| held.into_inner())
}

#[cfg(all(test, unix))]
mod protector_tests {
    use super::{connect_timeout, exclusive, hold, install, remove};
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::os::unix::io::AsRawFd;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    const GREETING: &[u8] = b"mesh";

    fn local_listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").expect("a loopback listener")
    }

    #[test]
    fn a_host_that_registers_nothing_changes_nothing() {
        let _turn = exclusive();
        remove();

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(hold(&socket).is_ok());

        let listener = local_listener();
        let address = listener.local_addr().unwrap();
        let stream = connect_timeout(&address, DIAL_TIMEOUT).unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
    }

    #[test]
    fn every_socket_reaches_the_protector_and_still_works() {
        let _turn = exclusive();
        let seen: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        install(Box::new(move |descriptor| {
            recorder.lock().unwrap().push(descriptor);
            true
        }));

        let bound = UdpSocket::bind("127.0.0.1:0").unwrap();
        let outcome = hold(&bound);
        let listener = local_listener();
        let dialled = connect_timeout(&listener.local_addr().unwrap(), DIAL_TIMEOUT);
        remove();

        assert!(outcome.is_ok());
        let mut stream = dialled.expect("the protected path still connects");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen.contains(&bound.as_raw_fd()));
        assert!(seen.contains(&stream.as_raw_fd()));

        let (mut accepted, _) = listener.accept().unwrap();
        accepted.write_all(GREETING).unwrap();
        let mut echoed = [0u8; GREETING.len()];
        stream.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, GREETING);
    }

    #[test]
    fn a_refusing_protector_stops_the_socket_being_used() {
        let _turn = exclusive();
        install(Box::new(|_| false));

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let held = hold(&socket);
        let listener = local_listener();
        let dialled = connect_timeout(&listener.local_addr().unwrap(), DIAL_TIMEOUT);
        remove();

        assert!(held.is_err());
        assert!(dialled.is_err());
    }
}
