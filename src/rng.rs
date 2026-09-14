pub fn fill(out: &mut [u8]) {
    #[cfg(unix)]
    {
        let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr() as *const _, libc::O_RDONLY) };
        if fd >= 0 {
            unsafe {
                libc::read(fd, out.as_mut_ptr() as *mut _, out.len());
                libc::close(fd);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Security::Cryptography::*;
        unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                out.as_mut_ptr(),
                out.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            );
        }
    }
}

pub fn index(bound: usize) -> usize {
    let mut bytes = [0u8; 8];
    fill(&mut bytes);
    (u64::from_le_bytes(bytes) % bound.max(1) as u64) as usize
}
