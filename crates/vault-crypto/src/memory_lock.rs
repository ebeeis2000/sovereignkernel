#[cfg(unix)]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(unix)]
pub fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::munlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(windows)]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    unsafe {
        extern "system" {
            fn VirtualLock(lpAddress: *const u8, dwSize: usize) -> i32;
        }
        VirtualLock(ptr, len) != 0
    }
}

#[cfg(windows)]
pub fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    unsafe {
        extern "system" {
            fn VirtualUnlock(lpAddress: *const u8, dwSize: usize) -> i32;
        }
        VirtualUnlock(ptr, len) != 0
    }
}
