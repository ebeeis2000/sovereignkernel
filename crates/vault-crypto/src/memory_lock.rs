#[cfg(unix)]
/// Lock a region of memory into RAM.
///
/// # Safety
///
/// The caller must ensure that `ptr` is valid for reads of `len` bytes and that the
/// region remains valid for the duration of the lock operation.
pub unsafe fn lock_memory(ptr: *const u8, len: usize) -> bool {
    libc::mlock(ptr as *const libc::c_void, len) == 0
}

#[cfg(unix)]
/// Unlock a region of memory previously locked with `lock_memory`.
///
/// # Safety
///
/// The caller must ensure that `ptr` is valid for reads of `len` bytes and that the
/// region was previously locked.
pub unsafe fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    libc::munlock(ptr as *const libc::c_void, len) == 0
}

#[cfg(windows)]
/// Lock a region of memory into RAM.
///
/// # Safety
///
/// The caller must ensure that `ptr` is valid for reads of `len` bytes and that the
/// region remains valid for the duration of the lock operation.
pub unsafe fn lock_memory(ptr: *const u8, len: usize) -> bool {
    extern "system" {
        fn VirtualLock(lpAddress: *const u8, dwSize: usize) -> i32;
    }
    VirtualLock(ptr, len) != 0
}

#[cfg(windows)]
/// Unlock a region of memory previously locked with `lock_memory`.
///
/// # Safety
///
/// The caller must ensure that `ptr` is valid for reads of `len` bytes and that the
/// region was previously locked.
pub unsafe fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    extern "system" {
        fn VirtualUnlock(lpAddress: *const u8, dwSize: usize) -> i32;
    }
    VirtualUnlock(ptr, len) != 0
}
