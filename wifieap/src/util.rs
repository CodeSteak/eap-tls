use std::ffi::c_void;

use crate::peer::{malloc, memccpy};

/// Converts a str into a null-terminated C string on the heap.
/// The returned length does not include the null terminator.
/// # Safety
/// The returned pointer must be freed with `free`. But accually this method is safe.
pub unsafe fn malloc_str(s: &str) -> (*mut u8, usize) {
    let ptr = malloc((s.len() + 1) as _);
    assert!(!ptr.is_null());

    memccpy(ptr, s.as_ptr() as *const c_void, 0, s.len() as _);
    *(ptr.add(s.len()) as *mut u8) = 0;

    (ptr as *mut u8, s.len())
}
