use std::ffi::c_void;

use crate::peer::{malloc, memccpy};

pub unsafe fn malloc_str(s : &str) -> (*mut u8, usize) {
    let ptr = malloc(s.len() as _);
    memccpy(ptr, s.as_ptr() as *const c_void, 0, s.len() as _);
    (ptr as *mut u8, s.len())
} 