use std::alloc::Layout;
use std::ffi::c_void;
use std::sync::atomic::{AtomicIsize, Ordering};

pub struct MonitoringAllocator {
    max : AtomicIsize,
    current : AtomicIsize,
}

impl MonitoringAllocator {
    pub const fn new() -> Self {
        Self {
            max : AtomicIsize::new(0),
            current : AtomicIsize::new(0),
        }
    }

    pub fn reset(&self) {
        self.current.store(0, Ordering::Relaxed);
        self.max.store(0, Ordering::Relaxed);
    }

    pub fn get_max(&self) -> isize {
        self.max.load(Ordering::Relaxed)
    }
}

unsafe impl std::alloc::GlobalAlloc for MonitoringAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let val = self.current.fetch_add(layout.size() as _, Ordering::Relaxed);
        self.max.fetch_max(val, Ordering::Relaxed);
        esp_idf_sys::malloc(layout.size() as _) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size() as _, Ordering::Relaxed);
        esp_idf_sys::free(ptr as *mut c_void)
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: Layout,
        new_size: usize
    ) -> *mut u8 { 
        let delta = (new_size as isize) - (layout.size() as isize);
        let val = self.current.fetch_add(delta, Ordering::Relaxed);
        self.max.fetch_max(val, Ordering::Relaxed);
        esp_idf_sys::realloc(ptr as *mut c_void, new_size as _) as *mut u8
    }    
}
