use std::time::Instant;

pub struct StackMeter {
    start : *mut u8,
    len : usize,
}

impl StackMeter {
    pub fn new(length : usize) -> Self {
        let start = Self::stack_pointer();
        for i in 16..length {
            unsafe {
                core::ptr::write_volatile(start.offset((i as isize) * -1), 0x55);
            }
        }

        Self {
            start,
            len : length,
        }
    }

  

    #[inline(always)]
    pub fn stack_pointer() -> *mut u8 {
        use core::arch::asm;
        let mut stack;
        unsafe {
            asm!("mv {}, sp", out(reg) stack);
        }
        stack
    }
    
    pub fn get(&self) -> usize {
        let mut stack_len = 0;
        for i in 16..self.len {
            unsafe {
                if core::ptr::read_volatile(self.start.offset((i as isize) * -1)) != 0x55 {
                    stack_len = i;
                }
            }
        }
        stack_len
    }
}

pub struct MeterResult {
    pub stack_len : usize,
    pub runtime : f32,
}

#[inline(never)]
pub fn meter<A, F : FnOnce()->A>(len : usize, f : F) -> (MeterResult, A) {
    let stack = StackMeter::new(len);
    let now = Instant::now();
    let ret = f();
    let runtime = (now.elapsed().as_micros() as f32) / 1_000_000f32;
    let stack_len = stack.get();
    (MeterResult {
        stack_len,
        runtime,
    }, ret)
} 

#[inline(never)]
pub fn stack_meter_test() {
    let mut x = [0u8;231];
    core::hint::black_box(&mut x[..]);
}
