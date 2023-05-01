#![no_std]
#![no_main]

use eap::environment::*;
use eap::layers::auth::{AuthIdentityMethod, AuthMD5ChallengeMethod};
use eap::layers::eap_layer::*;
use eap::layers::peer::{PeerIdentityMethod, PeerMD5ChallengeMethod};
use eap::layers::{AuthLayer, EapLayer, PeerLayer};
use eap::StaticEnvironment;
use esp_backtrace as _;

use esp_println::println;
use esp_println::print;

use hal::clock::CpuClock;
use hal::system::SystemParts;
use hal::systimer::SystemTimer;
use hal::{clock::ClockControl, peripherals::Peripherals, prelude::*, timer::TimerGroup, Rtc};

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take();
    let system = peripherals.SYSTEM.split();

    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock160MHz)
        .freeze();

    // Disable the RTC and TIMG watchdog timers
    let mut rtc = Rtc::new(peripherals.RTC_CNTL);
    let timer_group0 = TimerGroup::new(peripherals.TIMG0, &clocks);
    let mut wdt0 = timer_group0.wdt;
    let timer_group1 = TimerGroup::new(peripherals.TIMG1, &clocks);
    let mut wdt1 = timer_group1.wdt;


    rtc.swd.disable();
    rtc.rwdt.disable();
    wdt0.disable();
    wdt1.disable();

    let syst: SystemTimer = SystemTimer::new(peripherals.SYSTIMER);

    let stack_meter = StackMeter::new(4096);
    stack_meter_test();
    println!("Stack: {} expected: 231", stack_meter.get());

    const num : usize = 100;
    let mut runs = [0f64;num]; 
    for i in 0..num {
        let mut auth_env = StaticEnvironment::<256>::new(get_random);
        let mut peer_env = StaticEnvironment::<256>::new(get_random);
        let mut stats = Stats::new();

        let peer = PeerLayer::new()
            .with(PeerIdentityMethod::new("username".as_bytes()))
            .with(PeerMD5ChallengeMethod::new("password".as_bytes()));
        let mut peer: EapLayer<PeerLayer<(PeerIdentityMethod, PeerMD5ChallengeMethod)>> = EapLayer::new(peer);

        let auth = AuthLayer::new()
            .with(AuthIdentityMethod::new())
            .with(AuthMD5ChallengeMethod::new("password".as_bytes()));
        let mut auth = EapLayer::new(auth);


        // Prevent the compiler from allocating later
        core::hint::black_box(&mut auth_env);
        core::hint::black_box(&mut peer_env);
        core::hint::black_box(&mut peer);
        core::hint::black_box(&mut auth);
        core::hint::black_box(&mut stats);

        run(&mut auth_env, &mut peer_env, &mut stats, &mut peer, &mut auth);
        println!("Status {:?} {:?}", stats.status_auth, stats.status_peer);

        runs[i] = stats.total_run_time_s();
        stats.show_just_delta_time();

        if (i==num-1) {
            println!("\n\n\nPeerSize {} AuthSize {} EnvSize {}", 
                core::mem::size_of_val(&peer),
                core::mem::size_of_val(&auth),
                core::mem::size_of_val(&auth_env),
            );
            stats.show()
        };
    }

    println!("{:?}", runs);
    println!("AVG: {:?}", avg(&runs));
    println!("Variance {:?}", variance(&runs));
    println!("LEN: {:?}", runs.len());
    loop {}
}

#[inline(never)]
fn run(
    auth_env: &mut StaticEnvironment::<256>, 
    peer_env: &mut StaticEnvironment::<256>,
    status : &mut Stats,
    peer : &mut EapLayer<PeerLayer<(PeerIdentityMethod, PeerMD5ChallengeMethod)>>,
    auth : &mut EapLayer<AuthLayer<(AuthIdentityMethod, AuthMD5ChallengeMethod)>>,
) {
    let mut last_auth_message;
    let mut last_peer_message = false;

    let mut last_auth_status = EapStatus::Ok;
    let mut last_peer_status = EapStatus::Ok;


    for _ in 0..10 {
        let step = if last_peer_message {
            EapInput::Receive(peer_env.last_message_buffer().unwrap())
        } else {
            EapInput::Start
        };

        let EapOutput {
            status: auth_status,
            message: auth_message,
        } = status.track(|| 
            auth.step(&step, auth_env)
        );

        last_auth_message = auth_message.is_some();
        last_auth_status = auth_status;

        let step = if last_auth_message {
            EapInput::Receive(auth_env.last_message_buffer().unwrap())
        } else {
            EapInput::Timeout
        };

        let EapOutput {
            status: peer_status,
            message: peer_message,
        } = status.track(|| 
            peer.step(&step, peer_env)
        );

        last_peer_message = peer_message.is_some();
        last_peer_status = peer_status;

        if last_auth_status != EapStatus::Ok && last_peer_status != EapStatus::Ok {
            status.status_auth = last_auth_status;
            status.status_peer = last_peer_status;
            break;
        }
    }
}

fn get_random(buf: &mut [u8]) {
    // not that random, but okay for the demo.
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = i as u8 ^0x64;
    }
}


fn avg(values : &[f64]) -> f64 {
    values.iter().sum::<f64>() / (values.len() as f64)
}

fn variance(values : &[f64]) -> f64 {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|x| (x - mean)*(x - mean)).sum::<f64>() / n;
    variance
}



struct StackMeter {
    start : *mut u8,
    len : usize,
}

impl StackMeter {
    fn new(length : usize) -> Self {
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
    fn stack_pointer() -> *mut u8 {
        use core::arch::asm;
        let mut stack;
        unsafe {
            asm!("mv {}, sp", out(reg) stack);
        }
        stack
    }
    
    fn get(&self) -> usize {
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

#[inline(never)]
fn stack_meter_test() {
    let mut x = [0u8;231];
    core::hint::black_box(&mut x[..]);
}

struct Stats {
    pos : usize,
    times_start : [u64;20],
    times_end : [u64;20],
    stack : [usize;20],
    status_peer : EapStatus,
    status_auth : EapStatus,
}

impl Stats {
    fn new() -> Self {
        Self {
            pos : 0,
            times_start : [0;20],
            times_end : [0;20],
            stack : [0;20],
            status_peer : EapStatus::Ok,
            status_auth : EapStatus::Ok,
        }
    }

    fn track<A, F: FnOnce() -> A>(&mut self, f : F) -> A {
        if self.pos >= self.times_start.len() {
            self.pos = self.times_start.len() - 1;
        }
        let stack = StackMeter::new(1024);
        self.times_start[self.pos] = SystemTimer::now();
        let res = f();
        self.times_end[self.pos] = SystemTimer::now();
        self.stack[self.pos] = stack.get();
        self.pos += 1;
        res
    }

    fn total_run_time_s(&self) -> f64 {
        let mut total = 0f64;
        for i in 0..self.times_start.len() {
            let delta = (self.times_end[i] - self.times_start[i]) as f64 / (SystemTimer::TICKS_PER_SECOND) as f64;
            total += delta;
        }
        total
    } 

    fn show_just_delta_time(&self) {
        for i in 0..self.times_start.len() {
            let delta = (self.times_end[i] - self.times_start[i]) as f64 / (SystemTimer::TICKS_PER_SECOND) as f64 * 1000.0;
            if delta != 0.0 {
                print!("{}, ", delta);
            }
        }
        println!()
    }

    fn show(&self) {
        print!("Execution times (ms) :\n   ");
        let mut total = 0.0;
        for i in 0..self.times_start.len() {
            let delta = (self.times_end[i] - self.times_start[i]) as f64 / (SystemTimer::TICKS_PER_SECOND) as f64 * 1000.0;
            if delta != 0.0 {
                print!("{}, ", delta);
                total += delta;
            }
        }
        println!("\nTotal: {}ms", total);

        print!("Stack usage (bytes) :\n   ");
        let mut max = 0;
        for i in 0..self.stack.len() {
            if self.stack[i] != 0 {
                print!("{}, ", self.stack[i]);
                max = max.max(self.stack[i]);
            }
        }
        println!("\nMax: {} bytes", max);
        println!("Status: {:?} {:?}", self.status_peer, self.status_auth);
        println!("\n")
    }
}