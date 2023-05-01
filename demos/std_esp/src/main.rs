use std::{
    ffi::c_void,
    time::{Duration, Instant, SystemTime},
};

use eap;
use esp_idf_sys as _;

mod stats;
mod mon_alloc;

use stats::meter;
use eap::*;


#[global_allocator]
static ALLOCATOR : mon_alloc::MonitoringAllocator = mon_alloc::MonitoringAllocator::new();


fn main() {
    esp_idf_sys::link_patches();

    unsafe {
        let ticks = esp_idf_sys::ets_get_cpu_frequency();
        println!("CPU frequency: {} MHz", ticks);
    }

    unsafe {
        let unix_time = 1680300000;
        let now = esp_idf_sys::timespec {
            tv_sec: unix_time,
            tv_nsec: 0,
        };
        assert!(esp_idf_sys::clock_settime(1, &now) == 0);
    }

    let mut stack_cfg = unsafe { esp_idf_sys::esp_pthread_get_default_config() };
    stack_cfg.stack_size = 64 * 1024;
    unsafe {
        assert!(esp_idf_sys::esp_pthread_set_cfg(&stack_cfg) == 0);
    }

    let mut thread = esp_idf_sys::pthread_t::default();
    unsafe {
        extern "C" fn run_wrapper(_: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
            main2();
            std::ptr::null_mut()
        }
        esp_idf_sys::pthread_create(
            &mut thread,
            std::ptr::null(),
            Some(run_wrapper),
            std::ptr::null_mut(),
        );
    }
}

fn main2() {
    for i in 0..3 {
        println!("\nMD5 {i} \n{:?}", run(|| (
            Authenticator::new_password("1234"),
            Peer::new_password("hans", "1234"),
        )));

        #[cfg(feature = "tls")]
        println!("\nTLS {i} ED25519 \n{:?}", run(|| (
            Authenticator::new_tls(TlsConfig::dummy_server_ed25519()),
            Peer::new_tls("hans", TlsConfig::dummy_client_ed25519()),
        )));

        #[cfg(feature = "tls")]
        println!("\nTLS {i} RSA 2048 \n{:?}", run(|| (
            Authenticator::new_tls(TlsConfig::dummy_server_rsa()),
            Peer::new_tls("hans", TlsConfig::dummy_client_rsa()),
        )));
    }

    println!("Runtimes");

    println!("\nMD5 \n{:?}", benchmark(|| (
        Authenticator::new_password("1234"),
        Peer::new_password("hans", "1234"),
    )));

    #[cfg(feature = "tls")]
    println!("\nTLS ED25519 \n{:?}", benchmark(|| (
        Authenticator::new_tls(TlsConfig::dummy_server_ed25519()),
        Peer::new_tls("hans", TlsConfig::dummy_client_ed25519()),
    )));

    #[cfg(feature = "tls")]
    println!("\nTLS RSA 2048 \n{:?}", benchmark(|| (
        Authenticator::new_tls(TlsConfig::dummy_server_rsa()),
        Peer::new_tls("hans", TlsConfig::dummy_client_rsa()),
    )));

}

#[derive(Debug)]
struct Stats {
    stack_size : usize,
    heap_size : usize,
    iterations : usize,
    runtime : f32,
    steps_runtime : Vec<f32>,
    create_runtime : f32,
    create_stack : usize,
}

fn run<A : EapWrapper, B: EapWrapper, F : FnOnce() -> (A,B)>(
    f : F
) -> Stats {
    yield_task();


    let mut stack_size = 0;
    let mut runtime = 0.0;
    let mut steps_runtime = Vec::with_capacity(20); // Preallocate, don't mess with measurement.

    ALLOCATOR.reset();

    let (c, (mut server, mut client)) = meter(16*1024, f);

    for i in 0..10 {
        let (u, res_server) = meter(16*1024, || server.step());
        if let Some(buffer) = &res_server.response {
            client.receive(buffer);
        }
        stack_size = stack_size.max(u.stack_len);
        runtime += u.runtime;
        steps_runtime.push(u.runtime);

        let server_status = res_server.status;
        let _ = res_server;

        let (u, res_client) = meter(16*1024, || client.step());
        if let Some(buffer) = &res_client.response {
            server.receive(buffer);
        }
        stack_size = stack_size.max(u.stack_len);
        runtime += u.runtime;
        steps_runtime.push(u.runtime);

        if server_status != AuthenticatorStepStatus::Ok
            && res_client.status != PeerStepStatus::Ok
        {
            let heap_size = ALLOCATOR.get_max() as usize;

            let steps_runtime = (&steps_runtime[..]).to_vec(); // reallocate to free

            assert_eq!(server_status, AuthenticatorStepStatus::Finished);
            assert_eq!(res_client.status, PeerStepStatus::Finished);

            return Stats {
                runtime,
                stack_size,
                heap_size,
                iterations : i,
                create_runtime: c.runtime,
                create_stack: c.stack_len,
                steps_runtime
            };
        }
    }   
    panic!("Too many iterations.")
}

#[derive(Debug)]
struct RunTimeInfo {
    len : usize,
    avg : f32,
    stddev : f32,
    avg_steps : Vec<f32>,
    stddev_steps : Vec<f32>,
}

fn benchmark<A : EapWrapper, B: EapWrapper, F : Fn() -> (A,B)>(
    f : F
) -> RunTimeInfo {
    let mut runs = vec![0f32; 1000];
    let mut runs_steps = vec![vec![]; 10];

    for r in runs.iter_mut() {
        print!(".");
        let res = run(|| f());
        *r = res.runtime;
    }

    // Only Ten
    for r in runs_steps.iter_mut() {
        print!("#");
        let res = run(|| f());
        *r = res.steps_runtime;
    }

    print!("\n");

    fn avg(values : &[f32]) -> f32 {
        values.iter().sum::<f32>() / (values.len() as f32)
    }
    
    fn stddev(values : &[f32]) -> f32 {
        let n = values.len() as f32;
        let mean = values.iter().sum::<f32>() / n;
        let variance = values.iter().map(|x| (x - mean)*(x - mean)).sum::<f32>() / n;
        variance.sqrt()
    }

    fn transpose<A : Copy>(matrix : Vec<Vec<A>>) -> Vec<Vec<A>> {
        let len = matrix[0].len();
        let mut res = vec![vec![]; len];
        for row in matrix {
            assert_eq!(len, row.len());
            for (i, val) in row.into_iter().enumerate() {
                res[i].push(val);
            }
        }
        res
    }

    let runs_steps = transpose(runs_steps);
    RunTimeInfo {
        len: runs.len(),
        avg: avg(&runs),
        stddev : stddev(&runs),
        avg_steps : runs_steps.iter().map(|x| avg(x)).collect(),
        stddev_steps : runs_steps.iter().map(|x| stddev(x)).collect(),
    }
}




// prevents watchdog from triggering
fn yield_task() {
    unsafe {
        esp_idf_sys::vTaskDelay(1 );
    }
}