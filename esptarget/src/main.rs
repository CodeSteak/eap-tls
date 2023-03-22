use std::{
    ffi::c_void,
    time::{Duration, Instant, SystemTime},
};

use eap;
use esp_idf_sys as _;

use eap::*;

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
            run(true, true);
            run(true, false);

            run(false, true);
            run(false, false);

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

fn print_heap() {
    let heap = unsafe { esp_idf_sys::esp_get_free_heap_size() };
    println!("free heap: {}", heap);
}

fn print_unix_time() {
    let unix_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("unix time: {}\n", unix_time);
}

fn run(print: bool, ed: bool) {
    print!("print={print} ed={ed}");
    print_unix_time();

    let mut server = Authenticator::new_tls(if ed {
        TlsConfig::dummy_server_ed25519()
    } else {
        TlsConfig::dummy_client_rsa()
    });

    let mut client = Peer::new_tls(
        "user",
        if ed {
            TlsConfig::dummy_client_ed25519()
        } else {
            TlsConfig::dummy_client_rsa()
        },
    );

    let start = Instant::now();

    for i in 0..100 {
        if print {
            println!("=== {i}");
            print_heap();
        }

        if print {
            println!("== SERVER");
            print_heap();
        }
        let res_server = server.step();
        if let Some(buffer) = &res_server.response {
            if print {
                hex_dump("S->P", buffer);
            }
            client.receive(buffer);
        }

        if print {
            println!("== PEER");
            print_heap();
        }

        let res_client = client.step();
        if let Some(buffer) = &res_client.response {
            if print {
                hex_dump("P->S", buffer);
            }
            server.receive(buffer);
        }

        if res_server.status != AuthenticatorStepStatus::Ok
            || res_client.status != PeerStepStatus::Ok
        {
            if print {
                println!(
                    "peer {:?} server {:?}",
                    &res_client.status, &res_server.status
                );
            }
            break;
        }
    }

    let elapsed = start.elapsed();

    println!("Elapsed: {:#?}", elapsed);

    std::thread::sleep(Duration::from_secs(10));
}

fn hex_dump(label: &str, data: &[u8]) {
    println!("{label:10}");

    for line in data.chunks(16) {
        for byte in line {
            print!("{byte:02x} ",);
        }
        print!(" | ");

        for byte in line {
            if *byte >= 32 && *byte < 127 {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }

        println!();
    }
}
