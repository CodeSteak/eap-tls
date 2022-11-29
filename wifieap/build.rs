use std::{process::Command, path::{PathBuf}};

extern crate cc;
extern crate bindgen;

const SOURCE_DIR : &str = "./hostap/src/";

const SOURCE_LIBS : &[&str] = &[
    "ap",
    "common",
    "crypto",
    "eap_common",
    "eapol_auth",
    "eapol_supp",
    "eap_peer",
    "eap_server",
    "l2_packet",
    "radius",
    "rsn_supp",
    "tls",
    "utils",
    "wps",
];

// This needs (tag) hostap_2_9  (ca8c2bd28), later versions seem to fail.

// Adapted from Makefile
const BOTH_OBJECTS : &[&str] = &[ 
    "eap_common/eap_peap_common.c",
    "eap_common/eap_psk_common.c",
    "eap_common/eap_pax_common.c",
    "eap_common/eap_sake_common.c",
    "eap_common/eap_gpsk_common.c",
    "eap_common/chap.c",
];

const PEER_OBJECTS : &[&str] = &[
    "eap_peer/eap_tls.c",
    "eap_peer/eap_peap.c",
    "eap_peer/eap_ttls.c",
    "eap_peer/eap_md5.c",
    "eap_peer/eap_mschapv2.c",
    "eap_peer/mschapv2.c",
    "eap_peer/eap_otp.c",
    "eap_peer/eap_gtc.c",
    "eap_peer/eap_leap.c",
    "eap_peer/eap_psk.c",
    "eap_peer/eap_pax.c",
    "eap_peer/eap_sake.c",
    "eap_peer/eap_gpsk.c",
    "eap_common/eap_common.c",
    "eap_peer/eap_tls_common.c",
];

const SERVER_OBJECTS : &[&str] = &[
    "eap_server/eap_server_tls.c",
    "eap_server/eap_server_peap.c",
    "eap_server/eap_server_ttls.c",
    "eap_server/eap_server_md5.c",
    "eap_server/eap_server_mschapv2.c",
    "eap_server/eap_server_gtc.c",
    "eap_server/eap_server_psk.c",
    "eap_server/eap_server_pax.c",
    "eap_server/eap_server_sake.c",
    "eap_server/eap_server_gpsk.c",
    "eap_server/eap_server.c",
    "eap_server/eap_server_identity.c",
    "eap_server/eap_server_methods.c",
    "eap_server/eap_server_tls_common.c",
];

fn main() {
    build_hostap();
    bindgen_hostap();
}

fn build_hostap() {    
    Command::new("make")
        .current_dir(SOURCE_DIR)
        .status()
        .expect("Failed running make to build");

    for sublib in SOURCE_LIBS {
        eprintln!("Adding lib:{}", sublib);
        let search =  std::fs::canonicalize(
            PathBuf::from(SOURCE_DIR)
                .join(sublib)
        ).unwrap();

        println!("cargo:rustc-link-search={}", search.display());
        println!("cargo:rustc-link-lib=static={sublib}")
    }

    lib_from_objects("methods_both", BOTH_OBJECTS);
    lib_from_objects("methods_peer", PEER_OBJECTS);
    lib_from_objects("methods_server", SERVER_OBJECTS);
}

fn lib_from_objects(label : &str, files : &[&str]) {
    let mut build = cc::Build::new();

    for f in files {
        build.file(PathBuf::from(SOURCE_DIR).join(f).canonicalize().unwrap());
    }

    build.includes(includes());

    build.compile(label);
    println!("cargo:rustc-link-lib=static={label}");
}

fn includes() -> Vec<PathBuf> {
    vec![
        PathBuf::from(SOURCE_DIR).canonicalize().unwrap(),
        PathBuf::from(SOURCE_DIR).join("utils").canonicalize().unwrap(),
        PathBuf::from(SOURCE_DIR).join("../").canonicalize().unwrap(),
    ]
}

fn bindgen_hostap() {
    let builder = bindgen::Builder::default()
        .clang_arg(format!("-I{SOURCE_DIR}"))
        .clang_arg(format!("-I{SOURCE_DIR}utils"))
        .clang_arg(format!("-I{SOURCE_DIR}../"))
        .clang_arg("-DIEEE8021X_EAPOL");

    println!("cargo:rerun-if-changed=header_peer.h");
    builder.clone()
        .header("header_peer.h")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/bindings_peer.rs")
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=header_server.h");
    builder
        .header("header_server.h")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/bindings_server.rs")
        .expect("Couldn't write bindings!");
}