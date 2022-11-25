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
    "p2p",
    "pasn",
    "radius",
    "rsn_supp",
    "tls",
    "utils",
    "wps",
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
        let search =  std::fs::canonicalize(
            PathBuf::from(SOURCE_DIR)
                .join(sublib)
        ).unwrap();

        println!("cargo:rustc-link-search={}", search.display());
        println!("cargo:rustc-link-lib=static={sublib}")
    }
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