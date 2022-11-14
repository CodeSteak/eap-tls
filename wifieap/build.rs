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
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    
    Command::new("make")
        .current_dir(SOURCE_DIR)
        .status()
        .expect("Failed running make to build");

    for sublib in SOURCE_LIBS {
        /*let libfile = format!("lib{sublib}.a");

        let src = PathBuf::from(SOURCE_DIR)
            .join(sublib)
            .join(&libfile);

        let dest = out_path.join(&libfile);

        dbg!(&src);
        dbg!(&dest);

        std::fs::copy(src, dest).expect("Failed coping lib");*/

        let search =  std::fs::canonicalize(
            PathBuf::from(SOURCE_DIR)
                .join(sublib)
        ).unwrap();

        println!("cargo:rustc-link-search={}", search.display());
        println!("cargo:rustc-link-lib=static={sublib}")
    }
}

fn bindgen_hostap() {
    //let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=header.h");

    let builder = bindgen::Builder::default()
        .clang_arg(format!("-I{SOURCE_DIR}"))
        .clang_arg(format!("-I{SOURCE_DIR}utils"))
        .clang_arg(format!("-I{SOURCE_DIR}../"))
        .clang_arg("-DIEEE8021X_EAPOL");


    builder.header("header.h")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/bindings.rs")
        .expect("Couldn't write bindings!");
}