use std::{path::PathBuf, process::Command};

extern crate bindgen;
extern crate cc;

const SOURCE_DIR: &str = "./hostap/src/";

const SOURCE_LIBS: &[&str] = &[
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
const PEER_OBJECTS: &[&str] = &[
    "eap_peer/eap_tls.c",
    "eap_peer/eap_md5.c",
    "eap_peer/eap_tls_common.c",
];

const SERVER_OBJECTS: &[&str] = &[
    "eap_server/eap_server_tls.c",
    "eap_server/eap_server_md5.c",
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
        patch_makefile(sublib);
        eprintln!("Adding lib:{sublib}");
        let search = std::fs::canonicalize(PathBuf::from(SOURCE_DIR).join(sublib)).unwrap();

        println!("cargo:rustc-link-search={}", search.display());
        println!("cargo:rustc-link-lib=static={sublib}")
    }

    lib_from_objects("methods_peer", PEER_OBJECTS);
    lib_from_objects("methods_server", SERVER_OBJECTS);
}

fn patch_makefile(sublib: &str) {
    // Newer lld(?) version seem to fail with thin archives
    eprintln!("In case of error, try to use ld.gold");

    let from = "$(AR) crT $@ $?";
    let to = "$(AR) cr $@ $?";
    // So we patch the Makefile to use the old style. This is a bit of a hack, but it works.
    // Alternative would be build custom makefile, but that would be more work.
    let lib_path = PathBuf::from(SOURCE_DIR).join(sublib);
    let makefile = lib_path.join("Makefile");
    let mut contents = std::fs::read_to_string(&makefile).unwrap();
    if !contents.contains(from) {
        return; // everything is fine
    }
    contents = contents.replace(from, to);
    std::fs::write(&makefile, contents).unwrap();

    // rebuild
    Command::new("make")
        .arg("clean")
        .current_dir(&lib_path)
        .status()
        .expect("Failed running make to clean");

    Command::new("make")
        .current_dir(&lib_path)
        .status()
        .expect("Failed running make");
}

fn lib_from_objects(label: &str, files: &[&str]) {
    let mut build = cc::Build::new();
    build.warnings(false);
    build.flag("-w");

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
        PathBuf::from(SOURCE_DIR)
            .join("utils")
            .canonicalize()
            .unwrap(),
        PathBuf::from(SOURCE_DIR)
            .join("../")
            .canonicalize()
            .unwrap(),
    ]
}

fn bindgen_hostap() {
    let builder = bindgen::Builder::default()
        .clang_arg(format!("-I{SOURCE_DIR}"))
        .clang_arg(format!("-I{SOURCE_DIR}utils"))
        .clang_arg(format!("-I{SOURCE_DIR}../"))
        .clang_arg("-DIEEE8021X_EAPOL");

    println!("cargo:rerun-if-changed=header_peer.h");
    builder
        .clone()
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
