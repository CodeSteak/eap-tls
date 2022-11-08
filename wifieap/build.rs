extern crate cc;
extern crate bindgen;



fn main() {
    build_hostap();
    bindgen_hostap();
}

fn build_hostap() {
    let mut build = cc::Build::new();

    build.include("./ppp/pppd")
        .include("./ppp/pppd/plugins/pppoe");

    build.define("HAVE_CONFIG_H", None)
        .define("SYSCONFDIR", Some("\"/usr/local/etc\""))
        .define("LOCALSTATEDIR", Some("\"/usr/local/var\""))
        .define("PPPD_RUNTIME_DIR", Some("\"/usr/local/var/run/pppd\""))
        .define("PPPD_LOGFILE_DIR", Some("\"/usr/local/var/log/ppp\""))
        .define("PPPD_PLUGIN_DIR", Some("\"/usr/local/lib/pppd/2.4.10-dev\""));

    build
        .flag("-Wno-deprecated-declarations") // ppp uses deprecated ssl functions
        .opt_level(2)
        .warnings(false)
        .debug(true);

    for c_file in C_FILES.split_whitespace() {
        // May cause recompliation because of autoconf output
        // println!("cargo:rerun-if-changed=./ppp/pppd/{}", c_file);
        build.file(format!("./ppp/pppd/{}", c_file));
    }

    build.compile("pppd");

    println!("cargo:rustc-link-lib=static=pppd");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypt");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pcap");
    println!("cargo:rustc-link-lib=pam");
}

fn bindgen_hostap() {
    //let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=header.h");

    bindgen::Builder::default()
        .clang_arg("-I./ppp/pppd")
        .clang_arg("-I./ppp/pppd/plugins/pppoe")
        .clang_arg("-DHAVE_CONFIG_H")
        .header("header.h")
        .generate()
        .expect("Unable to generate bindings")
        //.write_to_file(out_path.join("bindings.rs"))
        .write_to_file("src/bindings.rs")
        .expect("Couldn't write bindings!");
}