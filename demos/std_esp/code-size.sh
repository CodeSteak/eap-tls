set -ev

# function 
function build() {
    cargo rustc --release -- $* 1>/dev/null 2>/dev/null
    echo "$*: "
    espflash save-image ESP32-C3 ./target/riscv32imc-esp-espidf/release/demo_std_esp  img.tmp
    stat --format=%s img.tmp
    rm img.tmp
    echo ""
}

function build_no_tls() {
    cargo rustc --release --no-default-features -- $* 1>/dev/null 2>/dev/null
    echo "$*: "
    espflash save-image ESP32-C3 ./target/riscv32imc-esp-espidf/release/demo_std_esp  img.tmp
    stat --format=%s img.tmp
    rm img.tmp
    echo ""
}


build -C opt-level=0
build -C opt-level=1
build -C opt-level=2
build -C opt-level=3
build -C opt-level=s 
build -C opt-level=s -C panic=abort
build -C opt-level=s -C panic=abort -C codegen-units=1


build_no_tls -C opt-level=0
build_no_tls -C opt-level=1
build_no_tls -C opt-level=2
build_no_tls -C opt-level=3
build_no_tls -C opt-level=s 
build_no_tls -C opt-level=s -C panic=abort
build_no_tls -C opt-level=s -C panic=abort -C codegen-units=1
