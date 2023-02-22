# https://esp-rs.github.io/book/installation/installation.html

```
install https://aur.archlinux.org/packages/esp-idf

cargo install espup

espup install 

cargo install espflash
## cargo +esp build -Zbuild-std=std,panic_abort --target riscv32imc-esp-espidf
```

Template is here:
https://github.com/esp-rs/esp-idf-template