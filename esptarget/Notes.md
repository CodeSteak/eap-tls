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

# Fix Ring by 
```
git clone https://github.com/briansmith/ring
wget https://github.com/briansmith/ring/pull/1174.patch
cd ring
git checkout 9cc0d45f
git apply ../1174.patch
```

also stolen from
https://github.com/briansmith/ring/compare/main...killyourphone:ring:esp32
https://github.com/briansmith/ring/pull/1436/files