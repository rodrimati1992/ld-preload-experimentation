just me messing with ld-preload and qemu

```rust
git clone https://github.com/kalmari246/kql
cd kql
cargo build --release
LD_PRELOAD=`realpath target/release/libkql.so` bash
...
```
