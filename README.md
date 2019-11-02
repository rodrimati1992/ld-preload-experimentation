## `poor-mans-binfmt-misc`

run programs from other architectures without prefixing it with qemu

most likely will break

### install

req:
 + rust
 + qemu-static

```bash
$ git clone https://github.com/kalmari246/poor-mans-binfmt-misc
$ cd poor-mans-binfmt-misc
$ cargo build --release
```

### usage

```bash
$ LD_PRELOAD=`realpath target/release/libpmbm.so` bash
$ ./some_program_that_isnt_your_architecture
$ # it runs!
$
```
