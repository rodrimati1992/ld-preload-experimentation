## `https://github.com/kalmari246/poor-mans-binfmt-misc`

wip project

run programs from other architectures without prefixing it with qemu

### install

```bash
$ git clone https://github.com/kalmari246/poor-mans-binfmt-misc
$ cd poor-mans-binfmt-misc
$ cargo build --release
```

### usage

```bash
$ LD_PRELOAD=`realpath target/release/libpmbm.so` bash
$ ./some_x86-64_program
$ # it runs!
$
```
