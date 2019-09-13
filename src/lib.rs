use goblin::Object;
use itertools::Itertools;
use libc::{c_char, c_int};
use path_dsl::path;
use std::{
    collections::HashMap,
    env,
    ffi::{CStr, CString},
    fs::File,
    io::Read,
    marker::PhantomData,
    path::PathBuf,
    ptr,
};

#[repr(transparent)]
pub struct CBuf<'a> {
    data: *mut c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> CBuf<'a> {
    pub fn to_path(&self) -> PathBuf {
        unsafe { CStr::from_ptr(self.data) }
            .to_string_lossy()
            .to_string()
            .into()
    }
}

#[repr(transparent)]
pub struct Argv<'a> {
    data: *const *mut c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> Argv<'a> {
    pub fn to_vec(&self) -> Vec<String> {
        let mut buffer = Vec::new();

        for i in 0.. {
            match unsafe { (*self.data.offset(i)).as_ref() } {
                Some(val) => {
                    buffer.push(unsafe { CStr::from_ptr(val) }.to_string_lossy().to_string())
                }
                None => break,
            }
        }

        buffer
    }
}

#[repr(transparent)]
pub struct Envp<'a> {
    data: *const *mut c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> Envp<'a> {
    pub fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        for i in 0.. {
            match unsafe { (*self.data.offset(i)).as_ref() } {
                Some(val) => {
                    let (key, val) = unsafe { CStr::from_ptr(val) }
                        .to_string_lossy()
                        .to_string()
                        .splitn(2, '=')
                        .map(|part| part.to_owned())
                        .next_tuple()
                        .unwrap();

                    map.insert(key, val);
                }
                None => break,
            }
        }

        map
    }
}

pub fn real_execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe {
        let symbol = CString::new("execve").unwrap();
        let raw = libc::dlsym(libc::RTLD_NEXT, symbol.as_ptr());
        let fun = std::mem::transmute::<
            *const _,
            unsafe extern "C" fn(
                *const c_char,
                *const *const c_char,
                *const *const c_char,
            ) -> c_int,
        >(raw);
        fun(path, argv, envp)
    }
}

#[no_mangle]
pub extern "C" fn execve(path: CBuf, args: Argv, env: Envp) -> c_int {
    let path = path.to_path();
    let mut args = args.to_vec();
    let mut env = env.to_map();

    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(_) => return libc::EACCES,
    };

    let mut buffer = Vec::new();

    match file.read_to_end(&mut buffer) {
        Err(_) => return libc::EACCES,
        _ => (),
    }

    let arch = match Object::parse(&buffer) {
        Ok(Object::Elf(elf)) => match elf.header.e_machine {
            0x03 => "x86",
            0x3E => "x86_64",
            0x28 => "arm",
            0xB7 => "aarch64",
            _ => return libc::ENOEXEC,
        },
        // Handle shebangs
        // Err(_) =>
        _ => return libc::ENOEXEC,
    };

    let path = if arch == env::consts::ARCH {
        path
    } else {
        let sysroot = path!("opt" | "pmbm" | arch);
        let qemu =
            which::which(format!("qemu-{}-static", arch)).expect("please install qemu-user-static");
        let qemu_ld_prefix = path!(sysroot | "lib");

        args.insert(0, format!("{}", qemu.display()));

        env.remove("LD_PRELOAD");
        env.insert(
            "QEMU_LD_PREFIX".to_owned(),
            format!("{}", qemu_ld_prefix.into_pathbuf().display()),
        );

        qemu
    };

    let path = CString::new(format!("{}", path.display())).unwrap();

    let args: Vec<_> = args
        .into_iter()
        .map(|arg| CString::new(arg).unwrap())
        .collect();

    let mut args: Vec<_> = args.iter().map(|arg| arg.as_ptr()).collect();

    args.push(ptr::null());

    let env: Vec<_> = env
        .into_iter()
        .map(|(key, value)| CString::new(format!("{}={}", key, value)).unwrap())
        .collect();

    let mut env: Vec<_> = env.iter().map(|env| env.as_ptr()).collect();

    env.push(ptr::null());

    real_execve(path.as_ptr(), args.as_ptr(), env.as_ptr())
}
