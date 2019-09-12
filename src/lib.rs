use goblin::Object;
use itertools::Itertools;
use libc::c_char;
use path_dsl::path;
use std::{
    collections::HashMap,
    env,
    ffi::{self, CStr, CString},
    fs::File,
    io::Read,
    marker::PhantomData,
    mem,
    path::PathBuf,
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
                        .splitn(1, ':')
                        .map(|part| Some(part.to_owned()))
                        .tuples()
                        .next()
                        .unwrap_or((None, None));

                    if key.is_some() && val.is_some() {
                        map.insert(key.unwrap(), val.unwrap());
                    }
                }
                None => break,
            }
        }

        map
    }
}

#[no_mangle]
pub extern "C" fn execve(path: CBuf, args: Argv, env: Envp) -> ! {
    let path = path.to_path();
    let mut args = args.to_vec();
    let mut env = env.to_map();

    println!("pre-inject-path: {}", path.display());
    println!("pre-inject-args: {}", args.join(" "));

    let mut file = File::open(&path).expect("missing or permission denied");
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).expect("failed to read");

    let arch = match Object::parse(&buffer).expect("unable to parse as elf") {
        Object::Elf(elf) => match elf.header.e_machine {
            0x03 => "x86",
            0x3E => "x86_64",
            0x28 => "arm",
            0xB7 => "aarch64",
            _ => panic!("invalid architecture"),
        },
        _ => panic!("cannot execute"),
    };

    let path = if arch == env::consts::ARCH {
        path
    } else {
        let sysroot = path!("opt" | "pmbm" | arch);
        let qemu_ld_prefix = path!(sysroot | "lib");

        args.insert(0, format!("{}", path.display()));

        env.insert(
            "QEMU_LD_PREFIX".to_owned(),
            format!("{}", qemu_ld_prefix.into_pathbuf().display()),
        );

        which::which(format!("qemu-{}-static", arch)).expect("please install qemu-user-static")
    };

    println!("post-inject-path: {}", path.display());
    println!("post-inject-path: {}", args.join(" "));

    let path = CString::new(format!("{}", path.display()))
        .unwrap()
        .as_ptr() as *const c_char;

    let args = args
        .into_iter()
        .map(|arg| CString::new(arg).unwrap().as_ptr() as *const c_char)
        .collect::<Vec<*const c_char>>()
        .as_ptr() as *const *const c_char;

    let env = env
        .into_iter()
        .map(|(key, value)| {
            CString::new(format!("{}={}", key, value)).unwrap().as_ptr() as *const c_char
        })
        .collect::<Vec<*const c_char>>()
        .as_ptr() as *const *const c_char;

    unsafe {
        mem::transmute::<
            *const ffi::c_void,
            Option<
                unsafe extern "C" fn(
                    *const c_char,
                    *const *const c_char,
                    *const *const c_char,
                ) -> !,
            >,
        >(libc::dlsym(
            libc::RTLD_NEXT as *mut _,
            "execve\0".as_ptr() as *const _,
        ))
        .unwrap()(path, args, env)
    }
}
