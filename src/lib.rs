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
use va_list::VaList;

trait VaListArgvExt {
    fn into_vec(&mut self) -> Vec<String>;
}

impl VaListArgvExt for VaList {
    fn into_vec(&mut self) -> Vec<String> {
        let mut buffer = Vec::new();

        loop {
            let ptr = unsafe { self.get::<*const c_char>() };

            if !ptr.is_null() {
                buffer.push(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().to_string());
            } else {
                break;
            }
        }

        buffer
    }
}

pub enum PathOrFile {
    File(String),
    Path(PathBuf),
}

#[repr(transparent)]
pub struct CBuf<'a> {
    data: *mut c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> CBuf<'a> {
    pub fn to_file(&self) -> PathOrFile {
        PathOrFile::File(
            unsafe { CStr::from_ptr(self.data) }
                .to_string_lossy()
                .to_string(),
        )
    }

    pub fn to_path(&self) -> PathOrFile {
        PathOrFile::Path(
            unsafe { CStr::from_ptr(self.data) }
                .to_string_lossy()
                .to_string()
                .into(),
        )
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
    pub fn to_hash_map(&self) -> HashMap<String, String> {
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
pub unsafe extern "C" fn execl(path: CBuf, mut argv: VaList) -> ! {
    print!("execl");
    exec(path.to_path(), argv.into_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execlp(path: CBuf, mut argv: VaList) -> ! {
    print!("execlp");
    exec(path.to_file(), argv.into_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execle(path: CBuf, mut argv: VaList, envp: Envp) -> ! {
    print!("execle");
    exec(path.to_path(), argv.into_vec(), envp.to_hash_map())
}

#[no_mangle]
pub unsafe extern "C" fn execv(path: CBuf, argv: Argv) -> ! {
    print!("execv");
    exec(path.to_path(), argv.to_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execve(path: CBuf, argv: Argv, envp: Envp) -> ! {
    print!("execve");
    exec(path.to_path(), argv.to_vec(), envp.to_hash_map())
}

#[no_mangle]
pub unsafe extern "C" fn execvp(path: CBuf, argv: Argv) -> ! {
    print!("execvp");
    exec(path.to_file(), argv.to_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execvpe(path: CBuf, argv: Argv, envp: Envp) -> ! {
    print!("execvpe");
    exec(path.to_file(), argv.to_vec(), envp.to_hash_map())
}

fn exec(program: PathOrFile, mut args: Vec<String>, mut env: HashMap<String, String>) -> ! {
    let program = match program {
        PathOrFile::File(file) => which::which(file).expect("cannot find program"),
        PathOrFile::Path(path) => path,
    };

    println!(": {:?}", program);
    println!("    args: {}", args.join(" "));

    let mut file = File::open(&program).expect("failed open file");
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).expect("failed to read elf");

    let arch = match Object::parse(&buffer).expect("unable to parse elf") {
        Object::Elf(elf) => match elf.header.e_machine {
            0x03 => "x86",
            0x3E => "x86_64",
            0x28 => "arm",
            0xB7 => "aarch64",
            _ => panic!("invalid architecture"),
        },
        _ => panic!("cannot execute"),
    };

    let target_path = if arch == env::consts::ARCH {
        format!("{}", program.display())
    } else {
        let sysroot = path!("opt" | "pmbm" | arch);
        let qemu_ld_prefix = path!(sysroot | "lib");

        args.insert(0, format!("{}", program.display()));

        env.insert(
            "QEMU_LD_PREFIX".to_owned(),
            format!("{}", qemu_ld_prefix.into_pathbuf().display()),
        );

        format!("qemu-{}-static", arch)
    };

    println!("    post-exec: {:?}", program);
    println!("    post-args: {}", args.join(" "));

    let argv0 = CString::new(target_path).unwrap().as_ptr() as *const c_char;

    let argv = args
        .into_iter()
        .map(|arg| CString::new(arg).unwrap().as_ptr() as *const c_char)
        .collect::<Vec<*const c_char>>()
        .as_ptr() as *const *const c_char;

    let envp = env
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
        .unwrap()(argv0, argv, envp)
    }
}
