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

#[repr(transparent)]
pub struct CPath<'a> {
    data: *mut c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> CPath<'a> {
    pub fn to_path_buf(&self) -> PathBuf {
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
        let mut i = 0isize;
        let mut buffer = Vec::new();

        loop {
            match unsafe { self.data.offset(i).as_ref() } {
                Some(&val) => {
                    buffer.push(unsafe { CStr::from_ptr(val) }.to_string_lossy().to_string())
                }
                None => break,
            }

            i += 1;
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
        let mut i = 0isize;
        let mut map = HashMap::new();

        unsafe {
            loop {
                match self.data.offset(i).as_ref() {
                    Some(&val) => {
                        let (key, val) = CString::from_raw(val)
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

                i += 1;
            }
        }

        map
    }
}

#[no_mangle]
pub unsafe extern "C" fn execl(path: CPath, mut argv: VaList) -> ! {
    println!("execl");
    exec(path.to_path_buf(), argv.into_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execlp(path: CPath, mut argv: VaList) -> ! {
    println!("execlp");
    exec(path.to_path_buf(), argv.into_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execle(path: CPath, mut argv: VaList, envp: Envp) -> ! {
    println!("execle");
    exec(path.to_path_buf(), argv.into_vec(), envp.to_hash_map())
}

#[no_mangle]
pub unsafe extern "C" fn execv(path: CPath, argv: Argv) -> ! {
    println!("execv");
    exec(path.to_path_buf(), argv.to_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execvp(path: CPath, argv: Argv) -> ! {
    println!("execvp");
    exec(path.to_path_buf(), argv.to_vec(), env::vars().collect())
}

#[no_mangle]
pub unsafe extern "C" fn execvpe(path: CPath, argv: Argv, envp: Envp) -> ! {
    println!("execvpe");
    exec(path.to_path_buf(), argv.to_vec(), envp.to_hash_map())
}

fn exec(program: PathBuf, mut args: Vec<String>, mut env: HashMap<String, String>) -> ! {
    println!("exec: {:?} {}", program, args.join(" "));

    let mut file = File::open(&program).unwrap();
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).unwrap();

    let elf = match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => elf,
        _ => panic!(),
    };

    let arch = match elf.header.e_machine {
        0x03 => "x86",
        0x3E => "x86_64",
        0x28 => "arm",
        0xB7 => "aarch64",
        _ => panic!(),
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
            "execvpe\0".as_ptr() as *const _,
        ))
        .unwrap()(argv0, argv, envp)
    }
}
