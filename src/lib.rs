use ffi_support::FfiStr;
use goblin::Object;
use itertools::Itertools;
use libc::c_char;
use path_dsl::path;
use std::{
    collections::HashMap,
    env,
    ffi::{self, CString},
    fs::File,
    io::Read,
    marker::PhantomData,
    mem,
    path::PathBuf,
};
use va_list::VaList;

trait VaListExt {
    fn into_vec<T: 'static, U, F: Fn(&T) -> U>(&mut self, transform: F) -> Vec<U>;
}

impl VaListExt for VaList {
    fn into_vec<T: 'static, U, F: Fn(&T) -> U>(&mut self, transform: F) -> Vec<U> {
        let mut buffer = Vec::new();

        loop {
            match unsafe { self.get::<*const T>().as_ref() } {
                Some(val) => buffer.push(transform(val)),
                None => break,
            }
        }

        buffer
    }
}

#[repr(transparent)]
pub struct CArray<'a, T> {
    ptr: *mut T,
    _boo: PhantomData<&'a ()>,
}

impl<'a, T> CArray<'a, T> {
    pub fn to_vec<U, F: Fn(&T) -> U>(&self, transform: F) -> Vec<U> {
        let mut i = 0isize;
        let mut buffer = Vec::new();

        loop {
            match unsafe { (self.ptr.offset(i) as *mut T).as_ref() } {
                Some(val) => buffer.push(transform(val)),
                None => break,
            }

            i += 1;
        }

        buffer
    }
}

#[no_mangle]
pub unsafe extern "C" fn execl(path: FfiStr, mut argv: VaList) -> ! {
    exec(
        path.as_str().to_owned().into(),
        argv.into_vec(|arg: &FfiStr| arg.as_str().to_owned()),
        env::vars().collect(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn execlp(file: FfiStr, mut argv: VaList) -> ! {
    exec(
        file.as_str().to_owned().into(),
        argv.into_vec(|arg: &FfiStr| arg.as_str().to_owned()),
        env::vars().collect(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn execle(file: FfiStr, mut argv: VaList, envp: CArray<FfiStr>) -> ! {
    exec(
        file.as_str().to_owned().into(),
        argv.into_vec(|arg: &FfiStr| arg.as_str().to_owned()),
        envp.to_vec(|env| {
            let (key, value) = env
                .as_str()
                .to_owned()
                .splitn(1, ':')
                .map(|part| Some(part.to_owned()))
                .tuples()
                .next()
                .unwrap_or((None, None));

            if key.is_some() && value.is_some() {
                Some((key.unwrap(), value.unwrap()))
            } else {
                None
            }
        })
        .into_iter()
        .filter_map(|pair| pair)
        .collect(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn execv(path: FfiStr, argv: CArray<FfiStr>) -> ! {
    exec(
        path.as_str().to_owned().into(),
        argv.to_vec(|arg| arg.as_str().to_owned()),
        env::vars().collect(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn execvp(file: FfiStr, argv: CArray<FfiStr>) -> ! {
    exec(
        file.as_str().to_owned().into(),
        argv.to_vec(|arg| arg.as_str().to_owned()),
        env::vars().collect(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn execvpe(file: FfiStr, argv: CArray<FfiStr>, envp: CArray<FfiStr>) -> ! {
    exec(
        file.as_str().to_owned().into(),
        argv.to_vec(|arg| arg.as_str().to_owned()),
        envp.to_vec(|env| {
            let (key, value) = env
                .as_str()
                .to_owned()
                .splitn(1, ':')
                .map(|part| Some(part.to_owned()))
                .tuples()
                .next()
                .unwrap_or((None, None));

            if key.is_some() && value.is_some() {
                Some((key.unwrap(), value.unwrap()))
            } else {
                None
            }
        })
        .into_iter()
        .filter_map(|pair| pair)
        .collect(),
    )
}

fn exec(program: PathBuf, args: Vec<String>, mut env: HashMap<String, String>) -> ! {
    let mut file = File::open(program).unwrap();
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).unwrap();

    let elf = match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => elf,
        _ => panic!(),
    };

    let arch = match elf.header.e_machine {
        //0x2 => "sparc",
        0x3 => "x86",
        //0x8 => "mips",
        //0x14 => "powerpc",
        //0x16 => "s390",
        0x28 => "arm",
        //0x2A => "superh",
        //0x32 => "ia-64",
        0x3E => "x86_64",
        0xB7 => "aarch64",
        //0xF3 => "risc-v",
        _ => panic!(),
    };

    let target_path = if arch == env::consts::ARCH {
        format!("{}", program.display())
    } else {
        let sysroot = path!("opt" | "pmbm" | arch);
        let qemu_ld_prefix = path!(sysroot | "lib");

        args.insert(0, format!("{}", program.display());

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
