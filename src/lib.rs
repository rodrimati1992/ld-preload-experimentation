use {
    goblin::Object,
    libc::{c_char, c_int, dlsym, EACCES, ENOEXEC, RTLD_NEXT},
    null_terminated::{Nul, NulStr},
    std::{
        collections::{HashMap, VecDeque},
        env,
        ffi::{CStr, CString, OsStr, OsString},
        fs,
        io::Read,
        iter,
        marker::PhantomData,
        mem,
        os::unix::ffi::{OsStrExt, OsStringExt},
        path::{Path, PathBuf},
        ptr, slice,
    },
};

#[no_mangle]
pub unsafe extern "C" fn execve(path: &NulStr, argv: &Nul<&NulStr>, envp: &Nul<&NulStr>) -> c_int {
    let mut path = PathBuf::from(&path.to_string());
    let mut argv: VecDeque<String> = argv.iter().map(|arg| arg.to_string()).collect();
    let mut envp: HashMap<_, _> = envp
        .iter()
        .flat_map(|env| {
            let env = env.to_string();
            let mut split = env.splitn(2, '=');
            Some((split.next()?.to_string(), split.next()?.to_string()))
        })
        .collect();

    let elf = fs::read(&path).unwrap();

    let elf = match Object::parse(&elf) {
        Ok(Object::Elf(elf)) => elf,
        _ => return ENOEXEC,
    };

    let arch = match elf.header.e_machine {
        0x03 => "i386",
        0x3e => "x86_64",
        0x28 => "arm",
        0xb7 => "aarch64",
        _ => return ENOEXEC,
    };

    if arch != std::env::consts::ARCH {
        argv.push_front(path.display().to_string());
        argv.push_front("-0".to_string());

        path = PathBuf::from(format!("/bin/qemu-{}", arch));

        envp.remove("LD_PRELOAD");
    }

    let path = CString::new(path.display().to_string()).unwrap();

    let argv: Vec<CString> = argv.into_iter().flat_map(|arg| CString::new(arg)).collect();

    let argv: Vec<*const c_char> = argv
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(iter::once(ptr::null()))
        .collect();

    let envp: Vec<CString> = envp
        .iter()
        .flat_map(|(key, value)| CString::new(format!("{}={}", key, value)))
        .collect();

    let envp: Vec<*const c_char> = envp
        .iter()
        .map(|env| env.as_ptr())
        .chain(iter::once(ptr::null()))
        .collect();

    let execve = dlsym(
        RTLD_NEXT,
        CString::new("execve")
            .expect("this should never fail")
            .as_ptr(),
    );

    let execve = match mem::transmute::<
        *const _,
        Option<
            unsafe extern "C" fn(
                *const c_char,
                *const *const c_char,
                *const *const c_char,
            ) -> c_int,
        >,
    >(execve)
    {
        Some(execve) => execve,
        None => return ENOEXEC,
    };

    execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
}

/*#[no_mangle]
pub unsafe extern "C" fn execve(path: &NulStr, argv: &Nul<&NulStr>, envp: &Nul<&NulStr>) -> c_int {
    let mut path = PathBuf::from(path.to_string());
    let mut argv: VecDeque<_> = slice::from_raw_parts(argv.as_ptr(), argv.len())
        .iter()
        .map(|s| s.to_string())
        .collect();
    let envp: HashMap<_, _> = std::slice::from_raw_parts(envp.as_ptr(), envp.len())
        .iter()
        .map(|s| {
            let s = s.to_string();
            let v: Vec<&str> = s.splitn(2, '=').collect();

            (v[0].to_string(), v[1].to_string())
        })
        .collect();

    let buf = {
        let mut file = match File::open(&path) {
            Ok(file) => file,
            _ => return EACCES,
        };

        let mut buf = Vec::new();

        match file.read_to_end(&mut buf) {
            Ok(_) => buf,
            _ => return EACCES,
        }
    };

    let elf = match Object::parse(&buf) {
        Ok(Object::Elf(elf)) => elf,
        _ => return ENOEXEC,
    };

    let arch = match elf.header.e_machine {
        0x03 => "i386",
        0x3e => "x86_64",
        0x28 => "arm",
        0xb7 => "aarch64",
        _ => return ENOEXEC,
    };

    if arch != std::env::consts::ARCH {
        argv.push_front(path.display().to_string());

        path = PathBuf::from(format!("qemu-{}", arch));
    }

    dbg!(&path, &argv);

    let execve = dlsym(
        RTLD_NEXT,
        CString::new("execve")
            .expect("this should never fail")
            .as_ptr(),
    );

    let execve = match mem::transmute::<
        *const _,
        Option<
            unsafe extern "C" fn(
                *const c_char,
                *const *const c_char,
                *const *const c_char,
            ) -> c_int,
        >,
    >(execve)
    {
        Some(execve) => execve,
        None => return ENOEXEC,
    };

    let path = CString::new(path.as_os_str().as_bytes()).unwrap().as_ptr();

    let argv = argv
        .into_iter()
        .flat_map(|arg| CString::new(arg))
        .map(|arg| arg.as_ptr() as *const c_char)
        .chain(vec![ptr::null()].into_iter())
        .collect::<Vec<_>>()
        .as_ptr();

    let envp = envp
        .into_iter()
        .map(|(key, val)| format!("{}={}", key, val))
        .flat_map(|arg| CString::new(arg))
        .map(|arg| arg.as_ptr() as *const c_char)
        .chain(vec![ptr::null()].into_iter())
        .collect::<Vec<_>>()
        .as_ptr();

    execve(path, argv, envp)
}*/

/*fn execve2(
    mut path: PathBuf,
    mut args: VecDeque<String>,
    mut env: HashMap<String, String>,
) -> failure::Fallible<c_int> {
    let mut file = File::open(&path)?;
    let mut buf = Vec::new();

    file.read_to_end(&mut buf)?;

    let elf = if let Object::Elf(elf) = Object::parse(&buf)? {
        elf
    } else {
        return Ok(ENOEXEC);
    };

    let arch = match elf.header.e_machine {
        0x03 => "i386",
        0x3e => "x86_64",
        0x28 => "arm",
        0xb7 => "aarch64",
        _ => return Ok(ENOEXEC),
    };

    if arch != env::consts::ARCH {
        let qemu = which::which(format!("qemu-{}", arch))?;

        env.insert("QEMU_ARGV0".to_string(), args.pop_front().unwrap());
        args.push_front(path.display().to_string());

        path = qemu;
    }

    dbg!(&path, &args, &env);

    Ok(execve3(path, args, env))
}

fn execve3(path: PathBuf, mut args: VecDeque<String>, env: HashMap<String, String>) -> c_int {
    let path = format!("{}\0", path.display());
    let path = path.as_ptr();

    for arg in &mut args {
        arg.push('\0');
    }

    let mut args: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
    args.push(ptr::null());
    let args = args.as_ptr();

    let env: Vec<_> = env.iter().map(|(k, v)| format!("{}={}\0", k, v)).collect();
    let mut env: Vec<_> = env.iter().map(|e| e.as_ptr()).collect();
    env.push(ptr::null());
    let env = env.as_ptr();

    unsafe {
        let sym = dlsym(-1i64 as *mut _, b"execve\0".as_ptr() as *const _);
        let fun = mem::transmute::<
            *const _,
            Option<
                extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int,
            >,
        >(sym);

        fun.unwrap()(path, args, env)
    }
}*/
