use {
    goblin::elf::header::header64::Header,
    libc::{c_char, c_int, dlsym, ENOEXEC, RTLD_NEXT},
    null_terminated::{Nul, NulStr},
    std::{
        collections::{HashMap, VecDeque},
        ffi::CString,
        fs::File, iter, mem,
        path::PathBuf,
        ptr,
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

    let mut elf = File::open(&path).unwrap();

    let header = match Header::from_fd(&mut elf) {
        Ok(header) => header,
        _=> return ENOEXEC,
    };

    let arch = match header.e_machine {
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
