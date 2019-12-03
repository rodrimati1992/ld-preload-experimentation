use {
    goblin::elf::header::header64::Header,
    libc::{c_char, c_int, dlsym, ENOEXEC, RTLD_NEXT},
    null_terminated::{Nul, NulStr},
    std::{
        collections::VecDeque,
        ffi::CString,
        fs::File, iter, mem,
        path::PathBuf,
        ptr,
    },
};

#[no_mangle]
pub unsafe extern "C" fn execve(path: &NulStr, argv: &Nul<&NulStr>, envp: &Nul<&NulStr>) -> c_int {
    fn push_front(argv_prefix:&mut VecDeque<CString>,s:&str){
        if let Ok(cs)=CString::new(s) {
            argv_prefix.push_front(cs);
        }
    }

    let mut path = PathBuf::from(&path.to_string());
    let mut argv_prefix = VecDeque::<CString>::new();


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

    let mut filtered_out_keys=Vec::<&'static str>::new();
    if arch != std::env::consts::ARCH {
        push_front(&mut argv_prefix,&path.display().to_string());
        push_front(&mut argv_prefix,"-0");

        path = PathBuf::from(format!("/bin/qemu-{}", arch));

        filtered_out_keys.push("LD_PRELOAD");
    }

    let path = CString::new(path.display().to_string()).unwrap();

    let argv: Vec<*const c_char> = argv_prefix
        .iter()
        .map(|arg:&CString| arg.as_ptr())
        .chain( argv.iter().copied().map(|arg:&NulStr| arg.as_ptr() as *const c_char ) )
        .chain(iter::once(ptr::null()))
        .collect();

    let envp: Vec<CString> = envp
        .iter()
        .filter_map(|env| {
            let mut split = env[..].splitn(2, '=');
            Some((split.next()?, split.next()?))
        })
        .filter(|(k,_)| !filtered_out_keys.contains(k) )
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
