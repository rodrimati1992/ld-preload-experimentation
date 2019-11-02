use goblin::Object;
use libc::{c_char, c_int, dlsym, ENOEXEC};
use null_terminated::{Nul, NulStr};
use std::{
    collections::{HashMap, VecDeque},
    env,
    fs::File,
    io::Read,
    mem,
    path::PathBuf,
    ptr,
};

#[no_mangle]
pub extern "C" fn execve(path: &NulStr, args: &Nul<&NulStr>, env: &Nul<&NulStr>) -> c_int {
    let path = path.to_string().into();
    let args = unsafe { std::slice::from_raw_parts(args.as_ptr(), args.len()) }
        .iter()
        .map(|s| s.to_string())
        .collect();
    let env = unsafe { std::slice::from_raw_parts(env.as_ptr(), env.len()) }
        .iter()
        .map(|s| {
            let s = s.to_string();
            let v: Vec<&str> = s.splitn(2, '=').collect();

            (v[0].to_string(), v[1].to_string())
        })
        .collect();

    match execve2(path, args, env) {
        Ok(ret) => ret,
        Err(_) => ENOEXEC,
    }
}

fn execve2(
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
}
