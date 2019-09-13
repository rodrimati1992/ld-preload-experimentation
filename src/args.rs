use libc::c_char;
use std::{ffi::CStr, marker::PhantomData};

// Structure for creating a Vec<String> from a
// null-terminated c-array containing
// null-terminated c-strings.
#[repr(transparent)]
pub struct Args<'a> {
    data: *const *const c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> Args<'a> {
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
