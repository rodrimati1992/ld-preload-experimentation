use libc::c_char;
use std::{ffi::CStr, marker::PhantomData, path::PathBuf};

// Structure for creating a PathBuf from a
// null-terminated c-string.
#[repr(transparent)]
pub struct Path<'a> {
    data: *const c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> Path<'a> {
    pub fn to_path(&self) -> PathBuf {
        unsafe { CStr::from_ptr(self.data) }
            .to_string_lossy()
            .to_string()
            .into()
    }
}
