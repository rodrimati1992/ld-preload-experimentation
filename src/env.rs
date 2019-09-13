use itertools::Itertools;
use libc::c_char;
use std::{collections::HashMap, ffi::CStr, marker::PhantomData};

// Structure for creating a HashMap<String, String>
// from a null-terminated c-array containing
// null-terminated c-strings in a key=value format.
#[repr(transparent)]
pub struct Env<'a> {
    data: *const *const c_char,
    _ghost: PhantomData<&'a ()>,
}

impl<'a> Env<'a> {
    pub fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        for i in 0.. {
            match unsafe { (*self.data.offset(i)).as_ref() } {
                Some(val) => {
                    let (key, val) = unsafe { CStr::from_ptr(val) }
                        .to_string_lossy()
                        .to_string()
                        .splitn(2, '=')
                        .map(|part| part.to_owned())
                        .next_tuple()
                        .unwrap();

                    map.insert(key, val);
                }
                None => break,
            }
        }

        map
    }
}
