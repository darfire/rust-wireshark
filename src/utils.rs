use std::ffi::CStr;

use crate::raw;


pub(crate) fn cstr_to_string(cstr: *const raw::gchar) -> String {
  unsafe { CStr::from_ptr(cstr).to_str().unwrap().to_string() }
}