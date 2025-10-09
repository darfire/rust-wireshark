use crate::Error;
use crate::ParsedRec;
use crate::ProtoNode;
use crate::raw;
use crate::raw::DF_OPTIMIZE;
use crate::utils;

use std::fmt;

#[derive(Debug)]
pub struct DFilter {
  pub(crate) dfp: *mut raw::dfilter_t,
  filter_str: String,
}

impl Drop for DFilter {
  fn drop(&mut self) {
    unsafe {
      raw::dfilter_free(self.dfp);
    }
  }
}

impl fmt::Display for DFilter {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "DFilter {{ filter: '{}' }}", self.filter_str)
  }
}

impl DFilter {
  pub fn new(filter_str: String) -> Result<DFilter, Error> {
    unsafe {
      let mut dfp: *mut raw::dfilter_t = std::ptr::null_mut();

      let mut derr: *mut raw::df_error_t = std::ptr::null_mut();

      let filter_str = filter_str.clone();

      let fstr = filter_str.as_ptr();

      let caller = "rust-wireshark".as_ptr();

      let expanded = raw::dfilter_expand(
        fstr as *const ::std::os::raw::c_char,
        (&mut derr) as *mut *mut raw::df_error_t,
      );

      if expanded.is_null() {
        let err_str = utils::cstr_to_string((*derr).msg);

        raw::df_error_free((&mut derr) as *mut *mut raw::df_error_t);

        return Err(Error::InvalidFilter(err_str));
      };

      let ret = raw::dfilter_compile_full(
        expanded,
        (&mut dfp) as *mut *mut raw::dfilter_t,
        (&mut derr) as *mut *mut raw::df_error_t,
        DF_OPTIMIZE,
        caller as *const ::std::os::raw::c_char,
      );

      if ret {
        Ok(DFilter { dfp, filter_str })
      } else {
        let err_str = utils::cstr_to_string((*derr).msg);

        raw::df_error_free((&mut derr) as *mut *mut raw::df_error_t);

        Err(Error::InvalidFilter(err_str))
      }
    }
  }

  pub fn apply_rec(&self, rec: &ParsedRec) -> bool {
    unsafe {
      raw::dfilter_apply_edt(
        self.dfp,
        (&mut rec.inner_pr.borrow_mut().edt) as *mut raw::epan_dissect_t,
      )
    }
  }
}
