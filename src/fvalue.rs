use std::ffi::CStr;
use std::{cell::RefCell, pin::Pin, rc::Rc};

use crate::InnerParsedRec;
use crate::raw;

#[derive(Debug)]
pub struct FValue {
  #[expect(unused)]
  prec: Rc<RefCell<Pin<Box<InnerParsedRec>>>>,
  fvalue: *mut raw::fvalue_t,
}

impl FValue {
  pub(crate) fn new(
    prec: Rc<RefCell<Pin<Box<InnerParsedRec>>>>,
    fvalue: *mut raw::fvalue_t,
  ) -> Self {
    FValue { prec, fvalue }
  }

  pub fn to_string(&self) -> String {
    unsafe {
      let char_ptr = raw::fvalue_to_string_repr(
        std::ptr::null_mut(),
        self.fvalue,
        raw::ftrepr_FTREPR_DFILTER,
        0,
      );
      if char_ptr.is_null() {
        return "NULL".to_string();
      }
      CStr::from_ptr(char_ptr).to_str().unwrap().to_string()
    }
  }

  pub fn length(&self) -> Option<usize> {
    unsafe {
      if self.fvalue.is_null()
        || (*self.fvalue).ftype.is_null()
        || (*(*self.fvalue).ftype).len.is_none()
      {
        None
      } else {
        Some(raw::fvalue_length2(self.fvalue) as usize)
      }
    }
  }

  pub fn get_ftype(&self) -> FType {
    unsafe { FType::new((*self.fvalue).ftype) }
  }

  pub fn get_ftype_name(&self) -> String {
    unsafe {
      let char_ptr = raw::fvalue_type_name(self.fvalue);
      CStr::from_ptr(char_ptr).to_str().unwrap().to_string()
    }
  }
}

pub struct FType {
  ftype: *const raw::ftype_t,
}

impl FType {
  pub fn new(ftype: *const raw::ftype_t) -> FType {
    FType { ftype }
  }

  pub fn get_id(&self) -> raw::ftenum {
    unsafe { (*self.ftype).ftype }
  }

  pub fn get_wire_size(&self) -> i32 {
    unsafe { (*self.ftype).wire_size }
  }
}
