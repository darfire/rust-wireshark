use crate::*;
use core::fmt;
use std::fmt::Display;

#[derive(Debug)]
pub struct WsError {
  pub err: ::std::os::raw::c_int,
  pub errInfo: *mut raw::gchar,
}

impl WsError {
  pub fn new() -> WsError {
    WsError {
      err: 0,
      errInfo: std::ptr::null_mut(),
    }
  }
}

impl Display for WsError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Wtap error")
  }
}

#[derive(Debug)]
pub enum Error {
  EOF,
  WsError(WsError),
}