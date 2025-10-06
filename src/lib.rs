#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod raw {
  include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub mod error;
pub mod wtap;
pub mod epan;

pub use error::*;
pub use wtap::*;
pub use epan::*;


pub fn wtap_init() {
  unsafe {
    raw::wtap_init(false);
  }  
}

pub fn epan_init() -> bool {
  unsafe {
    raw::epan_init(
      None,
      std::ptr::null_mut(),
      false,
    )
  }
}