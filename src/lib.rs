#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod error;
pub mod wtap_wrapper;
pub mod rec_wrapper;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
      let c_str = CString::new("1.pcap").unwrap();
      let mut err: ::std::os::raw::c_int = 0;
      let mut err_info: *mut gchar = std::ptr::null_mut();

      unsafe {
        let wt: *mut wtap = wtap_open_offline(
            c_str.as_ptr(),
            0,
            (&mut err) as *mut ::std::os::raw::c_int,
            (&mut err_info) as *mut *mut gchar,
            0);
        
        println!("Got err: {:?}, err_info: {:?}, wtap: {:?}", err, err_info, wt);
      }
  }
}