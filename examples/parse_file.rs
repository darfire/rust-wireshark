extern crate rust_wireshark;

use clap::Parser;
use std::ffi::CString;
use rust_wireshark::*;
use std::mem;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
  #[arg(short, long)]
  file: String,
}

fn main() {
  let args = Args::parse();

  let c_str = CString::new(args.file).unwrap();
  let mut err: ::std::os::raw::c_int = 0;
  let mut err_info: *mut gchar = std::ptr::null_mut();

  unsafe {
    wtap_init(1);
    
    epan_init(
      None,
      std::ptr::null_mut(),
      1,
    );

    let wt: *mut wtap = wtap_open_offline(
        c_str.as_ptr(),
        WTAP_TYPE_AUTO,
        (&mut err) as *mut ::std::os::raw::c_int,
        (&mut err_info) as *mut *mut gchar,
        0);
    
    println!("Got err: {:?}, err_info: {:?}, wtap: {:?}", err, err_info, wt);
    
    if wt.is_null() {
      println!("Could not open file. Bailing out.");
      return;
    }
    
    let mut rec: wtap_rec = mem::zeroed();
    let mut buf: Buffer = mem::zeroed();
    let mut offset: gint64 = 0;
    
    wtap_rec_init(&mut rec as *mut wtap_rec);
    
    ws_buffer_init(&mut buf as *mut Buffer, 1024);
    
    loop {
      let ret = wtap_read(
        wt,
        (&mut rec) as *mut wtap_rec,
        (&mut buf) as *mut Buffer,
        (&mut err) as *mut ::std::os::raw::c_int,
        (&mut err_info) as *mut *mut gchar,
        (&mut offset) as *mut gint64,
      );

    }
    
    println!("Reply after wtap_read: {}, {:?}, {:?}", ret, err, err_info);
  }
}