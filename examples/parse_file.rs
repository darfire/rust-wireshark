extern crate rust_wireshark;

use clap::Parser;
use std::ffi::{CStr, CString};
use rust_wireshark::*;
use std::mem;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
  #[arg(short, long)]
  file: String,
}

unsafe fn do_epan_init() -> *mut epan_t {
  let funcs = packet_provider_funcs{
    get_frame_ts: None,
    get_interface_name: None,
    get_interface_description: None,
    get_modified_block: None,
    get_process_id: None,
    get_process_name: None,
    get_process_uuid: None,
    get_start_ts: None,
  };

  return epan_new(std::ptr::null_mut(), (&funcs) as *const packet_provider_funcs);
}

unsafe fn iterate_proto_node<F>(node: *const proto_tree, cb: &F, depth: u16 )
where F: Fn(u16, *const proto_tree) {
  if (node).is_null() {
    return;
  }
  
  let (first_child, last_child) = unsafe {
    ((*node).first_child, (*node).last_child)
  };
  
  cb(depth, node);
  
  if first_child.is_null() {
    return;
  } else {
    let mut current = first_child;
    
    while current != last_child {
      iterate_proto_node(current, cb, depth + 1);
      current = (*current).next;
    }
    
    iterate_proto_node(current, cb, depth + 1);
  }
}

fn iterate_proto_tree<F>(tree: *const proto_tree, cb: F)
where F: Fn(u16, *const proto_tree) {
  unsafe {
    iterate_proto_node(tree, &cb, 0);
  }
}


fn main() {
  let args = Args::parse();

  let c_str = CString::new(args.file).unwrap();
  let mut err: ::std::os::raw::c_int = 0;
  let mut err_info: *mut gchar = std::ptr::null_mut();

  unsafe {
    wtap_init(false);
    
    if !epan_init(
      None,
      std::ptr::null_mut(),
      false,
    ) {
      println!("Failed to initialize EPAN");
      return;
    }

    let wt: *mut wtap = wtap_open_offline(
        c_str.as_ptr(),
        WTAP_TYPE_AUTO,
        (&mut err) as *mut ::std::os::raw::c_int,
        (&mut err_info) as *mut *mut gchar,
        false);
      
    let file_type = wtap_file_type_subtype(wt);
    
    let epan = do_epan_init();
    
    println!("Got err: {:?}, err_info: {:?}, wtap: {:?}", err, err_info, wt);
    
    if wt.is_null() {
      println!("Could not open file. Bailing out.");
      return;
    }
    
    let mut rec: wtap_rec = mem::zeroed();
    let mut offset: gint64 = 0;
    
    wtap_rec_init(&mut rec as *mut wtap_rec, 2000);
    
    loop {
      let mut fd: frame_data = mem::zeroed();
      let ret = wtap_read(
        wt,
        (&mut rec) as *mut wtap_rec,
        (&mut err) as *mut ::std::os::raw::c_int,
        (&mut err_info) as *mut *mut gchar,
        (&mut offset) as *mut gint64,
      );

      println!("Reply after wtap_read: {}, {:?}, {:?}, {:?}", ret, err, err_info, offset);
      
      if ! ret {
        break;
      }
      
      frame_data_init(
        (&mut fd) as *mut frame_data,
        1,
        (&mut rec) as *mut wtap_rec,
        offset,
        0);
      
      let mut edt: epan_dissect_t = std::mem::zeroed();
      
      epan_dissect_init(
        (&mut edt) as *mut epan_dissect_t,
        epan,
        true, 
        true,
      );
      
      // let mut cinfo: epan_column_info = std::mem::zeroed();
      
      println!("file_type={}", file_type);
      
      epan_dissect_run(
        (&mut edt) as *mut epan_dissect_t,
        file_type,
        (&mut rec) as *mut wtap_rec,
        (&mut fd) as *mut frame_data,
        std::ptr::null_mut(),
      );
      
      println!("fd: pkt_len={}, file_off={}", fd.pkt_len, fd.file_off);
      
      /*
      epan_dissect_fill_in_columns(
        (&mut edt) as *mut epan_dissect_t,
        true, true);
      */
      
      let stream = print_stream_text_stdio_new(stdout);
      
      iterate_proto_tree(edt.tree, |depth, node| {
        let finfo = unsafe { (*node).finfo};
        let hfinfo = if finfo.is_null() {
          std::ptr::null_mut()
        } else {
          unsafe {
            (*finfo).hfinfo
          }
        };
        let abbrev = if hfinfo.is_null() {
          ""
        } else {
          let char_ptr = unsafe { (*hfinfo).abbrev };
          let str = unsafe { CStr::from_ptr(char_ptr) };
          str.to_str().unwrap()
        };
        let tln = if finfo.is_null() {
          -1
        } else {
          (*finfo).total_layer_num
        };
        let pln = if finfo.is_null() {
          -1
        } else {
          (*finfo).proto_layer_num
        };
        
        let fvt = if finfo.is_null() {
          "NULL"
        } else {
          let char_ptr = fvalue_type_name((*finfo).value);
          let str = unsafe { CStr::from_ptr(char_ptr) };
          str.to_str().unwrap()
        };
        
        let fv = if finfo.is_null() || (*finfo).value.is_null() {
          "NULL"
        } else {
          let char_ptr = fvalue_to_string_repr(
            std::ptr::null_mut(),
            (*finfo).value,
            ftrepr_FTREPR_DFILTER,
            0,
          );
          if char_ptr.is_null() {
            "NULL"
          } else {
            unsafe { CStr::from_ptr(char_ptr) }.to_str().unwrap()
          }
        };

        println!("{}{:?}: {:?}, {:?}, abbrev={}, tln={}, pln={}, fvt={}, fv={}",
          ".".repeat(depth as usize),
          node, finfo, hfinfo, abbrev,
          tln, pln, fvt, fv,
        );
      });
      
      proto_tree_print(
        print_dissections_e_print_dissections_expanded,
        true,
        (&mut edt) as *mut epan_dissect_t,
        std::ptr::null_mut(),
        stream,
      );
      
      wtap_rec_reset((&mut rec) as *mut wtap_rec);
    }
  }
}