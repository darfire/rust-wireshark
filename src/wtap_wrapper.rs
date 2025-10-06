use std::pin::Pin;
use std::{cell::RefCell, ffi::CString, rc::Rc};
use std::fmt;

use crate::*;

use crate::error::WsError;
use crate::rec_wrapper::ParsedRec;


pub struct Wtap {
  path: String,
  wth: *mut raw::wtap,
  file_type: i32,
}

impl Drop for Wtap {
  fn drop(&mut self) {
    unsafe {
      raw::wtap_close(self.wth);
    }
  }
}

pub struct InnerWtapRec {
  pub (crate) rec: raw::wtap_rec,
}

impl fmt::Debug for InnerWtapRec {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "InnerWtapRec{{ rec: {:p} }}", &self.rec)
  }
}

pub struct WtapRec {
  pub (crate) rec: Rc<RefCell<InnerWtapRec>>,
  pub (crate) offset: raw::gint64,
  pub (crate) file_type: i32,
}

impl Drop for InnerWtapRec {
  fn drop(&mut self) {
    unsafe {
      raw::wtap_rec_cleanup((&mut self.rec) as *mut raw::wtap_rec);
    }
  }
}

impl InnerWtapRec {
  pub(crate) fn new() -> InnerWtapRec {
    unsafe {
      let mut rec = InnerWtapRec {
        rec: std::mem::zeroed(),
      };
      
      raw::wtap_rec_init((&mut rec.rec) as *mut raw::wtap_rec, 2048);

      rec
    }
  }
}

impl WtapRec {
  fn new() -> WtapRec {
    WtapRec {
      rec: Rc::new(RefCell::new(InnerWtapRec::new())),
      offset: 0,
      file_type: 0,
    }
  }
  
  fn set_file_type(&mut self, ftype: i32) {
    self.file_type = ftype;
  }
}

impl Wtap {
  pub fn new(path: String) -> Result<Wtap, WsError> {
    let mut err = WsError::new();
    
    let cstr = CString::new(path.clone()).unwrap();
    
    unsafe {
      let wth = raw::wtap_open_offline(
        cstr.as_ptr(),
        raw::WTAP_TYPE_AUTO,
        (&mut err.err) as *mut ::std::os::raw::c_int,
        (&mut err.errInfo) as *mut *mut raw::gchar,
        false,
      );
      
      if wth.is_null() {
        Err(err)
      } else{
        let file_type = raw::wtap_file_type_subtype(wth);
        Ok(Wtap {
          wth,
          path,
          file_type,
        })
      }
    }
  }
  
  pub fn read(&mut self) -> Result<WtapRec, Error> {
    let mut rec: WtapRec = WtapRec::new();
    
    let mut err = WsError::new();
    
    rec.set_file_type(self.file_type);
    
    unsafe {
      let ret = raw::wtap_read(
        self.wth,
        (&mut (rec.rec).borrow_mut().rec) as *mut raw::wtap_rec,
        (&mut err.err) as *mut ::std::os::raw::c_int,
        (&mut err.errInfo) as *mut *mut raw::gchar,
        (&mut rec.offset) as *mut raw::gint64,
      );
      
      if err.err != 0 {
        return Err(Error::WsError(err));
      }
      
      if ret {
        Ok(rec)
      } else {
        Err(Error::EOF)
      }
    }
  }
  
  pub fn seek_read(&mut self, offset: i64) -> Result<WtapRec, WsError> {
    let mut rec: WtapRec = WtapRec::new();
    
    let mut err = WsError::new();
    
    rec.set_file_type(self.file_type);
    
    unsafe {
      let ret = raw::wtap_seek_read(
        self.wth,
        offset,
        (&mut rec.rec.borrow_mut().rec) as *mut raw::wtap_rec,
        (&mut err.err) as *mut ::std::os::raw::c_int,
        (&mut err.errInfo) as *mut *mut raw::gchar,
      );
      
      if ret {
        Err(err)
      } else {
        rec.offset = offset;
        Ok(rec)
      }
    }
  }
}

#[derive(Debug)]
pub struct InnerEpanSession {
  pub (crate) epan: *mut raw::epan_session,
}

pub struct Session {
  pub (crate) epan: Rc<RefCell<InnerEpanSession>>
}

impl Drop for InnerEpanSession {
  fn drop(&mut self) {
    unsafe {
      raw::epan_free(self.epan);
    }
  }
}

impl Session {
  pub fn new() -> Session {
    let epan = unsafe {
      let funcs = raw::packet_provider_funcs{
        get_frame_ts: None,
        get_interface_name: None,
        get_interface_description: None,
        get_modified_block: None,
        get_process_id: None,
        get_process_name: None,
        get_process_uuid: None,
        get_start_ts: None,
      };

      raw::epan_new(
        std::ptr::null_mut(),
        (&funcs) as *const raw::packet_provider_funcs,
      )
    };
    
    Session {
      epan: Rc::new(RefCell::new(InnerEpanSession {
        epan,
      })),
    }
  }
    
  pub fn dissect(&mut self, rec: &mut WtapRec) -> Pin<Box<ParsedRec>> {
    let mut prec = ParsedRec::new(self.epan.clone(), rec);
    let raw_rec = &mut rec.rec.borrow_mut().rec;
    
    unsafe {
      raw::epan_dissect_run(
        (&mut prec.edt) as *mut raw::epan_dissect_t,
        rec.file_type,
        raw_rec as *mut raw::wtap_rec,
        (&mut prec.fdata) as *mut raw::frame_data,
        std::ptr::null_mut(),
      );
    };
    
    prec.was_dissected = true;
    
    prec
  }
}

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