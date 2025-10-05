use std::{cell::RefCell, ffi::CString, rc::Rc};

use crate::*;

use crate::error::WsError;
use crate::rec_wrapper::ParsedRec;


pub struct Wtap {
  path: String,
  wth: *mut wtap,
}

impl Drop for Wtap {
  fn drop(&mut self) {
    unsafe {
      wtap_close(self.wth);
    }
  }
}

pub struct InnerWtapRec {
  pub (crate) rec: wtap_rec,
}

pub struct WtapRec {
  pub (crate) rec: Rc<RefCell<InnerWtapRec>>,
  pub (crate) offset: gint64,
}

impl Drop for InnerWtapRec {
  fn drop(&mut self) {
    unsafe {
      wtap_rec_cleanup((&mut self.rec) as *mut wtap_rec);
    }
  }
}

impl InnerWtapRec {
  pub(crate) fn new() -> InnerWtapRec {
    unsafe {
      let mut rec: wtap_rec = std::mem::zeroed();
      
      wtap_rec_init((&mut rec) as *mut wtap_rec, 2048);
      
      InnerWtapRec {
        rec,
      }
    }
  }
}

impl WtapRec {
  fn new() -> WtapRec {
    WtapRec {
      rec: Rc::new(RefCell::new(InnerWtapRec::new())),
      offset: 0,
    }
  }
}

impl Wtap {
  fn new(path: String) -> Result<Wtap, WsError> {
    let mut err = WsError::new();
    
    let cstr = CString::new(path.clone()).unwrap();
    
    unsafe {
      let wth = wtap_open_offline(
        cstr.as_ptr(),
        WTAP_TYPE_AUTO,
        (&mut err.err) as *mut ::std::os::raw::c_int,
        (&mut err.errInfo) as *mut *mut gchar,
        false,
      );
      
      if wth.is_null() {
        Err(err)
      } else{
        Ok(Wtap {
          wth,
          path,
        })
      }
    }
  }
  
  fn read(&mut self) -> Result<WtapRec, WsError> {
    let mut rec: WtapRec = WtapRec::new();
    
    let mut err = WsError::new();
    
    unsafe {
      let ret = wtap_read(
        self.wth,
        (&mut (rec.rec).borrow_mut().rec) as *mut wtap_rec,
        (&mut err.err) as *mut ::std::os::raw::c_int,
        (&mut err.errInfo) as *mut *mut gchar,
        (&mut rec.offset) as *mut gint64,
      );
      
      if ret {
        Err(err)
      } else {
        Ok(rec)
      }
    }
  }
  
  fn seek_read(&mut self, offset: i64) -> Result<WtapRec, WsError> {
    let mut rec: WtapRec = WtapRec::new();
    
    let mut err = WsError::new();
    
    unsafe {
      let ret = wtap_seek_read(
        self.wth,
        offset,
        (&mut rec.rec.borrow_mut().rec) as *mut wtap_rec,
        (&mut err.err) as *mut ::std::os::raw::c_int,
        (&mut err.errInfo) as *mut *mut gchar,
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

pub struct InnerEpanSession {
  pub (crate) epan: *mut epan_session,
}

pub struct Session {
  pub (crate) epan: Rc<RefCell<InnerEpanSession>>
}

impl Drop for InnerEpanSession {
  fn drop(&mut self) {
    unsafe {
      epan_free(self.epan);
    }
  }
}

impl Session {
  fn dissect(&mut self, rec: &mut WtapRec) -> ParsedRec {
    let mut prec = ParsedRec::new(self.epan.clone(), rec);
    
    unsafe {
      epan_dissect_run(
        (&mut prec.edt) as *mut epan_dissect_t,
        0,
        (&mut rec.rec.borrow_mut().rec) as *mut wtap_rec,
        (&mut prec.fdata) as *mut frame_data,
        std::ptr::null_mut(),
      );
    };
    
    prec
  }
}