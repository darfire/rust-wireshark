use std::{cell::RefCell, rc::Rc};

use crate::wtap_wrapper::*;

use crate::*;


pub struct ParsedRec {
  pub(crate) session: Rc<RefCell<InnerEpanSession>>,
  pub(crate) rec: Rc<RefCell<InnerWtapRec>>,
  pub(crate) fdata: frame_data,
  pub(crate) edt: epan_dissect_t,
  pub(crate) was_dissected: bool,
}

impl Drop for ParsedRec {
  fn drop(&mut self) {
    unsafe {
      epan_dissect_free((&mut self.edt) as *mut epan_dissect_t);
      frame_data_destroy((&mut self.fdata) as *mut frame_data);
    }
  }
}

impl ParsedRec {
  pub(crate) fn new(session: Rc<RefCell<InnerEpanSession>>, rec: &mut WtapRec) -> ParsedRec {
     let fdata = unsafe {
      let mut fdata: frame_data = std::mem::zeroed();

      frame_data_init(
        (&mut fdata) as *mut frame_data,
        1,
        (&mut rec.rec.borrow_mut().rec) as *mut wtap_rec,
        rec.offset,
        0,
      );

      fdata
    };
    
    let edt: epan_dissect_t = unsafe {
      let mut edt: epan_dissect_t = std::mem::zeroed();
      
      epan_dissect_init(
        (&mut edt) as *mut epan_dissect_t,
        session.borrow_mut().epan,
        true,
        true,
      );
      
      edt
    };   
    
    ParsedRec {
      session,
      rec: rec.rec.clone(),
      fdata,
      edt,
      was_dissected: false,
    }
  }
}