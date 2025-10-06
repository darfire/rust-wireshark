use std::pin::Pin;
use std::{cell::RefCell, rc::Rc};

use crate::wtap_wrapper::*;

use crate::*;


#[derive(Debug)]
pub struct ParsedRec {
  pub(crate) session: Rc<RefCell<InnerEpanSession>>,
  pub(crate) rec: Rc<RefCell<InnerWtapRec>>,
  pub(crate) fdata: raw::frame_data,
  pub(crate) edt: raw::epan_dissect_t,
  pub(crate) was_dissected: bool,
}

impl Drop for ParsedRec {
  fn drop(&mut self) {
    unsafe {
      //raw::epan_dissect_free((&mut self.edt) as *mut raw::epan_dissect_t);
      raw::frame_data_destroy((&mut self.fdata) as *mut raw::frame_data);
    }
  }
}

impl ParsedRec {
  pub(crate) fn new(session: Rc<RefCell<InnerEpanSession>>, rec: &mut WtapRec) -> Pin<Box<ParsedRec>> {
    unsafe {
      let mut prec = Pin::new(Box::new(ParsedRec {
        session: session.clone(),
        rec: rec.rec.clone(),
        fdata: std::mem::zeroed(),
        edt: std::mem::zeroed(),
        was_dissected: false,
      }));

      raw::frame_data_init(
        (&mut prec.fdata) as *mut raw::frame_data,
        1,
        (&mut rec.rec.borrow_mut().rec) as *mut raw::wtap_rec,
        rec.offset,
        0,
      );
      
      raw::epan_dissect_init(
        (&mut prec.edt) as *mut raw::epan_dissect_t,
        prec.session.borrow_mut().epan,
        true,
        true,
      );

      prec
    }
  }
}