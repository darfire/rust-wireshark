use std::pin::Pin;
use std::{cell::RefCell, rc::Rc};

use crate::wtap::*;

use crate::*;

#[derive(Debug)]
pub(crate) struct InnerParsedRec {
  pub(crate) fdata: raw::frame_data,
  pub(crate) edt: raw::epan_dissect_t,
}

impl InnerParsedRec {
  pub(crate) fn new() -> Self {
    unsafe {
      InnerParsedRec {
        fdata: std::mem::zeroed(),
        edt: std::mem::zeroed(),
      }
    }
  }
}

#[derive(Debug)]
pub struct ParsedRec {
  pub(crate) session: Rc<RefCell<InnerEpanSession>>,
  #[expect(unused)]
  pub(crate) rec: Rc<RefCell<InnerWtapRec>>,
  pub(crate) inner_pr: Rc<RefCell<Pin<Box<InnerParsedRec>>>>,
  pub(crate) root_node: Option<ProtoNode>,
}

impl Drop for InnerParsedRec {
  fn drop(&mut self) {
    unsafe {
      //raw::epan_dissect_free((&mut self.edt) as *mut raw::epan_dissect_t);
      raw::frame_data_destroy((&mut self.fdata) as *mut raw::frame_data);
    }
  }
}

impl ParsedRec {
  pub(crate) fn new(session: Rc<RefCell<InnerEpanSession>>, rec: &mut WtapRec) -> ParsedRec {
    unsafe {
      let prec = ParsedRec {
        session: session.clone(),
        rec: rec.rec.clone(),
        inner_pr: Rc::new(RefCell::new(Pin::new(Box::new(InnerParsedRec::new())))),
        root_node: None,
      };

      raw::frame_data_init(
        (&mut prec.inner_pr.borrow_mut().fdata) as *mut raw::frame_data,
        1,
        (&mut rec.rec.borrow_mut().rec) as *mut raw::wtap_rec,
        rec.offset,
        0,
      );

      raw::epan_dissect_init(
        (&mut prec.inner_pr.borrow_mut().edt) as *mut raw::epan_dissect_t,
        prec.session.borrow_mut().epan,
        true,
        true,
      );

      prec
    }
  }

  pub fn get_root_node(&self) -> Result<ProtoNode, Error> {
    match self.root_node {
      None => Err(Error::NotDissected),
      Some(ref node) => Ok(node.clone()),
    }
  }

  pub fn get_frames(&self) -> Result<Vec<ProtoNode>, Error> {
    let root = self.get_root_node()?;

    Ok(root.get_children())
  }
}

#[derive(Debug)]
pub struct InnerEpanSession {
  pub(crate) epan: *mut raw::epan_session,
}

pub struct Session {
  pub(crate) epan: Rc<RefCell<InnerEpanSession>>,
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
      let funcs = raw::packet_provider_funcs {
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
      epan: Rc::new(RefCell::new(InnerEpanSession { epan })),
    }
  }

  pub fn dissect(&mut self, rec: &mut WtapRec) -> ParsedRec {
    let mut prec = ParsedRec::new(self.epan.clone(), rec);
    let raw_rec = &mut rec.rec.borrow_mut().rec;

    prec.root_node = unsafe {
      let mut inner_pr = prec.inner_pr.borrow_mut();
      raw::epan_dissect_run(
        (&mut inner_pr.edt) as *mut raw::epan_dissect_t,
        rec.file_type,
        raw_rec as *mut raw::wtap_rec,
        (&mut inner_pr.fdata) as *mut raw::frame_data,
        std::ptr::null_mut(),
      );

      Some(ProtoNode::new(prec.inner_pr.clone(), inner_pr.edt.tree, 0))
    };

    prec
  }
}