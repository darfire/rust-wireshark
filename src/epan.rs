use std::pin::Pin;
use std::{cell::RefCell, rc::Rc};

use crate::wtap::*;

use crate::*;

#[derive(Debug)]
pub(crate) struct Edt {
  pub(crate) edt: raw::epan_dissect_t,
}

impl Edt {
  pub(crate) fn new() -> Self {
    unsafe {
      Edt {
        edt: std::mem::zeroed(),
      }
    }
  }
}

#[derive(Debug)]
pub struct ParsedRec {
  pub(crate) session: Rc<RefCell<InnerEpanSession>>,
  pub(crate) rec: Rc<RefCell<InnerWtapRec>>,
  pub(crate) inner_pr: Rc<RefCell<Pin<Box<Edt>>>>,
  pub(crate) root_node: Option<ProtoNode>,
  pub(crate) offset: raw::gint64,
  pub(crate) file_type: i32,
}

impl Drop for Edt {
  fn drop(&mut self) {
    unsafe {
      raw::epan_dissect_cleanup((&mut self.edt) as *mut raw::epan_dissect_t);
    }
  }
}

impl ParsedRec {
  fn new(session: Rc<RefCell<InnerEpanSession>>, rec: &mut WtapRec) -> ParsedRec {
    unsafe {
      let prec = ParsedRec {
        session: session.clone(),
        rec: rec.rec.clone(),
        inner_pr: Rc::new(RefCell::new(Pin::new(Box::new(Edt::new())))),
        root_node: None,
        offset: rec.offset,
        file_type: rec.file_type,
      };

      raw::epan_dissect_init(
        (&mut prec.inner_pr.borrow_mut().edt) as *mut raw::epan_dissect_t,
        prec.session.borrow_mut().epan,
        true,
        true,
      );

      prec
    }
  }

  pub fn prime_dfilter(&self, dfilter: &DFilter) -> () {
    unsafe {
      raw::epan_dissect_prime_with_dfilter(
        (&mut self.inner_pr.borrow_mut().edt) as *mut raw::epan_dissect_t,
        dfilter.dfp,
      )
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

  pub fn dissect(&mut self) -> () {
    let raw_rec = &mut self.rec.borrow_mut().rec;

    self.root_node = unsafe {
      let mut inner_pr = self.inner_pr.borrow_mut();
      let mut fdata: raw::frame_data = std::mem::zeroed();

      raw::frame_data_init(
        (&mut fdata) as *mut raw::frame_data,
        1,
        raw_rec as *mut raw::wtap_rec,
        self.offset,
        0,
      );

      raw::epan_dissect_run(
        (&mut inner_pr.edt) as *mut raw::epan_dissect_t,
        self.file_type,
        raw_rec as *mut raw::wtap_rec,
        (&mut fdata) as *mut raw::frame_data,
        std::ptr::null_mut(),
      );

      raw::frame_data_destroy((&mut fdata) as *mut raw::frame_data);

      Some(ProtoNode::new(self.inner_pr.clone(), inner_pr.edt.tree, 0))
    };
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

  pub fn new_prec(&self, rec: &mut WtapRec) -> ParsedRec {
    ParsedRec::new(self.epan.clone(), rec)
  }
}
