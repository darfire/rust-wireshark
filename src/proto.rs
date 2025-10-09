use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::{cell::RefCell, rc::Rc};

use crate::raw;
use crate::utils;
use crate::{FValue, Edt};

#[derive(Debug)]
pub struct ProtoNode {
  prec: Rc<RefCell<Pin<Box<Edt>>>>,

  pub(crate) raw_node: *mut raw::proto_node,

  depth: i16,
}

impl fmt::Display for ProtoNode {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "ProtoNode {{ a={}, d={} }}",
      self.get_abbrev(),
      self.depth
    )
  }
}

impl Clone for ProtoNode {
  fn clone(&self) -> Self {
    ProtoNode {
      prec: self.prec.clone(),
      raw_node: self.raw_node,
      depth: self.depth,
    }
  }
}

impl PartialEq for ProtoNode {
  fn eq(&self, other: &Self) -> bool {
    self.raw_node == other.raw_node
  }
}

impl ProtoNode {
  pub(crate) fn new(
    prec: Rc<RefCell<Pin<Box<Edt>>>>,
    raw_node: *mut raw::proto_node,
    depth: i16,
  ) -> Self {
    ProtoNode {
      prec,
      raw_node,
      depth,
    }
  }

  pub fn get_abbrev(&self) -> String {
    unsafe {
      let hfinfo = (*self.raw_node).hfinfo;

      utils::cstr_to_string((*hfinfo).abbrev)
    }
  }

  pub fn get_fvalue(&self) -> Option<FValue> {
    unsafe {
      let finfo = (*self.raw_node).finfo;

      if finfo.is_null() || (*finfo).value.is_null() {
        None
      } else {
        Some(FValue::new(self.prec.clone(), (*finfo).value))
      }
    }
  }

  pub fn get_parent(&self) -> Option<ProtoNode> {
    let parent = unsafe { (*self.raw_node).parent };

    if parent.is_null() {
      None
    } else {
      Some(ProtoNode {
        prec: self.prec.clone(),
        raw_node: parent,
        depth: self.depth - 1,
      })
    }
  }

  pub fn get_first_child(&self) -> Option<ProtoNode> {
    let first_child = unsafe { (*self.raw_node).first_child };

    if first_child.is_null() {
      None
    } else {
      Some(ProtoNode {
        prec: self.prec.clone(),
        raw_node: first_child,
        depth: self.depth + 1,
      })
    }
  }

  pub fn get_last_child(&self) -> Option<ProtoNode> {
    let last_child = unsafe { (*self.raw_node).last_child };

    if last_child.is_null() {
      None
    } else {
      Some(ProtoNode {
        prec: self.prec.clone(),
        raw_node: last_child,
        depth: self.depth + 1,
      })
    }
  }

  pub fn get_next(&self) -> Option<ProtoNode> {
    let next = unsafe { (*self.raw_node).next };

    if next.is_null() {
      None
    } else {
      Some(ProtoNode {
        prec: self.prec.clone(),
        raw_node: next,
        depth: self.depth,
      })
    }
  }

  pub fn get_children(&self) -> Vec<ProtoNode> {
    let mut children = Vec::new();
    let mut current = self.get_first_child();

    while let Some(node) = current {
      children.push(node.clone());

      current = node.get_next();
    }

    children
  }
  pub fn iter_depth_first(&self) -> ProtoNodeDepthFirstIter {
    ProtoNodeDepthFirstIter::new(self.clone())
  }

  pub fn iter_breadth_first(&self) -> ProtoNodeBreadthFirstIter {
    ProtoNodeBreadthFirstIter::new(self.clone())
  }

  pub fn iter_children(&self) -> ProtoNodeChildrenIter {
    ProtoNodeChildrenIter::new(self.get_first_child())
  }

  pub fn get_depth(&self) -> i16 {
    self.depth
  }

  pub fn is_leaf(&self) -> bool {
    self.get_first_child().is_none()
  }

  pub fn find_exhaustive(&self, abbrev: String) -> Option<ProtoNode> {
    self
      .iter_depth_first()
      .find(|node| node.get_abbrev() == abbrev)
  }

  pub fn find_hierarchical(&self, abbrev: String) -> Option<ProtoNode> {
    let dot_indices = abbrev.match_indices('.');

    let mut crt_node = self.clone();

    for (idx, _) in dot_indices {
      let child = crt_node
        .iter_children()
        .find(|node| node.get_abbrev() == abbrev[..idx]);

      match child {
        Some(child) => crt_node = child,
        None => return None,
      }
    }

    Some(crt_node)
  }
}

pub struct ProtoNodeDepthFirstIter {
  parent_node: ProtoNode,
  current_node: Option<ProtoNode>,
}

impl ProtoNodeDepthFirstIter {
  fn new(node: ProtoNode) -> Self {
    ProtoNodeDepthFirstIter {
      parent_node: node.clone(),
      current_node: Some(node),
    }
  }
}

impl Iterator for ProtoNodeDepthFirstIter {
  type Item = ProtoNode;

  fn next(&mut self) -> Option<Self::Item> {
    let next_node = self
      .current_node
      .clone()
      .map(|node| {
        // try down
        let first_child = node.get_first_child();

        if first_child.is_some() {
          self.current_node = first_child.clone();
          return first_child;
        }

        // try sideways
        let next_node = node.get_next();

        if next_node.is_some() {
          self.current_node = next_node.clone();
          return next_node;
        }

        let mut cnode = node;

        // try up and sideways
        loop {
          let parent_node = cnode.get_parent()?;

          if parent_node == self.parent_node {
            // we reached the top, we're done
            return None;
          } else {
            let next_node = parent_node.get_next();

            if next_node.is_some() {
              self.current_node = next_node.clone();
              return next_node;
            } else {
              cnode = parent_node;
            }
          }
        }
      })
      .flatten();

    self.current_node = next_node.clone();

    next_node
  }
}

pub struct ProtoNodeBreadthFirstIter {
  queue: VecDeque<ProtoNode>,
}

impl ProtoNodeBreadthFirstIter {
  fn new(root: ProtoNode) -> ProtoNodeBreadthFirstIter {
    let mut queue = VecDeque::new();
    queue.push_back(root);

    ProtoNodeBreadthFirstIter { queue }
  }
}

impl Iterator for ProtoNodeBreadthFirstIter {
  type Item = ProtoNode;

  fn next(&mut self) -> Option<Self::Item> {
    let node = self.queue.pop_front();

    match node {
      Some(node) => {
        let children = node.get_children();

        for child in children {
          self.queue.push_back(child);
        }

        Some(node)
      }
      None => None,
    }
  }
}

pub struct ProtoNodeChildrenIter {
  crt_node: Option<ProtoNode>,
}

impl Iterator for ProtoNodeChildrenIter {
  type Item = ProtoNode;

  fn next(&mut self) -> Option<Self::Item> {
    let current = self.crt_node.take();

    if let Some(node) = current {
      self.crt_node = node.get_next();
      Some(node)
    } else {
      None
    }
  }
}

impl ProtoNodeChildrenIter {
  fn new(first_child: Option<ProtoNode>) -> Self {
    ProtoNodeChildrenIter {
      crt_node: first_child,
    }
  }
}
