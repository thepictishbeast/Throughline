//! A network-lab canvas for one real Linux host.
//!
//! The model is deliberately separate from the drawing: `scene` is what
//! is on the bench and has no renderer in it, so the rules about what can
//! be added, joined or deleted are tested without a GPU.

pub mod scene;
