//! Shared FOSS authorization service building blocks. HTTP deployment and SaaS
//! account policy stay outside these provider and credential handoff primitives.
pub mod handoff;
pub(crate) mod notion;

pub(crate) mod remote;
pub mod service;
