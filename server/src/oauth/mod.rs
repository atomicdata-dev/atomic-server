//! Shared FOSS authorization service building blocks. HTTP deployment and SaaS
//! account policy stay outside these provider and credential handoff primitives.
pub(crate) mod exchange;
pub mod handoff;
pub(crate) mod provider;

pub(crate) mod remote;
pub mod service;
