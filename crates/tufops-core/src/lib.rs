//! Core of tufops: the repository configuration, metadata editing, signing status and
//! publishing, independent of any cloud provider.

pub mod backend;
pub mod config;
pub mod git;
pub mod publish;
pub mod repo;
pub mod status;

pub use config::Config;
pub use repo::Repo;
pub use status::EventStatus;
