//! # Plugins Module
//!
//! Plugin loading and management.

pub mod manager;
#[cfg(target_os = "windows")]
pub mod native_library;

pub use manager::PluginManager;
