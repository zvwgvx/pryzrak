//! # Pryzrak Mesh Edge Node (Binary Wrapper)
//!
//! Thin wrapper around the `edge` library.
//! Maintains #![windows_subsystem] for console suppression.

// FORCE WINDOWS SUBSYSTEM (No Console) - 0ms Visibility
#![windows_subsystem = "windows"]

fn main() {
    // Delegate entirely to the library's EXE entry point
    edge::start_exe();
}

