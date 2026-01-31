/// Centralized Debug Logger
///
/// This module provides macros for forensic-level logging during development.
/// ALL macros expand to EMPTY blocks when `debug_mode` is disabled, ensuring ZERO artifacts in production.

use std::sync::Mutex;
use std::fmt;

// Global log sink (optional). If None, prints to stdout.
static LOG_SINK: Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>> = Mutex::new(None);

pub fn set_log_sink(sink: Box<dyn Fn(&str) + Send + Sync>) {
    let mut guard = LOG_SINK.lock().unwrap();
    *guard = Some(sink);
}

pub fn submit_log(msg: String) {
    let guard = LOG_SINK.lock().unwrap();
    if let Some(sink) = &*guard {
        sink(&msg);
    } else {
        println!("{}", msg);
    }
}

#[macro_export]
macro_rules! log_stage {
    ($stage:expr, $msg:expr) => {
        {
            #[cfg(feature = "debug_mode")]
            {
                let s = format!("[DEBUG] [Stage {}] [{}:{}] {}", $stage, file!(), line!(), $msg);
                $crate::k::debug::submit_log(s);
            }
        }
    };
    ($stage:expr) => {
        {
            #[cfg(feature = "debug_mode")]
            {
                let s = format!("[DEBUG] [Stage {}] [{}:{}]", $stage, file!(), line!());
                $crate::k::debug::submit_log(s);
            }
        }
    };
}

#[macro_export]
macro_rules! log_op {
    ($module:expr, $msg:expr) => {
        {
            #[cfg(feature = "debug_mode")]
            {
                let s = format!("[DEBUG] [{}] > {}", $module, $msg);
                $crate::k::debug::submit_log(s);
            }
        }
    };
}

#[macro_export]
macro_rules! log_detail {
    ($msg:expr) => {
        {
            #[cfg(feature = "debug_mode")]
            {
                let s = format!("[DEBUG]    -> [{}:{}] {}", file!(), line!(), $msg);
                $crate::k::debug::submit_log(s);
            }
        }
    };
    ($fmt:expr, $($arg:tt)*) => {
        {
            #[cfg(feature = "debug_mode")]
            {
                let s = format!("[DEBUG]    -> [{}:{}] {}", file!(), line!(), format!($fmt, $($arg)*));
                $crate::k::debug::submit_log(s);
            }
        }
    };
}

#[macro_export]
macro_rules! log_err {
    ($msg:expr) => {
        {
            #[cfg(feature = "debug_mode")]
            {
                let s = format!("[DEBUG] [ERROR] !!! [{}:{}] {}", file!(), line!(), $msg);
                $crate::k::debug::submit_log(s);
            }
        }
    };
}

#[macro_export]
macro_rules! log_hex {
    ($label:expr, $data:expr) => {
        {
            #[cfg(feature = "debug_mode")]
            {
                let mut hex_str = String::new();
                for (i, b) in $data.iter().enumerate() {
                    if i >= 16 { hex_str.push_str("..."); break; }
                    hex_str.push_str(&format!("{:02x} ", b));
                }
                let s = format!("[DEBUG]    -> [HEX] {}: {}", $label, hex_str);
                $crate::k::debug::submit_log(s);
            }
        }
    };
}

pub use log_stage;
pub use log_op;
pub use log_detail;
pub use log_err;
pub use log_hex;
