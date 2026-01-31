use std::sync::{Arc, Mutex, Condvar};
use std::time::{Duration, Instant};
use log::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemMode {
    /// Ghost Mode: Network silent, only Reddit/ETH polling active.
    /// P2P mesh is DISABLED by default.
    Ghost,
    /// Active Mode: P2P Swarm running, Local Discovery active.
    /// Only enabled when explicitly commanded via Reddit/ETH.
    Active,
}

#[derive(Clone)]
pub struct CommandState {
    inner: Arc<StateInner>,
}

struct StateInner {
    mode: Mutex<SystemMode>,
    p2p_enabled: Mutex<bool>,
    cvar: Condvar,
    last_activation: Mutex<Option<Instant>>,
}

impl CommandState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StateInner {
                mode: Mutex::new(SystemMode::Ghost),
                p2p_enabled: Mutex::new(false), // P2P disabled by default
                cvar: Condvar::new(),
                last_activation: Mutex::new(None),
            })
        }
    }

    /// Transition the system to a new mode.
    /// Returns true if the mode actually changed.
    pub fn set_mode(&self, new_mode: SystemMode) -> bool {
        let mut mode_lock = self.inner.mode.lock().unwrap();
        if *mode_lock != new_mode {
            info!("[CommandState] Transitioning: {:?} -> {:?}", *mode_lock, new_mode);
            *mode_lock = new_mode;
            
            if new_mode == SystemMode::Active {
                if let Ok(mut last) = self.inner.last_activation.lock() {
                    *last = Some(Instant::now());
                }
            }
            
            // Notify all waiters (e.g. Network Thread)
            self.inner.cvar.notify_all();
            true
        } else {
            false
        }
    }

    /// Get current mode
    pub fn current_mode(&self) -> SystemMode {
        *self.inner.mode.lock().unwrap()
    }

    /// Enable P2P subsystem (mesh networking)
    pub fn enable_p2p(&self) -> bool {
        let mut flag = self.inner.p2p_enabled.lock().unwrap();
        if !*flag {
            info!("[CommandState] P2P ENABLED via Reddit/ETH signal");
            *flag = true;
            self.inner.cvar.notify_all();
            true
        } else {
            false
        }
    }

    /// Check if P2P is enabled
    pub fn is_p2p_enabled(&self) -> bool {
        *self.inner.p2p_enabled.lock().unwrap()
    }

    /// Block current thread until the system enters Active mode.
    /// If already Active, returns immediately.
    pub fn await_activation(&self) {
        let mut mode_lock = self.inner.mode.lock().unwrap();
        while *mode_lock != SystemMode::Active {
            mode_lock = self.inner.cvar.wait(mode_lock).unwrap();
        }
    }

    /// Block current thread until P2P is enabled.
    pub fn await_p2p_enabled(&self) {
        loop {
            {
                let flag = self.inner.p2p_enabled.lock().unwrap();
                if *flag {
                    return;
                }
            }
            let mode_lock = self.inner.mode.lock().unwrap();
            drop(self.inner.cvar.wait(mode_lock).unwrap());
        }
    }

    /// Block current thread until system enters Active mode OR timeout occurs.
    /// Returns true if Active, false if Timed Out.
    pub fn await_activation_timeout(&self, timeout: Duration) -> bool {
        let mut mode_lock = self.inner.mode.lock().unwrap();
        let start = Instant::now();
        
        while *mode_lock != SystemMode::Active {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return false;
            }
            let remaining = timeout - elapsed;
            let (new_lock, result) = self.inner.cvar.wait_timeout(mode_lock, remaining).unwrap();
            mode_lock = new_lock;
            if result.timed_out() && *mode_lock != SystemMode::Active {
                return false;
            }
        }
        true
    }
}
