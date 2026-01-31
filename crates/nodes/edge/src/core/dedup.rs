//! # Deduplication Engine
//!
//! Prevents processing duplicate messages within a TTL window.

use std::collections::HashSet;
use std::time::Instant;

/// Time-to-live for deduplication entries (seconds)
pub const DEDUP_TTL: u64 = 600;

/// Deduplication engine using sliding window
pub struct Deduplicator {
    seen: HashSet<u32>,
    timestamps: Vec<(Instant, u32)>,
}

impl Deduplicator {
    /// Create a new deduplicator
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            timestamps: Vec::new(),
        }
    }

    /// Check if ID is new and add it to the seen set
    /// 
    /// Returns `true` if the ID is new, `false` if it's a duplicate.
    pub fn check_and_add(&mut self, id: u32) -> bool {
        let now = Instant::now();
        
        // Cleanup expired entries
        self.timestamps.retain(|(t, k)| {
            if now.duration_since(*t).as_secs() > DEDUP_TTL {
                self.seen.remove(k);
                false
            } else {
                true
            }
        });

        // Check if already seen
        if self.seen.contains(&id) {
            crate::k::debug::log_detail!("Dedup: Dropping duplicate ID {}", id);
            return false;
        }

        // Add new entry
        self.seen.insert(id);
        self.timestamps.push((now, id));
        true
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new()
    }
}
