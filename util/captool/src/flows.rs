
use crate::limit::{Hashable, Limit, PacketType};

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;



struct KeyCount {
    flows: AtomicU64,
    packets: AtomicU64,
}

pub struct Limits {
    /// limit packets per key
    pub lpk: u64,
    /// limit flows per key
    pub lfk: u64,
    /// limit # of packets
    pub lp  : u64,
    /// limit # of flows
    pub lf : u64,
    /// limit packets per flow (requires one of the above limits)
    pub lppf: u64,
}


impl Limits {
    pub fn new() -> Self {
        Limits { lpk: 0, lfk: 0, lp: 0, lf: 0, lppf: 0 }
    }

    // pub fn limit(self) -> Option<Box<dyn Limit>> {

    //     let ls = LimiterState{
    //         packets_per_flow: HashMap::new(),
    //         counts_per_key: HashMap::new(),
    //         total_flow_count: AtomicU64::new(0),
    //         total_packet_count: AtomicU64::new(0),
    //         limits: self,
    //         m: Mutex::new(0_u32),
    //     };
    //     Some(ls)
    // }
}

pub struct LimiterState<T> {
    m: Mutex<T>,
    packets_per_flow: HashMap<String, AtomicU64>,
    counts_per_key: HashMap<Hashable, KeyCount>,
    total_flow_count: AtomicU64,
    total_packet_count: AtomicU64,
    limits: Limits,
}

/// LimiterState tracks the current state of packet counts under a variety of situations.
///
/// lpa  - limit packets per asn
/// lpc  - limit packets per cc
/// l    - limit # of packets
///
/// lfa  - limit flows per asn
/// lfc  - limit flows per cc
/// lf   - limit flows
///
/// ppf  - limit packets per flow (requires one of the above limits)
impl<T> LimiterState<T> {
    pub fn reset(&mut self) {

    }

    pub fn count_or_drop(
        &mut self,
        key: Hashable,
        afi: String,
        t: PacketType,
    ) -> Result<(), Box<dyn Error>> {
        self.count_or_drop_many(vec![key], afi, t).unwrap();
        Ok(())
    }

    pub fn count_or_drop_many(
        &mut self,
        keys: Vec<Hashable>,
        afi: String,
        t: PacketType,
    ) -> Result<Hashable, Box<dyn Error>> {
        Err("not implemented")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_limit() -> Result<(), Box<dyn Error>> {
        // let limiter = Limits::new().limit();
        let limiter = LimiterState{
            packets_per_flow: HashMap::new(),
            counts_per_key: HashMap::new(),
            total_flow_count: AtomicU64::new(0),
            total_packet_count: AtomicU64::new(0),
            limits: Limits { lpk: 0, lfk: 10, lp: 0, lf: 0, lppf: 10 },
            m: Mutex::new(0_u32),
        };
        Ok(())
    }
}