use crate::ip::PacketType;
use crate::limit::{Hashable, Limit, LimitError};

use std::cmp::min;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct KeyCount {
    packets: AtomicU64,
    flows: AtomicU64,
}

impl KeyCount {
    fn new() -> Self {
        KeyCount {
            packets: AtomicU64::new(0),
            flows: AtomicU64::new(0),
        }
    }

    fn load(&self) -> (u64, u64) {
        (
            self.packets.load(Ordering::Relaxed),
            self.flows.load(Ordering::Relaxed),
        )
    }

    fn load_inc(&self, new_flow: bool) -> (u64, u64) {
        if new_flow {
            (
                self.packets.load(Ordering::Relaxed) + 1,
                self.flows.load(Ordering::Relaxed) + 1,
            )
        } else {
            (
                self.packets.load(Ordering::Relaxed) + 1,
                self.flows.load(Ordering::Relaxed),
            )
        }
    }

    fn store(&mut self, p: u64, f: u64, ordering: Ordering) {
        self.packets.store(p, ordering);
        self.flows.store(f, ordering);
    }
}

#[derive(Debug, Clone)]
pub struct Limits {
    /// limit packets per key
    pub lpk: u64,
    /// limit flows per key
    pub lfk: u64,
    /// limit # of packets
    pub lp: u64,
    /// limit # of flows
    pub lf: u64,
    /// limit packets per flow (requires one of the above limits)
    pub lppf: u64,
}

impl Limits {
    pub fn into_limiter<H: Into<Hashable>>(
        mut self,
        keys: Vec<H>,
        flag: Arc<AtomicBool>,
    ) -> LimiterState {
        let n_keys = keys.len() as u64;
        let counts_per_key = keys
            .into_iter()
            .map(|h| (h.into(), KeyCount::new()))
            .collect();

        if self.lfk != 0 {
            if self.lf == 0 {
                self.lf = self.lfk * n_keys;
            } else {
                self.lf = min(self.lfk * n_keys, self.lf);
            }
        }

        if self.lppf != 0 && self.lf != 0 {
            self.lp = self.lppf * self.lf;
        }

        if self.lpk != 0 {
            if self.lp == 0 {
                self.lp = self.lpk * n_keys;
            } else {
                self.lp = min(self.lpk * n_keys, self.lp);
            }
        }

        LimiterState {
            packets_per_flow: HashMap::new(),
            counts_per_key,
            total_flow_count: AtomicU64::new(0),
            total_packet_count: AtomicU64::new(0),
            limits: self,
            flag,
            m: Mutex::new(0_u32),
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.lpk == 0 && self.lp == 0 && self.lppf == 0 && self.lf == 0 && self.lfk == 0
    }

    pub fn no_packet_limit(&self) -> bool {
        if self.lpk == 0 && self.lp == 0 {
            self.lppf == 0 || (self.lf == 0 && self.lfk == 0)
        } else {
            false
        }
    }
}

pub struct LimiterState {
    m: Mutex<u32>,
    packets_per_flow: HashMap<String, AtomicU64>,
    counts_per_key: HashMap<Hashable, KeyCount>,
    total_flow_count: AtomicU64,
    total_packet_count: AtomicU64,
    limits: Limits,
    flag: Arc<AtomicBool>,
}

impl LimiterState {
    fn count_or_drop_many_no_packet_limit(
        &mut self,
        keys: Vec<Hashable>,
        afi: String,
        known_flow: bool,
        flow_packet_count: u64,
        total_flows: u64,
    ) -> Result<Hashable, LimitError> {
        if known_flow {
            // known flow (so doesn't change total or key flow counts) and ppf already checked.
            self.packets_per_flow
                .get(&afi)
                .unwrap()
                .store(flow_packet_count, Ordering::Relaxed);
            return Ok(Hashable::Z);
        }
        if self.limits.lf != 0 && self.limits.lppf == 0 && total_flows >= self.limits.lf {
            // We have no packet limit, check if adding a new flow pushes us over the flow count
            Err(LimitError::Full(Hashable::Z))?;
        }
        let mut result = Hashable::Z;
        if self.limits.lfk != 0 && self.limits.lppf == 0 {
            // check to see if we have reached any flow limits by key
            let mut known_keys = HashMap::new();
            for key in keys {
                if self.counts_per_key.contains_key(&key) {
                    let (packets_for_key, flows_for_key) =
                        self.counts_per_key.get(&key).unwrap().load();
                    // println!("{key} -> {flows_for_key}");
                    if flows_for_key >= self.limits.lfk {
                        return Err(LimitError::Full(key));
                    }
                    known_keys.insert(key, (packets_for_key, flows_for_key));
                }
            }
            // If we expect to limit by flows per key and we did not recognize any key associated
            // with this packet then we are not interested in this packet and we should return
            // without committing increments to counts.
            if (self.limits.lpk != 0 || self.limits.lfk != 0) && known_keys.is_empty() {
                Err(LimitError::NoRelevantKeys)?;
            }

            for (key, (p, f)) in known_keys {
                result = key.clone();
                self.counts_per_key
                    .get_mut(&key)
                    .unwrap()
                    .store(p, f + 1, Ordering::Relaxed);
            }
        }

        self.packets_per_flow.insert(afi, AtomicU64::new(1));
        self.total_flow_count
            .store(total_flows + 1, Ordering::Relaxed);
        Ok(result)
    }

    fn count_or_drop_many_packet_limit(
        &mut self,
        keys: Vec<Hashable>,
        afi: String,
        known_flow: bool,
        flow_packet_count: u64,
        total_flows: u64,
        total_packets: u64,
    ) -> Result<Hashable, LimitError> {
        let mut result = Hashable::Z;
        let mut known_keys = HashMap::new();

        // If we have keys and a key based limit to apply
        if !self.counts_per_key.is_empty() && (self.limits.lpk != 0 || self.limits.lfk != 0) {
            for key in keys {
                //Find any of the keys that we know about.
                if self.counts_per_key.contains_key(&key) {
                    // for all known keys fetch and increment the counters. Note that the flow counter
                    // is only incremented if we have made it to this point and this is an unknown flow
                    // indicating that this is a SYN or a UDP flow we have not seen before.
                    known_keys.insert(
                        key.clone(),
                        self.counts_per_key.get(&key).unwrap().load_inc(!known_flow),
                    );
                }
            }
            // If we expect to limit by either packets or flows per key and we did not recognize any key
            // associated with this packet then we are not interested in this packet and we should return
            // without committing increments to counts.
            if (self.limits.lpk != 0 || self.limits.lfk != 0) && known_keys.is_empty() {
                Err(LimitError::NoRelevantKeys)?;
            }

            // Check out limits for each key.
            for (key, (packets_by_key, flows_by_key)) in known_keys.iter() {
                // if this packet would put us above the limit for packets with this key...
                if self.limits.lpk != 0 && packets_by_key > &self.limits.lpk {
                    // If we are at the limit for packet count as well set the flag and return Ok.
                    if total_packets >= self.limits.lp {
                        self.flag.store(true, Ordering::Relaxed);
                    }
                    // return an error to skip
                    Err(LimitError::Full(key.clone()))?;
                }
                if self.limits.lfk != 0 && flows_by_key > &self.limits.lfk {
                    if total_packets > self.limits.lp {
                        self.flag.store(true, Ordering::Relaxed);
                    }
                    Err(LimitError::Full(key.clone()))?;
                }
                result = key.clone();
            }
        }

        // if we are beyond the packet limit set the flag and return error
        if total_packets > self.limits.lp {
            self.flag.store(true, Ordering::Relaxed);
            Err(LimitError::Full(Hashable::Z))?;
        }
        // If we are at the limit set the flag and return Ok so we count the packet.
        if total_packets == self.limits.lp {
            self.flag.store(true, Ordering::Relaxed);
        }

        // If a flow limit is set...
        if self.limits.lf != 0 {
            // if we are beyond the limit and return error we do NOT set the flag -- we only stop on
            // packet limits and a packet limit will be set if the the capture is limited. e.g
            // We have reached the flow count limit, but we are under the ppf limit for some of those
            // flows.
            if total_flows > self.limits.lf {
                return Err(LimitError::Full(result));
            }
        }

        // commit all changes to the limiter state
        self.total_packet_count
            .store(total_packets, Ordering::Relaxed);
        self.total_flow_count.store(total_flows, Ordering::Relaxed);

        // update the KEY Map with the values for each existing key
        for (k, (p, f)) in known_keys {
            self.counts_per_key
                .get_mut(&k)
                .unwrap()
                .store(p, f, Ordering::Relaxed);
        }

        // Update the Packets_Per_flow table
        if known_flow {
            self.packets_per_flow
                .get(&afi)
                .unwrap()
                .store(flow_packet_count, Ordering::Relaxed);
        } else {
            self.packets_per_flow.insert(afi, AtomicU64::new(1));
            self.total_flow_count
                .store(total_flows + 1, Ordering::Relaxed);
        }

        Ok(result)
    }
}

impl Limit for &mut LimiterState {
    fn reset(&mut self) {
        self.counts_per_key = self
            .counts_per_key
            .keys()
            .map(|h| (h.clone(), KeyCount::new()))
            .collect();

        self.packets_per_flow = HashMap::new();
        self.total_flow_count = AtomicU64::new(0);
        self.total_packet_count = AtomicU64::new(0);
    }

    fn check_flag(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    fn count_or_drop(
        &mut self,
        key: Hashable,
        afi: String,
        t: PacketType,
    ) -> Result<(), LimitError> {
        self.count_or_drop_many(vec![key], afi, t)?;
        Ok(())
    }

    fn count_or_drop_many(
        &mut self,
        keys: Vec<Hashable>,
        afi: String,
        t: PacketType,
    ) -> Result<Hashable, LimitError> {
        if self.flag.load(Ordering::Relaxed) {
            Err(LimitError::Flag)?;
        }

        _ = self.m.lock();

        let total_packets = self.total_packet_count.load(Ordering::Relaxed) + 1;
        let total_flows = self.total_flow_count.load(Ordering::Relaxed);

        let known_flow = self.packets_per_flow.contains_key(&afi);
        let mut flow_packet_count = 0_u64;
        if known_flow {
            flow_packet_count = self
                .packets_per_flow
                .get(&afi)
                .unwrap()
                .load(Ordering::Relaxed)
                + 1;
        } else if t == PacketType::TCPOther {
            Err(LimitError::UnknownFlow)?;
        }

        // If we expect to limit by packets per flow and the packet count for this flow is at
        // or beyond the limit return without committing the incremented counts.
        if self.limits.lppf != 0 && flow_packet_count > self.limits.lppf {
            Err(LimitError::FullPPF)?;
        }

        match self.limits.no_packet_limit() {
            true => self.count_or_drop_many_no_packet_limit(
                keys,
                afi,
                known_flow,
                flow_packet_count,
                total_flows,
            ),
            false => self.count_or_drop_many_packet_limit(
                keys,
                afi,
                known_flow,
                flow_packet_count,
                total_flows,
                total_packets,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit::Limit;
    use std::error::Error;

    // packet sequence for testing
    struct MockPacket {
        keys: Vec<Hashable>,
        afi: String,
        t: PacketType,
        erfs: bool, // expected resultant flag state
        expected: Result<Hashable, LimitError>,
    }
    type MP = MockPacket;

    fn test<T: Limit>(packet: MockPacket, limiter: &mut T) -> Result<Hashable, Box<dyn Error>> {
        let result = limiter.count_or_drop_many(packet.keys, packet.afi, packet.t);
        match (result, packet.expected) {
            (Ok(h), Ok(eh)) => {
                if h != eh {
                    Err(format!("expected: {eh}\nreceived: {h}\n").into())
                } else if limiter.check_flag() == packet.erfs {
                    Ok(Hashable::Z)
                } else {
                    Err(format!("incorrect flag state: {}", packet.erfs).into())
                }
            }
            (Err(e), Err(ee)) => {
                let def = Err(format!("expected: {ee}\nreceived: {e}").into());
                if e == ee {
                    if limiter.check_flag() == packet.erfs {
                        Ok(Hashable::Z)
                    } else {
                        Err(format!("incorrect flag state: {}", packet.erfs).into())
                    }
                } else {
                    def
                }
            }
            (a, b) => Err(format!("expected: {b:#?}\nreceived: {a:#?}\n").into()),
        }
    }

    fn run_test<L: Limit>(mut limiter: L, packets: Vec<MockPacket>) -> Result<(), Box<dyn Error>> {
        for packet in packets {
            print!(".");
            if !matches!(test(packet, &mut limiter)?, Hashable::Z) {
                return Err("Ok, but no match".into());
            }
        }
        Ok(())
    }

    #[test]
    fn limiter() -> Result<(), Box<dyn Error>> {
        // let limiter = Limits::new().limit();
        let limits = Limits {
            lpk: 0,
            lfk: 0,
            lp: 0,
            lf: 3,
            lppf: 0,
        };
        let keys: Vec<Hashable> = vec![];

        let packet = MP {
            afi: String::from("2"),
            keys: vec![],
            t: PacketType::TCPOther,
            erfs: false,
            expected: Err(LimitError::UnknownFlow),
        };
        let flag = Arc::new(AtomicBool::new(false));
        let mut limiter = &mut limits.into_limiter(keys, flag);

        let result =
            (&mut limiter as &mut dyn Limit).count_or_drop_many(packet.keys, packet.afi, packet.t);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), LimitError::UnknownFlow);
        // assert!(matches!(result.unwrap_err(), LimitError::UnknownFlow));
        Ok(())
    }

    /// Limit the flow count to 3 but no other limits, this means that we should
    /// count every NEW flow (starting with TCPSYN or UDP) up to three, and
    /// allow unlimited packets for those flows. Once we have 3 though we should
    /// stop adding new flows WITHOUT triggering the shutdown flag.
    #[test]
    fn flow_limit_only() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 0,
            lfk: 0,
            lp: 0,
            lf: 3,
            lppf: 0,
        };
        let keys: Vec<Hashable> = vec![];

        let packets = vec![
            MP {
                // Rejected because part of a known flow and not the start of a flow
                afi: String::from("2"),
                keys: vec![],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec![],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // accepted as part of known flow 1
                afi: String::from("1"),
                keys: vec![],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // new flow 2
                afi: String::from("2"),
                keys: vec![],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                afi: String::from("3"),
                keys: vec![],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                afi: String::from("1"),
                keys: vec![],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                afi: String::from("4"),
                keys: vec![],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::Full(Hashable::Z)),
            },
            MP {
                afi: String::from("1"),
                keys: vec![],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
        ];

        assert!(limits.no_packet_limit());
        let flag = Arc::new(AtomicBool::new(false));
        let mut limiter = limits.into_limiter(keys, flag);

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }

    // ensure that if ppf is the only limit we still capture until killed, but obey ppf limits.
    #[test]
    fn ppf_limit_only() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 0,
            lfk: 0,
            lp: 0,
            lf: 0,
            lppf: 2,
        };
        assert!(limits.no_packet_limit());
        let mut limiter = limits.into_limiter::<()>(vec![], Arc::new(AtomicBool::new(false)));

        let packets = vec![
            MP {
                // Rejected because part of a known flow and not the start of a flow
                afi: String::from("2"),
                keys: vec![],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec![],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // accepted as part of known flow 1
                afi: String::from("1"),
                keys: vec![],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // new flow 2
                afi: String::from("2"),
                keys: vec![],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // new flow 3
                afi: String::from("3"),
                keys: vec![],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // Reject because of PPF limit for flow 1
                afi: String::from("1"),
                keys: vec![],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::FullPPF),
            },
        ];

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }

    #[test]
    fn flows_per_key_only() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 0,
            lfk: 2,
            lp: 0,
            lf: 0,
            lppf: 0,
        };
        assert!(limits.no_packet_limit());
        let mut limiter =
            limits.into_limiter::<&str>(vec!["ir", "cn"], Arc::new(AtomicBool::new(false)));
        let packets = vec![
            MP {
                // Rejected because part of a known flow and not the start of a flow
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // accepted as part of known flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // new flow 2
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // new flow 3
                afi: String::from("3"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::Full("ir".into())),
            },
            MP {
                // Allowed because part of existing flow for existing key
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
        ];

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }

    #[test]
    fn packet_limit() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 0,
            lfk: 0,
            lp: 2,
            lf: 0,
            lppf: 0,
        };
        assert!(!limits.no_packet_limit());
        let mut limiter =
            limits.into_limiter::<&str>(vec!["ir", "cn"], Arc::new(AtomicBool::new(false)));
        let packets = vec![
            MP {
                // rejected, not part of a flow despite no flow limit
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // accepted as part of known flow 1  -- triggers flag
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: true,
                expected: Ok(Hashable::Z),
            },
            MP {
                // rejected due to flag (triggered last packet when we hit the packet count)
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: true,
                expected: Err(LimitError::Flag),
            },
            MP {
                // rejected due to flag
                afi: String::from("3"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: true,
                expected: Err(LimitError::Flag),
            },
        ];

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }

    // Test limit packet count where lp < lpk *n_keys to make sure we get lp packets when the
    // flag is triggered for termination.
    #[test]
    fn packet_limit_below_lpk() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 2,
            lfk: 0,
            lp: 2,
            lf: 0,
            lppf: 0,
        };
        assert!(!limits.no_packet_limit());
        let mut limiter =
            limits.into_limiter::<&str>(vec!["ir", "cn"], Arc::new(AtomicBool::new(false)));
        let packets = vec![
            MP {
                // rejected, not part of a flow despite no flow limit
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // accepted as part of known flow 1  -- triggers flag
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: true,
                expected: Ok("ir".into()),
            },
            MP {
                // rejected due to flag (triggered last packet when we hit the packet count)
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: true,
                expected: Err(LimitError::Flag),
            },
            MP {
                // rejected due to flag
                afi: String::from("3"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: true,
                expected: Err(LimitError::Flag),
            },
        ];

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }

    // Test limit flow count where lp > lpk * n_keys to make sure we get lpk* n_keys packets when the
    // flag is triggered for termination.
    #[test]
    fn lpk_x_k_below_lp() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 2,
            lfk: 0,
            lp: 5,
            lf: 0,
            lppf: 0,
        };
        assert!(!limits.no_packet_limit());
        let mut limiter =
            limits.into_limiter::<&str>(vec!["ir", "cn"], Arc::new(AtomicBool::new(false)));
        let packets = vec![
            MP {
                // rejected, not part of a flow despite no flow limit
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // rejected, not using a known key despite being valid new flow
                afi: String::from("5"),
                keys: vec!["ru".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::NoRelevantKeys),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // accepted as part of known flow 1  -- triggers flag
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // rejected due to flag (triggered last packet when we hit the packet count)
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::Full("ir".into())),
            },
            MP {
                // new flow 3
                afi: String::from("3"),
                keys: vec!["cn".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("cn".into()),
            },
            MP {
                // accepted as part of known flow 1  -- triggers flag
                afi: String::from("3"),
                keys: vec!["cn".into()],
                t: PacketType::TCPOther,
                erfs: true,
                expected: Ok("cn".into()),
            },
        ];

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }

    #[test]
    fn flow_limit_below_lfk() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 0,
            lfk: 2,
            lp: 0,
            lf: 2,
            lppf: 0,
        };
        assert!(limits.no_packet_limit());
        let mut limiter =
            limits.into_limiter::<&str>(vec!["ir", "cn"], Arc::new(AtomicBool::new(false)));
        let packets = vec![
            MP {
                // rejected, not part of a flow despite no flow limit
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // rejected, not using a known key despite being valid new flow
                afi: String::from("5"),
                keys: vec!["ru".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::NoRelevantKeys),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // accepted as part of known flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
            MP {
                // new flow 2
                afi: String::from("2"),
                keys: vec!["cn".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("cn".into()),
            },
            MP {
                // denied since we are over flow count
                afi: String::from("3"),
                keys: vec!["cn".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::Full(Hashable::Z)),
            },
            MP {
                // accepted as part of known flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok(Hashable::Z),
            },
        ];

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }

    #[test]
    fn lfk_x_lppf_x_k_below_lp() -> Result<(), Box<dyn Error>> {
        let limits = Limits {
            lpk: 0,
            lfk: 1,
            lp: 5,
            lf: 0,
            lppf: 2,
        };
        assert!(!limits.no_packet_limit());
        let mut limiter =
            limits.into_limiter::<&str>(vec!["ir", "cn"], Arc::new(AtomicBool::new(false)));
        let packets = vec![
            MP {
                // rejected, not part of a flow despite no flow limit
                afi: String::from("2"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::UnknownFlow),
            },
            MP {
                // rejected, not using a known key despite being valid new flow
                afi: String::from("5"),
                keys: vec!["ru".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::NoRelevantKeys),
            },
            MP {
                // new flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // accepted as part of known flow 1
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Ok("ir".into()),
            },
            MP {
                // denied since ir is at the ppf limit
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::FullPPF),
            },
            MP {
                // new flow 2
                afi: String::from("2"),
                keys: vec!["cn".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Ok("cn".into()),
            },
            MP {
                // denied since we are over flow count for cn
                afi: String::from("3"),
                keys: vec!["cn".into()],
                t: PacketType::TCPSYN,
                erfs: false,
                expected: Err(LimitError::Full("cn".into())),
            },
            MP {
                // denied since ir is at the ppf limit
                afi: String::from("1"),
                keys: vec!["ir".into()],
                t: PacketType::TCPOther,
                erfs: false,
                expected: Err(LimitError::FullPPF),
            },
            MP {
                // allowed, but sets flag since we cannot receive any more packets
                afi: String::from("2"),
                keys: vec!["cn".into()],
                t: PacketType::TCPOther,
                erfs: true,
                expected: Ok("cn".into()),
            },
        ];

        run_test(&mut limiter, packets).unwrap();
        Ok(())
    }
}
