extern crate ipnetwork;

use std::collections::{BTreeMap, LinkedList};
use redis;

use self::ipnetwork::{IpNetwork};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct DDIpSelector {
    pub networks: BTreeMap<u32, Vec<String>>,
    // redis_conn: redis::Connection, // TODO
}

// Current implementation --> static map
fn get_static_subnets() ->  [Vec<String>; 2] {
    return  [
        vec![String::from("192.122.190.0/24"), String::from("2001:48a8:687f:1::/64")], // Gen 1
        vec![String::from("192.122.190.0/28"), String::from("2001:48a8:687f:1::/96")], // Gen 2
    ]
}

impl DDIpSelector {
    
    
    pub fn new() -> DDIpSelector {
        
        let blocks_by_generation = BTreeMap::new();
        let mut ret = DDIpSelector {
            networks: blocks_by_generation,
            // redis_conn: get_redis_conn(), TODO
        };
        for subnets in get_static_subnets().iter() {
            let _c = ret.add_generation(&subnets);
        }
        ret
    }

    pub fn select(&self, seed: [u8; 16], generation: u32, dd_client_v6_support: bool ) -> Option<IpAddr> 
    {
        let subnets = match self.get_generation_subnets(generation) {
            Some(net_list) => net_list,
            None => {
                return None
            },
        };

        let mut addresses_total: u128 = 0;
        let mut id_net = LinkedList::new(); // (min_id, max_id, subnet)

        for net_str in subnets.iter() {
            let net: IpNetwork = net_str.parse().unwrap();
            match net {
                IpNetwork::V4(_) => {
                    let old_addresses_total = addresses_total;
                    addresses_total += 2u128.pow((32 - net.prefix()).into()) - 1;
                    id_net.push_back((old_addresses_total, addresses_total, net));
                }
                IpNetwork::V6(_) => {
                    if dd_client_v6_support {
                        let old_addresses_total = addresses_total;
                        addresses_total += 2u128.pow((128 - net.prefix()).into()) - 1;
                        id_net.push_back((old_addresses_total, addresses_total, net));
                    }
                }
            }
        }


        let mut id = array_as_u128_be(&seed);
        if id >= addresses_total {
            id = id % addresses_total;
        }

        for elem in id_net.iter() {
            if elem.0 < id && elem.1 >= id {
                match elem.2 {
                    IpNetwork::V4(netv4) => {
                        let min_ip_u32: u32 = array_as_u32_be(&netv4.ip().octets());
                        let ip_u32 = min_ip_u32 + ((id - elem.0) as u32);
                        return Some(IpAddr::from(Ipv4Addr::from(ip_u32)));
                    }
                    IpNetwork::V6(netv6) => {
                        let min_ip_u128 = array_as_u128_be(&netv6.ip().octets());
                        let ip_u128 = min_ip_u128 + (id - elem.0);
                        return Some(IpAddr::from(Ipv6Addr::from(ip_u128)));
                    }
                }
            }
        }
        error!("failed to pick dark decoy IP with seed={:?}, in {:?}", seed, id_net);
        None
    }

    pub fn add_generation(&mut self, subnets: &Vec<String>) -> u32 
    {
        let max_idx = self.networks.len() as u32;
        self.networks.insert(max_idx+1, (*subnets).clone());
        return max_idx + 1 
    }

    fn remove_generation(&mut self, generation: u32) -> bool 
    {
        if self.networks.contains_key(&generation) {
            self.networks.remove(&generation);
            return true
        } else {
            return false
        }
    }

    fn update_generation(&mut self, generation: u32, subnets: &Vec<String>) -> bool 
    {
        if self.networks.contains_key(&generation) {
            self.networks.insert(generation, (*subnets).clone());
            return true
        } else {
            return false
        }
    }

    pub fn get_generation_subnets(&self, generation: u32) -> Option<Vec<String>> 
    {
        self.networks.get(&generation);
        return None
    }

    // fn ipnetworks_from_vec(subnets: &Vec<String>, dd_client_v6_support: bool ) -> Option<Vec<String>> 
    // {
    //     let mut net_list = LinkedList::new();
    //     for str_net in subnets.iter() {
    //         let net: IpNetwork = str_net.parse()?;
    //         if dd_client_v6_support {
    //             net_list.push_back(net.clone());
    //         } else {
    //             match net {
    //                 IpNetwork::V4(_) => net_list.push_back(net.clone()),
    //                 IpNetwork::V6(_) => (),
    //             }
    //         }
    //     }
    //     return net_list
    // }

    //TODO: Integrate with REDIS So that new generations can be added via network
}


fn array_as_u128_be(a: &[u8; 16]) -> u128 {
    ((a[0] as u128) << 120) +
        ((a[1] as u128) << 112) +
        ((a[2] as u128) << 104) +
        ((a[3] as u128) << 96) +
        ((a[4] as u128) << 88) +
        ((a[5] as u128) << 80) +
        ((a[6] as u128) << 72) +
        ((a[7] as u128) << 64) +
        ((a[8] as u128) << 56) +
        ((a[9] as u128) << 48) +
        ((a[10] as u128) << 40) +
        ((a[11] as u128) << 32) +
        ((a[12] as u128) << 24) +
        ((a[13] as u128) << 16) +
        ((a[14] as u128) << 8) +
        ((a[15] as u128) << 0)
}

fn array_as_u32_be(a: &[u8; 4]) -> u32 {
    ((a[0] as u32) << 24) +
        ((a[1] as u32) << 16) +
        ((a[2] as u32) << 8) +
        ((a[3] as u32) << 0)
}


fn get_redis_conn() -> redis::Connection
{
    let client = redis::Client::open("redis://127.0.0.1/").expect("Can't open Redis");
    let mut con = client.get_connection().expect("Can't get Redis connection");;
    con
}


#[cfg(test)]
mod tests {
    use util;
    use dd_selector::{DDIpSelector};
    use rand::Rng;
    use super::ipnetwork::{IpNetwork};
    use std::net::{IpAddr, Ipv4Addr};

 
    #[test]
    fn mem_used_kb_parses_something()
    {
        assert!(util::mem_used_kb() > 0);
    }

    #[test]
    fn test_dd_ip_selector4() {

        let dd_ip_selector = DDIpSelector::new();

        let seed_bytes = rand::thread_rng().gen::<[u8; 16]>();
        let gen = 1;

        let dark_decoy_addr = match dd_ip_selector.select(seed_bytes, gen, false) {
            Some(ip) => ip,
            None => {
                error!("failed to select dark decoy IP address");
                return
            }
        };

        println!("{:?}\n",dark_decoy_addr);

        let dark_decoy_addr4: Ipv4Addr = match dark_decoy_addr {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("Ipv6 Address SHOULD NOT BE CHOSEN"),
        };

        let mut included = false;
        for net_str in dd_ip_selector.get_generation_subnets(gen).unwrap().iter() {
            let net: IpNetwork = net_str.parse().unwrap();
            match net {
                IpNetwork::V4(net4) => {
                    if net4.contains( dark_decoy_addr4 ) {
                        included = true
                    }
                }
                IpNetwork::V6(_) => {
                    panic!("Error V6 address block found");
                }
            }
        }

        assert_eq!(included, true)
    }

    #[test]
    fn test_dd_ip_selector6() {
        let dd_ip_selector = DDIpSelector::new();

        let seed_bytes = rand::thread_rng().gen::<[u8; 16]>();
        let  gen = 1;
        
        let dark_decoy_addr = match dd_ip_selector.select(seed_bytes, gen, true) {
            Some(ip) => ip,
            None => {
                error!("failed to select dark decoy IP address");
                return
            }
        };

        println!("{:?}\n",dark_decoy_addr);

        let dark_decoy_ip4 = match dark_decoy_addr {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        };

        let dark_decoy_ip6 = match dark_decoy_addr {
            IpAddr::V4(_) => None,
            IpAddr::V6(ip) => Some(ip),
        };

        let mut included: bool = false;
        for net_str in dd_ip_selector.get_generation_subnets(gen).unwrap().iter() {
            let net: IpNetwork = net_str.parse().unwrap();
            match net {
                IpNetwork::V4(net4) => {
                    match dark_decoy_ip4 {
                        Some(ip) => {
                            if net4.contains( ip ) {
                                included = true
                            }
                        },
                        None => {},
                    }
                },
                IpNetwork::V6(net6) => {
                    match dark_decoy_ip6 {
                        Some(ip) => {
                            if net6.contains( ip ) {
                                included = true
                            }
                        },
                        None => {},
                    }
                },
            } // End Match Network type  
        } // End iterate through subnets

        assert_eq!(included, true)
    }
}
