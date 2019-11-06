extern crate ipnetwork;

use std::collections::{HashMap, LinkedList};
use std::fmt;
use std::fmt::{Write};
use redis;

use self::ipnetwork::{IpNetwork};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


// Blacklist is a quick hack for preventing clients from choosing LIVE
// hosts on the (admittedly small) ipv4 decoy space as their dark decoy.
struct DDBlackList {}

impl fmt::Debug for DDBlackList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "blacklist: {:?}\n", DDBlackList::List)
    }
}

impl DDBlackList {
    const List: [&'static str; 7] = [
        "192.122.190.101", "192.122.190.104", "192.122.190.105",
        "192.122.190.106", "192.122.190.108", "192.122.190.109",
        "192.122.190.110"];

    pub fn contains(ip: IpAddr) -> bool {
        for addr in DDBlackList::List.iter() {
            let net: IpNetwork = addr.parse().unwrap();
            if net.contains(ip) {
                return true
            }
        }
        return false
    }
}

#[derive(Debug)]
pub struct DDIpSelector {
    pub networks: HashMap<u32, Vec<&'static str>>,
    // redis_conn: redis::Connection, // TODO
}

// Current implementation --> static map
fn get_static_subnets() ->  HashMap<u32, Vec<&'static str>> {
    return  [
        (1, vec!["192.122.190.0/24", "2001:48a8:687f:1::/64"]), // Gen 1
        (2, vec!["192.122.190.0/28", "2001:48a8:687f:1::/96"]), // Gen 2
    ].iter().cloned().collect()
}

impl DDIpSelector {
    
    pub fn new() -> DDIpSelector {
        let new_selector = DDIpSelector {
            networks: get_static_subnets(),
            // redis_conn: get_redis_conn(), TODO
        };
        new_selector
    }

    pub fn select(&self, seed: [u8; 16], generation: u32, dd_client_v6_support: bool ) -> Result<IpAddr, DDSelectorErr>
    {
        let subnets = match self.get_generation_subnets(generation) {
            Ok(net_list) => net_list,
            Err(_) => {
                warn!("Unrecognized ClientConf gen using default subnet list: {}", generation);
                DDIpSelector::default_subnets()
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
                        let chosen_addr = IpAddr::from(Ipv4Addr::from(ip_u32));

                        if DDBlackList::contains(chosen_addr) {
                            let message = format!("Chose blacklisted IP ({})", chosen_addr);
                            return Err(DDSelectorErr{generation, message})
                        } else {
                            return Ok(chosen_addr)
                        }
                    }
                    IpNetwork::V6(netv6) => {
                        let min_ip_u128 = array_as_u128_be(&netv6.ip().octets());
                        let ip_u128 = min_ip_u128 + (id - elem.0);
                        return Ok(IpAddr::from(Ipv6Addr::from(ip_u128)));
                    }
                }
            }
        }
        let msg = format!("Failed to pick dark decoy ip (seed: {:?}, subnets: {:?}", seed, id_net);
        Err(DDSelectorErr{ message: msg, generation: generation})
    }

    pub fn add_generation(&mut self, subnets: &Vec<&'static str>) -> u32 
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

    fn update_generation(&mut self, generation: u32, subnets: &Vec<&'static str>) -> bool 
    {
        if self.networks.contains_key(&generation) {
            self.networks.insert(generation, (*subnets).clone());
            return true
        } else {
            return false
        }
    }

    pub fn get_generation_subnets(&self, generation: u32) -> Result<Vec<&'static str>, DDSelectorErr>
    {
        match self.networks.get(&generation) {
            Some (subnets) => Ok(subnets.to_owned()),
            None => Err(DDSelectorErr{generation, message: String::from("Unrecognized generation")}),
        }
    }

    pub fn default_subnets() -> Vec<&'static str> {
        vec!["192.122.190.0/24", "2001:48a8:687f:1::/64"].to_owned()
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

impl fmt::Display for DDIpSelector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut combined_str = String::new();
        
        for (gen_idx, gen) in self.networks.iter() {
            write!(&mut combined_str, "{} -[", gen_idx).unwrap();
            for net in gen.iter() {
                write!(&mut combined_str, "{}  ", net).unwrap();
            }
            write!(&mut combined_str,"]\n").unwrap();
        }
        write!(f, "{}", combined_str)
    }
}


pub struct DDSelectorErr {
    generation: u32,
    message: String,
}

impl fmt::Display for DDSelectorErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.message, self.generation)
    }
}

impl fmt::Debug for DDSelectorErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DDSelectorErr {{ generation: {}, message: {} }}", self.generation, self.message)
    }
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
    let con = client.get_connection().expect("Can't get Redis connection");;
    con
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;


    #[test]
    fn test_blacklist() {
        let ip_blacklisted: IpAddr = "192.122.190.105".parse().unwrap();
        let ip_okay: IpAddr = "192.122.190.120".parse().unwrap();

        assert_eq!(true, DDBlackList::contains(ip_blacklisted));
        assert_eq!(false, DDBlackList::contains(ip_okay));

    }

    #[test]
    fn test_get_generation() {
        let dd_ip_selector = DDIpSelector::new();
        println!("All Generations:\n{}", dd_ip_selector);
        let gen1 = match dd_ip_selector.get_generation_subnets(1) {
            Ok(subnets) => subnets,
            Err(_) => {
                println!("No subnets returned, unrecognized gen -- using default");
                DDIpSelector::default_subnets()
            },
        };
        // for net in gen1 {
        //     println!("{:?}", net);
        // }

        let gen1_real = vec!["192.122.190.0/24", "2001:48a8:687f:1::/64"];
        assert_eq!(gen1_real, gen1);
    }

    #[test]
    fn test_dd_ip_selector4() {

        let dd_ip_selector = DDIpSelector::new();

        let seed_bytes = rand::thread_rng().gen::<[u8; 16]>();
        let gen = 1;

        let dark_decoy_addr = match dd_ip_selector.select(seed_bytes, gen, false) {
            Ok(ip) => ip,
            Err(e) => {
                panic!("Failed to select dark decoy IP address: {}", e);
            }
        };

        println!("{:?}\n",dark_decoy_addr);

        match dark_decoy_addr {
            IpAddr::V4(_) => {},
            IpAddr::V6(_) => panic!("Ipv6 Address SHOULD NOT BE CHOSEN"),
        };

        let subnets = match dd_ip_selector.get_generation_subnets(gen){
            Ok(nets) =>  nets,
            Err(e) => {
                println!("{}", e);
                DDIpSelector::default_subnets()
            },
        };
        assert_eq!(check_subnets_contain_ip(dark_decoy_addr, subnets), true)
    }

    #[test]
    fn test_dd_ip_selector6() {
        let dd_ip_selector = DDIpSelector::new();

        let seed_bytes = rand::thread_rng().gen::<[u8; 16]>();
        let  gen = 1;
        
        let dark_decoy_addr = match dd_ip_selector.select(seed_bytes, gen, true) {
            Ok(ip) => ip,
            Err(e) => {
                panic!("Failed to select dark decoy IP address: {}", e);
            }
        };

        println!("{:?}\n",dark_decoy_addr);

        let subnets = match dd_ip_selector.get_generation_subnets(gen){
            Ok(nets) => nets,
            Err(e) => {
                println!("{}", e);
                DDIpSelector::default_subnets()
            },
        };
        assert_eq!(true, check_subnets_contain_ip(dark_decoy_addr, subnets));
    }

    #[test]
    fn test_seeded_selection() {

        let mut dd_ip_selector = DDIpSelector::new();
        let seed_bytes: [u8; 16] = [
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 
            0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF];

        let new_addr1 = vec!["18.0.0.0/8", "1234::/64"];
        let gen = dd_ip_selector.add_generation( &new_addr1);

        let dark_decoy_addr6 = match dd_ip_selector.select(seed_bytes, gen, true) {
            Ok(ip) => ip,
            Err(e) => {
                panic!("Failed to select dark decoy IP address: {}", e);
            }
        };

        let dark_decoy_addr4 = match dd_ip_selector.select(seed_bytes, gen, false) {
            Ok(ip) => ip,
            Err(e) => {
                panic!("Failed to select dark decoy IP address: {}", e);
            }
        };

        println!("{}\n", dark_decoy_addr4);
        println!("{}\n", dark_decoy_addr6);

        // Correct addresses were chosen based on seed from test generation  w/ and w/out v6 support
        assert_eq!("1234::507:90c:e17:181a".parse(), Ok(dark_decoy_addr6));
        assert_eq!("18.35.40.45".parse(), Ok(dark_decoy_addr4));
    }

    #[test] 
    fn test_remove_generation() {
        let mut dd_ip_selector = DDIpSelector::new();
        let seed_bytes: [u8; 16] = [
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 
            0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF];

        let new_addr1 = vec!["18.0.0.0/8", "1234::/64"];
        let gen = dd_ip_selector.add_generation( &new_addr1);

        match dd_ip_selector.select(seed_bytes, gen, true) {
            Ok(ip) => {
                println!("{}", ip);
            },
            Err(e) => {
                panic!("failed to select dark decoy IP address: {}", e);
            }
        };

        // Successful removal
        assert_eq!(true, dd_ip_selector.remove_generation(gen));

        // when selecting from non-existant generation 
        // address selected from default subnet list.
        let fall_back_ip = match dd_ip_selector.select(seed_bytes, gen, true){
            Ok(ip) => ip,
            Err(e) => panic!("Failed to select dark decoy IP address from Default list: {}", e),
        };
        assert_eq!("2001:48a8:687f:1:709:b0d:f11:121e".parse(), Ok(fall_back_ip));
    }


    fn check_subnets_contain_ip(ip: IpAddr, subnets: Vec<&str>) -> bool {
       let dark_decoy_ip4 = match ip {
            IpAddr::V4(ip4) => Some(ip4),
            IpAddr::V6(_) => None,
        };

        let dark_decoy_ip6 = match ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(ip6) => Some(ip6),
        };

        let mut included = false;
        for net_str in subnets.iter() {
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
        included
    }
}
