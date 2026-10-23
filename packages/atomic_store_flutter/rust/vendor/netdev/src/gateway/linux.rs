use crate::device::NetworkDevice;
use crate::mac::MacAddr;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

const PATH_PROC_NET_ROUTE: &str = "/proc/net/route";
const PATH_PROC_NET_IPV6_ROUTE: &str = "/proc/net/ipv6_route";
const PATH_PROC_NET_ARP: &str = "/proc/net/arp";

fn convert_hex_ipv4(hex_ip: &str) -> Ipv4Addr {
    if hex_ip.len() != 8 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let o1: u8 = u8::from_str_radix(&hex_ip[6..8], 0x10).unwrap_or(0);
    let o2: u8 = u8::from_str_radix(&hex_ip[4..6], 0x10).unwrap_or(0);
    let o3: u8 = u8::from_str_radix(&hex_ip[2..4], 0x10).unwrap_or(0);
    let o4: u8 = u8::from_str_radix(&hex_ip[0..2], 0x10).unwrap_or(0);
    Ipv4Addr::new(o1, o2, o3, o4)
}

fn convert_hex_ipv6(hex_ip: &str) -> Ipv6Addr {
    if hex_ip.len() != 32 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let h1: u16 = u16::from_str_radix(&hex_ip[0..4], 0x10).unwrap_or(0);
    let h2: u16 = u16::from_str_radix(&hex_ip[4..8], 0x10).unwrap_or(0);
    let h3: u16 = u16::from_str_radix(&hex_ip[8..12], 0x10).unwrap_or(0);
    let h4: u16 = u16::from_str_radix(&hex_ip[12..16], 0x10).unwrap_or(0);
    let h5: u16 = u16::from_str_radix(&hex_ip[16..20], 0x10).unwrap_or(0);
    let h6: u16 = u16::from_str_radix(&hex_ip[20..24], 0x10).unwrap_or(0);
    let h7: u16 = u16::from_str_radix(&hex_ip[24..28], 0x10).unwrap_or(0);
    let h8: u16 = u16::from_str_radix(&hex_ip[28..32], 0x10).unwrap_or(0);
    Ipv6Addr::new(h1, h2, h3, h4, h5, h6, h7, h8)
}

fn get_arp_map() -> HashMap<Ipv4Addr, MacAddr> {
    let mut arp_map: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let arp_data = read_to_string(PATH_PROC_NET_ARP);
    let arp_text = match arp_data {
        Ok(content) => content,
        Err(_) => String::new(),
    };
    let arp_table: Vec<&str> = arp_text.trim().split("\n").collect();
    for row in arp_table {
        let mut fields: Vec<&str> = row.split(" ").collect();
        fields.retain(|value| *value != "");
        if fields.len() >= 6 {
            // fields[0]: IP Address
            // fields[3]: MAC Address (colon-separated string of hex format)
            // fields[5]: Interface Name
            match Ipv4Addr::from_str(fields[0]) {
                Ok(ipv4_addr) => {
                    arp_map.insert(ipv4_addr, MacAddr::from_hex_format(fields[3]));
                }
                Err(_) => {}
            }
        }
    }
    arp_map
}

fn get_ipv4_gateway_map() -> HashMap<String, Ipv4Addr> {
    let mut ipv4_gateway_map: HashMap<String, Ipv4Addr> = HashMap::new();
    let route_data = read_to_string(PATH_PROC_NET_ROUTE);
    let route_text = match route_data {
        Ok(content) => content,
        Err(_) => String::new(),
    };
    let route_table: Vec<&str> = route_text.trim().split("\n").collect();
    for row in route_table {
        let fields: Vec<&str> = row.split("\t").collect();
        if fields.len() >= 3 {
            // fields[0]: Interface Name
            // fields[2]: IPv4 Address 8 hex chars
            if fields[2] != "00000000" {
                ipv4_gateway_map.insert(fields[0].to_string(), convert_hex_ipv4(fields[2]));
            }
        }
    }
    ipv4_gateway_map
}

fn get_ipv6_gateway_map() -> HashMap<String, Ipv6Addr> {
    let mut ipv6_gateway_map: HashMap<String, Ipv6Addr> = HashMap::new();
    let route_data = read_to_string(PATH_PROC_NET_IPV6_ROUTE);
    let route_text = match route_data {
        Ok(content) => content,
        Err(_) => String::new(),
    };
    let route_table: Vec<&str> = route_text.trim().split("\n").collect();
    for row in route_table {
        let fields: Vec<&str> = row.split("\t").collect();
        if fields.len() >= 10 {
            // fields[4]: IPv6 Address 32 hex chars without colons
            // fields[9]: Interface Name
            if fields[4] != "00000000000000000000000000000000" {
                ipv6_gateway_map.insert(fields[9].to_string(), convert_hex_ipv6(fields[4]));
            }
        }
    }
    ipv6_gateway_map
}

pub fn get_gateway_map() -> HashMap<String, NetworkDevice> {
    let mut gateway_map: HashMap<String, NetworkDevice> = HashMap::new();
    let arp_map: HashMap<Ipv4Addr, MacAddr> = get_arp_map();
    for (if_name, ipv4_addr) in get_ipv4_gateway_map() {
        let gateway = gateway_map.entry(if_name).or_insert(NetworkDevice::new());
        if let Some(mac_addr) = arp_map.get(&ipv4_addr) {
            gateway.mac_addr = mac_addr.clone();
        }
        gateway.ipv4.push(ipv4_addr);
    }
    for (if_name, ipv6_addr) in get_ipv6_gateway_map() {
        let gateway = gateway_map.entry(if_name).or_insert(NetworkDevice::new());
        gateway.ipv6.push(ipv6_addr);
    }
    gateway_map
}
