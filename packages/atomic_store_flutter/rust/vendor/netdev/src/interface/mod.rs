mod shared;
pub use self::shared::*;

mod types;
pub use self::types::*;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "ios",
    target_os = "android"
))]
mod unix;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "ios",
    target_os = "android"
))]
use self::unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use self::windows::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "macos")]
mod macos;

use crate::device::NetworkDevice;
use crate::ipnet::{Ipv4Net, Ipv6Net};
use crate::mac::MacAddr;
use crate::sys;
use std::net::IpAddr;

/// Structure of Network Interface information
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Interface {
    /// Index of network interface
    pub index: u32,
    /// Name of network interface
    pub name: String,
    /// Friendly Name of network interface
    pub friendly_name: Option<String>,
    /// Description of the network interface
    pub description: Option<String>,
    /// Interface Type
    pub if_type: InterfaceType,
    /// MAC address of network interface
    pub mac_addr: Option<MacAddr>,
    /// List of Ipv4Net for the network interface
    pub ipv4: Vec<Ipv4Net>,
    /// List of Ipv6Net for the network interface
    pub ipv6: Vec<Ipv6Net>,
    /// Flags for the network interface (OS Specific)
    pub flags: u32,
    /// Speed in bits per second of the transmit for the network interface
    pub transmit_speed: Option<u64>,
    /// Speed in bits per second of the receive for the network interface
    pub receive_speed: Option<u64>,
    /// Default gateway for the network interface
    pub gateway: Option<NetworkDevice>,
    /// DNS servers for the network interface
    pub dns_servers: Vec<IpAddr>,
    /// is default interface
    pub default: bool,
}

impl Interface {
    /// Construct a new default Interface instance
    pub fn default() -> Result<Interface, String> {
        let interfaces: Vec<Interface> = interfaces();
        for iface in &interfaces {
            if iface.default {
                return Ok(iface.clone());
            }
        }
        let local_ip: IpAddr = match get_local_ipaddr() {
            Some(local_ip) => local_ip,
            None => return Err(String::from("Local IP address not found")),
        };
        for iface in interfaces {
            match local_ip {
                IpAddr::V4(local_ipv4) => {
                    if iface.ipv4.iter().any(|x| x.addr() == local_ipv4) {
                        return Ok(iface);
                    }
                }
                IpAddr::V6(local_ipv6) => {
                    if iface.ipv6.iter().any(|x| x.addr() == local_ipv6) {
                        return Ok(iface);
                    }
                }
            }
        }
        Err(String::from("Default Interface not found"))
    }
    // Construct a dummy Interface instance
    pub fn dummy() -> Interface {
        Interface {
            index: 0,
            name: String::new(),
            friendly_name: None,
            description: None,
            if_type: InterfaceType::Unknown,
            mac_addr: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            flags: 0,
            transmit_speed: None,
            receive_speed: None,
            gateway: None,
            dns_servers: Vec::new(),
            default: false,
        }
    }
    /// Check if the network interface is up
    pub fn is_up(&self) -> bool {
        self.flags & (sys::IFF_UP as u32) != 0
    }
    /// Check if the network interface is a Loopback interface
    pub fn is_loopback(&self) -> bool {
        self.flags & (sys::IFF_LOOPBACK as u32) != 0
    }
    /// Check if the network interface is a Point-to-Point interface
    pub fn is_point_to_point(&self) -> bool {
        self.flags & (sys::IFF_POINTOPOINT as u32) != 0
    }
    /// Check if the network interface is a Multicast interface
    pub fn is_multicast(&self) -> bool {
        self.flags & (sys::IFF_MULTICAST as u32) != 0
    }
    /// Check if the network interface is a Broadcast interface
    pub fn is_broadcast(&self) -> bool {
        self.flags & (sys::IFF_BROADCAST as u32) != 0
    }
    /// Check if the network interface is a TUN interface
    pub fn is_tun(&self) -> bool {
        self.is_up() && self.is_point_to_point() && !self.is_broadcast() && !self.is_loopback()
    }
    /// Check if the network interface is running and ready to send/receive packets
    pub fn is_running(&self) -> bool {
        is_running(&self)
    }
    /// Check if the network interface is a physical interface
    pub fn is_physical(&self) -> bool {
        is_physical_interface(&self)
            && !crate::db::oui::is_virtual_mac(&self.mac_addr.unwrap_or(MacAddr::zero()))
            && !crate::db::oui::is_known_loopback_mac(&self.mac_addr.unwrap_or(MacAddr::zero()))
    }
}

/// Get default Network Interface
pub fn get_default_interface() -> Result<Interface, String> {
    let interfaces: Vec<Interface> = interfaces();
    for iface in &interfaces {
        if iface.default {
            return Ok(iface.clone());
        }
    }
    let local_ip: IpAddr = match get_local_ipaddr() {
        Some(local_ip) => local_ip,
        None => return Err(String::from("Local IP address not found")),
    };
    for iface in interfaces {
        match local_ip {
            IpAddr::V4(local_ipv4) => {
                if iface.ipv4.iter().any(|x| x.addr() == local_ipv4) {
                    return Ok(iface);
                }
            }
            IpAddr::V6(local_ipv6) => {
                if iface.ipv6.iter().any(|x| x.addr() == local_ipv6) {
                    return Ok(iface);
                }
            }
        }
    }
    Err(String::from("Default Interface not found"))
}

/// Get a list of available Network Interfaces
pub fn get_interfaces() -> Vec<Interface> {
    interfaces()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_interfaces() {
        let interfaces = get_interfaces();
        for interface in interfaces {
            println!("{:#?}", interface);
        }
    }
    #[test]
    fn test_default_interface() {
        println!("{:#?}", get_default_interface());
    }
}
