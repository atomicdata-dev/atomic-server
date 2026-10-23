#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::mac::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Structure of NetworkDevice information
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetworkDevice {
    /// MAC address of the device
    pub mac_addr: MacAddr,
    /// List of IPv4 address of the device
    pub ipv4: Vec<Ipv4Addr>,
    /// List of IPv6 address of the device
    pub ipv6: Vec<Ipv6Addr>,
}

impl NetworkDevice {
    /// Construct a new NetworkDevice instance
    pub fn new() -> NetworkDevice {
        NetworkDevice {
            mac_addr: MacAddr::zero(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        }
    }
}
