#[cfg(any(target_os = "openbsd", target_os = "freebsd", target_os = "netbsd"))]
pub(crate) mod bsd;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) mod macos;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod linux;

use crate::device::NetworkDevice;
use crate::interface::{self, Interface};
use std::net::IpAddr;

/// Get default Gateway
pub fn get_default_gateway() -> Result<NetworkDevice, String> {
    let local_ip: IpAddr = match interface::get_local_ipaddr() {
        Some(local_ip) => local_ip,
        None => return Err(String::from("Local IP address not found")),
    };
    let interfaces: Vec<Interface> = interface::get_interfaces();
    for iface in interfaces {
        match local_ip {
            IpAddr::V4(local_ipv4) => {
                if iface.ipv4.iter().any(|x| x.addr() == local_ipv4) {
                    if let Some(gateway) = iface.gateway {
                        return Ok(gateway);
                    }
                }
            }
            IpAddr::V6(local_ipv6) => {
                if iface.ipv6.iter().any(|x| x.addr() == local_ipv6) {
                    if let Some(gateway) = iface.gateway {
                        return Ok(gateway);
                    }
                }
            }
        }
    }
    Err(String::from("Default Gateway not found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_gateway() {
        println!("{:?}", get_default_gateway());
    }
}
