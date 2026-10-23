use crate::interface::InterfaceType;
use std::convert::TryFrom;
use std::fs::{read_link, read_to_string};

fn is_wifi_interface(interface_name: &str) -> bool {
    let wireless_path = format!("/sys/class/net/{}/wireless", interface_name);
    let phy80211_path = format!("/sys/class/net/{}/phy80211", interface_name);
    std::path::Path::new(&wireless_path).exists() || std::path::Path::new(&phy80211_path).exists()
}

pub fn is_virtual_interface(interface_name: &str) -> bool {
    let device_path = format!("/sys/class/net/{}", interface_name);
    match read_link(device_path) {
        Ok(link_path) => {
            // If the link path contains `virtual`, then it is a virtual interface.
            link_path.to_string_lossy().contains("virtual")
        }
        Err(_) => false,
    }
}

pub fn get_interface_type(if_name: String) -> InterfaceType {
    let if_type_path: String = format!("/sys/class/net/{}/type", if_name);
    let r = read_to_string(if_type_path);
    match r {
        Ok(content) => {
            let if_type_string = content.trim().to_string();
            match if_type_string.parse::<u32>() {
                Ok(if_type) => {
                    if if_type == crate::sys::if_arp::ARPHRD_ETHER {
                        // Since some Wi-Fi interfaces may also be reported as Ethernet,
                        // further check if the interface is actually Wi-Fi.
                        if is_wifi_interface(&if_name) {
                            return InterfaceType::Wireless80211;
                        } else {
                            return InterfaceType::Ethernet;
                        }
                    } else {
                        return InterfaceType::try_from(if_type).unwrap_or(InterfaceType::Unknown);
                    }
                }
                Err(_) => {
                    return InterfaceType::Unknown;
                }
            }
        }
        Err(_) => {
            return InterfaceType::Unknown;
        }
    };
}

pub fn get_interface_speed(if_name: String) -> Option<u64> {
    let if_speed_path: String = format!("/sys/class/net/{}/speed", if_name);
    let r = read_to_string(if_speed_path);
    match r {
        Ok(content) => {
            let if_speed_string = content.trim().to_string();
            match if_speed_string.parse::<u64>() {
                Ok(if_speed) => {
                    // Convert Mbps to bps
                    return Some(if_speed * 1000000);
                }
                Err(_) => {
                    return None;
                }
            }
        }
        Err(_) => {
            return None;
        }
    };
}
