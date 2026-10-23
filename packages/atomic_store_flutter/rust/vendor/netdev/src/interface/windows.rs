use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetIfEntry2, SendARP, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
    MIB_IF_ROW2, MIB_IF_ROW2_0,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_OPER_STATUS_UP;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET, SOCKET_ADDRESS,
};

use crate::device::NetworkDevice;
use crate::interface::{Interface, InterfaceType};
use crate::ipnet::{Ipv4Net, Ipv6Net};
use crate::mac::MacAddr;
use crate::sys;
use std::ffi::CStr;
use std::mem::MaybeUninit;

//const IFF_HARDWARE_INTERFACE: u8 = 0b0000_0001;
//const IFF_FILTER_INTERFACE: u8 = 0b0000_0010;
const IFF_CONNECTOR_PRESENT: u8 = 0b0000_0100;
//const IFF_NOT_AUTHENTICATED: u8 = 0b0000_1000;
//const IFF_NOT_MEDIA_CONNECTED: u8 = 0b0001_0000;
//const IFF_PAUSED: u8 = 0b0010_0000;
//const IFF_LOW_POWER: u8 = 0b0100_0000;
//const IFF_END_POINT_INTERFACE: u8 = 0b1000_0000;

fn get_mac_through_arp(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> MacAddr {
    let src_ip_int = u32::from_ne_bytes(src_ip.octets());
    let dst_ip_int = u32::from_ne_bytes(dst_ip.octets());
    let mut out_buf_len = 6;
    let mut target_mac_addr = MaybeUninit::<[u8; 6]>::uninit();
    let res = unsafe {
        SendARP(
            dst_ip_int,
            src_ip_int,
            target_mac_addr.as_mut_ptr().cast(),
            &mut out_buf_len,
        )
    };
    if res == NO_ERROR {
        assert_eq!(out_buf_len, 6);
        MacAddr::from_octets(unsafe { target_mac_addr.assume_init() })
    } else {
        MacAddr::zero()
    }
}

unsafe fn socket_address_to_ipaddr(addr: &SOCKET_ADDRESS) -> Option<IpAddr> {
    let sockaddr = addr.lpSockaddr.cast::<SOCKADDR_INET>().as_ref()?;

    Some(match sockaddr.si_family {
        AF_INET => unsafe { sockaddr.Ipv4.sin_addr.S_un.S_addr }
            .to_ne_bytes()
            .into(),
        AF_INET6 => unsafe { sockaddr.Ipv6.sin6_addr.u.Byte }.into(),
        _ => return None,
    })
}

pub fn is_running(interface: &Interface) -> bool {
    interface.is_up()
}

/// Check if a network interface has a connector present, indicating it is a physical interface.
fn is_connector_present(if_index: u32) -> bool {
    // Initialize MIB_IF_ROW2
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = if_index;
    // Retrieve interface information using GetIfEntry2
    unsafe {
        if GetIfEntry2(&mut row) != 0 {
            eprintln!("Failed to get interface entry for index: {}", if_index);
            return false;
        }
    }
    // Check if the connector is present
    let oper_status_flags: MIB_IF_ROW2_0 = row.InterfaceAndOperStatusFlags;
    oper_status_flags._bitfield & IFF_CONNECTOR_PRESENT != 0
}

pub fn is_physical_interface(interface: &Interface) -> bool {
    is_connector_present(interface.index)
        || (interface.is_up()
            && interface.is_running()
            && !interface.is_tun()
            && !interface.is_loopback())
}

unsafe fn from_wide_string(ptr: *const u16) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

// Note: We take `&*mut T` instead of just `*mut T` to tie the lifetime of all the returned items
// to the lifetime of the pointer for some extra safety.
unsafe fn linked_list_iter<T>(ptr: &*mut T, next: fn(&T) -> *mut T) -> impl Iterator<Item = &T> {
    let mut ptr = ptr.cast_const();

    std::iter::from_fn(move || {
        let cur = ptr.as_ref()?;
        ptr = next(cur);
        Some(cur)
    })
}

// The `Next` element is always the same, so use a macro to avoid the repetition.
macro_rules! linked_list_iter {
    ($ptr:expr) => {
        linked_list_iter($ptr, |cur| cur.Next)
    };
}

// Get network interfaces using the IP Helper API
// Reference: https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
pub fn interfaces() -> Vec<Interface> {
    let local_ip: IpAddr = match super::get_local_ipaddr() {
        Some(local_ip) => local_ip,
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    // "The recommended method of calling the GetAdaptersAddresses function is to pre-allocate a 15KB working buffer pointed to by the AdapterAddresses parameter."
    // (c) https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    let mut mem = Vec::<u8>::with_capacity(15000);
    let mut retries = 3;
    loop {
        let mut dwsize = mem.capacity() as u32;
        let ret_val = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_GATEWAYS,
                std::ptr::null_mut(),
                mem.as_mut_ptr().cast(),
                &mut dwsize,
            )
        };
        match ret_val {
            NO_ERROR => {
                unsafe {
                    mem.set_len(dwsize as usize);
                }
                break;
            }
            ERROR_BUFFER_OVERFLOW if retries > 0 => {
                mem.reserve(dwsize as usize);
                retries -= 1;
            }
            _ => {
                // TODO: return errors as a Result someday?
                return vec![];
            }
        }
    }
    // Enumerate all adapters
    let mem = mem.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    unsafe { linked_list_iter!(&mem) }
        .filter_map(|cur| {
            let if_type = InterfaceType::try_from(cur.IfType).ok()?;
            // Index
            let index = {
                let anon1 = cur.Anonymous1;
                let anon = unsafe { &anon1.Anonymous };
                anon.IfIndex
            };
            // Flags and Status
            let mut flags: u32 = 0;
            if cur.OperStatus == NET_IF_OPER_STATUS_UP {
                flags |= sys::IFF_UP;
            }
            match if_type {
                InterfaceType::Ethernet
                | InterfaceType::TokenRing
                | InterfaceType::Wireless80211
                | InterfaceType::HighPerformanceSerialBus => {
                    flags |= sys::IFF_BROADCAST | sys::IFF_MULTICAST;
                }
                InterfaceType::Ppp | InterfaceType::Tunnel => {
                    flags |= sys::IFF_POINTOPOINT | sys::IFF_MULTICAST;
                }
                InterfaceType::Loopback => {
                    flags |= sys::IFF_LOOPBACK | sys::IFF_MULTICAST;
                }
                InterfaceType::Atm => {
                    flags |= sys::IFF_BROADCAST | sys::IFF_POINTOPOINT | sys::IFF_MULTICAST;
                }
                _ => {}
            }
            // Name
            let adapter_name = unsafe { CStr::from_ptr(cur.AdapterName.cast()) }
                .to_string_lossy()
                .into_owned();
            // MAC address
            let mac_addr_arr: [u8; 6] = cur.PhysicalAddress[..6].try_into().unwrap_or_default();
            let mac_addr: MacAddr = MacAddr::from_octets(mac_addr_arr);
            let mut ipv4_vec: Vec<Ipv4Net> = vec![];
            let mut ipv6_vec: Vec<Ipv6Net> = vec![];
            // Enumerate all IPs
            for cur_a in unsafe { linked_list_iter!(&cur.FirstUnicastAddress) } {
                let Some(ip_addr) = (unsafe { socket_address_to_ipaddr(&cur_a.Address) }) else {
                    continue;
                };
                let prefix_len = cur_a.OnLinkPrefixLength;
                match ip_addr {
                    IpAddr::V4(ipv4) => match Ipv4Net::new(ipv4, prefix_len) {
                        Ok(ipv4_net) => ipv4_vec.push(ipv4_net),
                        Err(_) => {}
                    },
                    IpAddr::V6(ipv6) => match Ipv6Net::new(ipv6, prefix_len) {
                        Ok(ipv6_net) => ipv6_vec.push(ipv6_net),
                        Err(_) => {}
                    },
                }
            }
            // Gateway
            let gateway_ips: Vec<IpAddr> = unsafe { linked_list_iter!(&cur.FirstGatewayAddress) }
                .filter_map(|cur_g| unsafe { socket_address_to_ipaddr(&cur_g.Address) })
                .collect();
            let mut default_gateway: NetworkDevice = NetworkDevice::new();
            if flags & sys::IFF_UP != 0 {
                for gateway_ip in gateway_ips {
                    match gateway_ip {
                        IpAddr::V4(ipv4) => {
                            if let Some(ip_net) = ipv4_vec.first() {
                                let mac_addr = get_mac_through_arp(ip_net.addr(), ipv4);
                                default_gateway.mac_addr = mac_addr;
                                default_gateway.ipv4.push(ipv4);
                            }
                        }
                        IpAddr::V6(ipv6) => {
                            if !ipv6_vec.is_empty() {
                                default_gateway.ipv6.push(ipv6);
                            }
                        }
                    }
                }
            }
            // DNS Servers
            let dns_servers: Vec<IpAddr> = unsafe { linked_list_iter!(&cur.FirstDnsServerAddress) }
                .filter_map(|cur_d| unsafe { socket_address_to_ipaddr(&cur_d.Address) })
                .collect();
            let default: bool = match local_ip {
                IpAddr::V4(local_ipv4) => ipv4_vec.iter().any(|x| x.addr() == local_ipv4),
                IpAddr::V6(local_ipv6) => ipv6_vec.iter().any(|x| x.addr() == local_ipv6),
            };
            let interface: Interface = Interface {
                index,
                name: adapter_name,
                friendly_name: Some(unsafe { from_wide_string(cur.FriendlyName) }),
                description: Some(unsafe { from_wide_string(cur.Description) }),
                if_type,
                mac_addr: Some(mac_addr),
                ipv4: ipv4_vec,
                ipv6: ipv6_vec,
                flags,
                transmit_speed: Some(cur.TransmitLinkSpeed),
                receive_speed: Some(cur.ReceiveLinkSpeed),
                gateway: if default_gateway.mac_addr == MacAddr::zero() {
                    None
                } else {
                    Some(default_gateway)
                },
                dns_servers,
                default,
            };
            Some(interface)
        })
        .collect()
}
