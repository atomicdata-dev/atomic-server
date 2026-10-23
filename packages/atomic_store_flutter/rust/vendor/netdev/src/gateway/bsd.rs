#![allow(non_camel_case_types)]

use crate::device::NetworkDevice;
use crate::mac::MacAddr;

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const CTL_NET: u32 = 4;
const AF_INET: u32 = 2;
const AF_ROUTE: u32 = 17;
const AF_LINK: u32 = 18;
const AF_INET6: u32 = 30;
const PF_ROUTE: u32 = 17;
const NET_RT_DUMP: u32 = 1;
const NET_RT_FLAGS: u32 = 2;

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
const RTM_VERSION: u32 = 5;
#[cfg(target_os = "netbsd")]
const RTM_VERSION: u32 = 4;

const RTF_LLINFO: u32 = 1024;
const RTF_WASCLONED: u32 = 0x20000;
const RTAX_DST: u32 = 0;
const RTAX_GATEWAY: u32 = 1;
const RTAX_NETMASK: u32 = 2;

#[cfg(target_os = "freebsd")]
const RTAX_MAX: u32 = 8;
#[cfg(target_os = "netbsd")]
const RTAX_MAX: u32 = 9;
#[cfg(target_os = "openbsd")]
const RTAX_MAX: u32 = 15;

type __int32_t = ::std::os::raw::c_int;
type __uint8_t = ::std::os::raw::c_uchar;
type __uint16_t = ::std::os::raw::c_ushort;
type __uint32_t = ::std::os::raw::c_uint;
type sa_family_t = __uint8_t;
type in_addr_t = __uint32_t;
type in_port_t = __uint16_t;
type u_int = ::std::os::raw::c_uint;
type u_short = ::std::os::raw::c_ushort;
type u_char = ::std::os::raw::c_uchar;
type u_int32_t = ::std::os::raw::c_uint;
type size_t = usize;
type pid_t = __int32_t;

extern "C" {
    fn sysctl(
        arg1: *mut ::std::os::raw::c_int,
        arg2: u_int,
        arg3: *mut ::std::os::raw::c_void,
        arg4: *mut size_t,
        arg5: *mut ::std::os::raw::c_void,
        arg6: size_t,
    ) -> ::std::os::raw::c_int;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct rt_msghdr {
    pub rtm_msglen: u_short,
    pub rtm_version: u_char,
    pub rtm_type: u_char,
    pub rtm_index: u_short,
    pub rtm_flags: ::std::os::raw::c_int,
    pub rtm_addrs: ::std::os::raw::c_int,
    pub rtm_pid: pid_t,
    pub rtm_seq: ::std::os::raw::c_int,
    pub rtm_errno: ::std::os::raw::c_int,
    pub rtm_use: ::std::os::raw::c_int,
    pub rtm_inits: u_int32_t,
    pub rtm_rmx: rt_metrics,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct rt_metrics {
    pub rmx_locks: u_int32_t,
    pub rmx_mtu: u_int32_t,
    pub rmx_hopcount: u_int32_t,
    pub rmx_expire: i32,
    pub rmx_recvpipe: u_int32_t,
    pub rmx_sendpipe: u_int32_t,
    pub rmx_ssthresh: u_int32_t,
    pub rmx_rtt: u_int32_t,
    pub rmx_rttvar: u_int32_t,
    pub rmx_pksent: u_int32_t,
    pub rmx_weight: u_int32_t,
    pub rmx_nhidx: u_int32_t,
    pub rmx_filler: [u_int32_t; 2],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct sockaddr {
    pub sa_len: __uint8_t,
    pub sa_family: sa_family_t,
    pub sa_data: [::std::os::raw::c_char; 14usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
union in6_addr_bind {
    pub __u6_addr8: [__uint8_t; 16usize],
    pub __u6_addr16: [__uint16_t; 8usize],
    pub __u6_addr32: [__uint32_t; 4usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct in6_addr {
    pub __u6_addr: in6_addr_bind,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct sockaddr_in {
    pub sin_len: __uint8_t,
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [::std::os::raw::c_char; 8usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct sockaddr_in6 {
    pub sin6_len: __uint8_t,
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: __uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: __uint32_t,
}

fn code_to_error(err: i32) -> io::Error {
    let kind = match err {
        17 => io::ErrorKind::AlreadyExists, // EEXIST
        3 => io::ErrorKind::NotFound,       // ESRCH
        3436 => io::ErrorKind::OutOfMemory, // ENOBUFS
        _ => io::ErrorKind::Other,
    };

    io::Error::new(kind, format!("rtm_errno {}", err))
}

fn socketaddr_to_ipaddr(sa: &sockaddr) -> Option<IpAddr> {
    match sa.sa_family as u32 {
        AF_INET => {
            let inet: &sockaddr_in = unsafe { std::mem::transmute(sa) };
            let octets: [u8; 4] = inet.sin_addr.s_addr.to_ne_bytes();
            Some(IpAddr::from(octets))
        }
        AF_INET6 => {
            let inet6: &sockaddr_in6 = unsafe { std::mem::transmute(sa) };
            let octets: [u8; 16] = unsafe { inet6.sin6_addr.__u6_addr.__u6_addr8 };
            Some(IpAddr::from(octets))
        }
        AF_LINK => None,
        _ => None,
    }
}

fn message_to_route(hdr: &rt_msghdr, msg: &[u8]) -> Option<Route> {
    const MSG_START_INDEX: usize = 60;
    let mut gateway = None;
    if hdr.rtm_addrs & (1 << RTAX_DST) == 0 {
        return None;
    }
    let mut route_addresses = [None; RTAX_MAX as usize];
    let mut cur_pos = MSG_START_INDEX;
    for idx in 0..RTAX_MAX as usize {
        if hdr.rtm_addrs & (1 << idx) != 0 {
            let buf = &msg[cur_pos..];
            let sa: &sockaddr = unsafe { &*(buf.as_ptr() as *const sockaddr) };
            route_addresses[idx] = Some(sa);
            let aligned_len = if sa.sa_len == 0 {
                4
            } else {
                ((sa.sa_len - 1) | 0x3) + 1
            };
            cur_pos += aligned_len as usize;
        }
    }
    let sa = match route_addresses[RTAX_DST as usize] {
        Some(sa) => sa,
        None => return None,
    };
    let destination = socketaddr_to_ipaddr(sa)?;

    let mut prefix = match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if hdr.rtm_addrs & (1 << RTAX_GATEWAY) != 0 {
        let gw_sa = match route_addresses[RTAX_GATEWAY as usize] {
            Some(sa) => sa,
            None => return None,
        };
        gateway = socketaddr_to_ipaddr(gw_sa);
        if let Some(IpAddr::V6(ipv6gw)) = gateway {
            let is_unicast_ll = ipv6gw.segments()[0] == 0xfe80;
            let is_multicast = ipv6gw.octets()[0] == 0xff;
            let multicast_scope = ipv6gw.octets()[1] & 0x0f;
            if is_unicast_ll || (is_multicast && (multicast_scope == 1 || multicast_scope == 2)) {
                let segs = ipv6gw.segments();
                gateway = Some(IpAddr::V6(Ipv6Addr::new(
                    segs[0], 0, segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
                )))
            }
        }
    }

    if hdr.rtm_addrs & (1 << RTAX_NETMASK) != 0 {
        let sa = route_addresses[RTAX_NETMASK as usize].unwrap();
        if sa.sa_len == 0 {
            prefix = 0;
        } else {
            match destination {
                IpAddr::V4(_) => {
                    let mask_sa: &sockaddr_in = unsafe { std::mem::transmute(sa) };
                    prefix = u32::from_be(mask_sa.sin_addr.s_addr).leading_ones() as u8;
                }
                IpAddr::V6(_) => {
                    let mask_sa: &sockaddr_in6 = unsafe { std::mem::transmute(sa) };
                    prefix = u128::from_be_bytes(unsafe { mask_sa.sin6_addr.__u6_addr.__u6_addr8 })
                        .leading_ones() as u8;
                }
            }
        }
    }

    Some(Route {
        destination,
        prefix,
        gateway,
        ifindex: Some(hdr.rtm_index as u32),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub ifindex: Option<u32>,
}

fn list_routes() -> io::Result<Vec<Route>> {
    let mut mib: [u32; 7] = [0; 7];
    let mut len = 0;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_DUMP;
    mib[5] = 0;
    mib[6] = 0;

    if unsafe {
        sysctl(
            &mut mib as *mut _ as *mut _,
            7,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut msgs_buf: Vec<u8> = vec![0; len as usize];

    if unsafe {
        sysctl(
            &mut mib as *mut _ as *mut _,
            7,
            msgs_buf.as_mut_ptr() as _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut routes = vec![];
    let mut offset = 0;

    while offset + std::mem::size_of::<rt_msghdr>() <= len as usize {
        let buf = &mut msgs_buf[offset..];

        if buf.len() < std::mem::size_of::<rt_msghdr>() {
            break;
        }

        let rt_hdr = unsafe { std::mem::transmute::<_, &rt_msghdr>(buf.as_ptr()) };
        if rt_hdr.rtm_version as u32 != RTM_VERSION {
            eprintln!(
                "unexpected RTM_VERSION: {} in {:?}",
                rt_hdr.rtm_version, rt_hdr
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected RTM_VERSION: {}", rt_hdr.rtm_version),
            ));
        }

        if rt_hdr.rtm_errno != 0 {
            return Err(code_to_error(rt_hdr.rtm_errno));
        }

        let msg_len = rt_hdr.rtm_msglen as usize;
        offset += msg_len;

        if rt_hdr.rtm_flags as u32 & RTF_WASCLONED != 0 {
            continue;
        }
        let rt_msg = &mut buf[std::mem::size_of::<rt_msghdr>()..msg_len];

        if let Some(route) = message_to_route(rt_hdr, rt_msg) {
            routes.push(route);
        }
    }

    Ok(routes)
}

fn message_to_arppair(msg_bytes: *mut u8) -> (IpAddr, MacAddr) {
    const IP_START_INDEX: usize = 64;
    const IP_END_INDEX: usize = 67;
    const MAC_START_INDEX: usize = 84;
    const MAC_END_INDEX: usize = 89;
    let ip_bytes = unsafe {
        std::slice::from_raw_parts(
            msg_bytes.add(IP_START_INDEX),
            IP_END_INDEX + 1 - IP_START_INDEX,
        )
    };
    let mac_bytes = unsafe {
        std::slice::from_raw_parts(
            msg_bytes.add(MAC_START_INDEX),
            MAC_END_INDEX + 1 - MAC_START_INDEX,
        )
    };
    let ip_addr = IpAddr::V4(Ipv4Addr::new(
        ip_bytes[0],
        ip_bytes[1],
        ip_bytes[2],
        ip_bytes[3],
    ));
    let mac_addr = MacAddr::from_octets([
        mac_bytes[0],
        mac_bytes[1],
        mac_bytes[2],
        mac_bytes[3],
        mac_bytes[4],
        mac_bytes[5],
    ]);
    (ip_addr, mac_addr)
}

fn get_arp_table() -> io::Result<HashMap<IpAddr, MacAddr>> {
    let mut arp_map: HashMap<IpAddr, MacAddr> = HashMap::new();
    let mut mib: [u32; 6] = [CTL_NET, AF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO];
    let mut len: libc::size_t = 0;

    unsafe {
        if sysctl(
            &mut mib as *mut _ as *mut _,
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut buf: Vec<u8> = vec![0; len as usize];
        if sysctl(
            &mut mib as *mut _ as *mut _,
            mib.len() as u32,
            buf.as_mut_ptr() as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut offset = 0;
        while offset < len as usize {
            let rt_hdr = &*(buf.as_ptr().add(offset) as *const rt_msghdr);
            if rt_hdr.rtm_version as u32 != RTM_VERSION {
                eprintln!(
                    "Unexpected RTM_VERSION: {} in {:?}",
                    rt_hdr.rtm_version, rt_hdr
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unexpected RTM_VERSION: {}", rt_hdr.rtm_version),
                ));
            }

            let msg_len = rt_hdr.rtm_msglen as usize;
            offset += msg_len;

            let rt_msg: &mut [u8] = &mut buf[std::mem::size_of::<rt_msghdr>()..msg_len];
            let (ip, mac) = message_to_arppair(rt_msg.as_mut_ptr());
            arp_map.insert(ip, mac);
        }
    }

    Ok(arp_map)
}

fn get_default_routes() -> Vec<Route> {
    let mut default_routes = Vec::new();
    match list_routes() {
        Ok(routes) => {
            for route in routes {
                if (route.destination == Ipv4Addr::UNSPECIFIED
                    || route.destination == Ipv6Addr::UNSPECIFIED)
                    && route.prefix == 0
                    && route.gateway != Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                    && route.gateway != Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                {
                    default_routes.push(route);
                }
            }
        }
        Err(_) => {}
    }
    default_routes
}

pub fn get_gateway_map() -> HashMap<u32, NetworkDevice> {
    let mut gateway_map: HashMap<u32, NetworkDevice> = HashMap::new();
    let routes = get_default_routes();
    let arp_map = get_arp_table().unwrap_or(HashMap::new());
    for route in routes {
        if let Some(gw_ip) = route.gateway {
            let gateway = gateway_map
                .entry(route.ifindex.unwrap_or(0))
                .or_insert(NetworkDevice::new());
            if let Some(mac_addr) = arp_map.get(&gw_ip) {
                gateway.mac_addr = mac_addr.clone();
            }
            match gw_ip {
                IpAddr::V4(ipv4) => {
                    gateway.ipv4.push(ipv4);
                }
                IpAddr::V6(ipv6) => {
                    gateway.ipv6.push(ipv6);
                }
            }
        }
    }
    gateway_map
}
