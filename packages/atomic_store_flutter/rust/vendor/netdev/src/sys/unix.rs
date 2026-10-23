use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub type SockAddrIn = libc::sockaddr_in;
pub type SockAddrIn6 = libc::sockaddr_in6;
pub type SockAddrStorage = libc::sockaddr_storage;
pub type InAddr = libc::in_addr;

pub const AF_INET: libc::c_int = libc::AF_INET;
pub const AF_INET6: libc::c_int = libc::AF_INET6;

pub use libc::{IFF_BROADCAST, IFF_LOOPBACK, IFF_MULTICAST, IFF_POINTOPOINT, IFF_RUNNING, IFF_UP};

fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

pub fn sockaddr_to_addr(storage: &SockAddrStorage, len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        AF_INET => {
            assert!(len as usize >= mem::size_of::<SockAddrIn>());
            let storage: &SockAddrIn = unsafe { mem::transmute(storage) };
            let ip = ipv4_addr_int(storage.sin_addr);
            // octets
            let o1 = (ip >> 24) as u8;
            let o2 = (ip >> 16) as u8;
            let o3 = (ip >> 8) as u8;
            let o4 = ip as u8;
            let sockaddrv4 =
                SocketAddrV4::new(Ipv4Addr::new(o1, o2, o3, o4), ntohs(storage.sin_port));
            Ok(SocketAddr::V4(sockaddrv4))
        }
        AF_INET6 => {
            assert!(len as usize >= mem::size_of::<SockAddrIn6>());
            let storage: &SockAddrIn6 = unsafe { mem::transmute(storage) };
            let arr: [u16; 8] = unsafe { mem::transmute(storage.sin6_addr.s6_addr) };
            // hextets
            let h1 = ntohs(arr[0]);
            let h2 = ntohs(arr[1]);
            let h3 = ntohs(arr[2]);
            let h4 = ntohs(arr[3]);
            let h5 = ntohs(arr[4]);
            let h6 = ntohs(arr[5]);
            let h7 = ntohs(arr[6]);
            let h8 = ntohs(arr[7]);
            let ip = Ipv6Addr::new(h1, h2, h3, h4, h5, h6, h7, h8);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                ntohs(storage.sin6_port),
                u32::from_be(storage.sin6_flowinfo),
                storage.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Not supported")),
    }
}

#[inline(always)]
pub fn ipv4_addr_int(addr: InAddr) -> u32 {
    (addr.s_addr as u32).to_be()
}
