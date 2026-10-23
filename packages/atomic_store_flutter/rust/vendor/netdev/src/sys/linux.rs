// ARP protocol HARDWARE identifiers
pub mod if_arp {
    pub const ARPHRD_ETHER: u32 = libc::ARPHRD_ETHER as u32;
    pub const ARPHRD_IEEE802: u32 = libc::ARPHRD_IEEE802 as u32;
    pub const ARPHRD_FDDI: u32 = libc::ARPHRD_FDDI as u32;
    pub const ARPHRD_PPP: u32 = libc::ARPHRD_PPP as u32;
    pub const ARPHRD_LOOPBACK: u32 = libc::ARPHRD_LOOPBACK as u32;
    pub const ARPHRD_EETHER: u32 = libc::ARPHRD_EETHER as u32;
    pub const ARPHRD_SLIP: u32 = libc::ARPHRD_SLIP as u32;
    pub const ARPHRD_ATM: u32 = libc::ARPHRD_ATM as u32;
    pub const ARPHRD_IEEE80211: u32 = libc::ARPHRD_IEEE80211 as u32;
    pub const ARPHRD_TUNNEL: u32 = libc::ARPHRD_TUNNEL as u32;
    pub const ARPHRD_X25: u32 = libc::ARPHRD_X25 as u32;
    pub const ARPHRD_IEEE1394: u32 = libc::ARPHRD_IEEE1394 as u32;
    pub const ARPHRD_CAN: u32 = libc::ARPHRD_CAN as u32;
}

pub use libc::IFF_LOWER_UP;
