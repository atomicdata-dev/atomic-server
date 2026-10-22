use windows_sys::Win32::Networking::WinSock as ws;

pub const IFF_UP: u32 = ws::IFF_UP;
pub const IFF_BROADCAST: u32 = ws::IFF_BROADCAST;
pub const IFF_LOOPBACK: u32 = ws::IFF_LOOPBACK;
pub const IFF_POINTOPOINT: u32 = ws::IFF_POINTTOPOINT;
pub const IFF_MULTICAST: u32 = ws::IFF_MULTICAST;
