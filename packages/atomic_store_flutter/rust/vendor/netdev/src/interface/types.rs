use std::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Type of Network Interface
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum InterfaceType {
    /// Unknown interface type
    Unknown,
    /// The network interface using an Ethernet connection
    Ethernet,
    /// The network interface using a Token-Ring connection
    TokenRing,
    /// The network interface using a Fiber Distributed Data Interface (FDDI) connection
    Fddi,
    /// The network interface using a basic rate interface Integrated Services Digital Network (ISDN) connection
    BasicIsdn,
    /// The network interface using a primary rate interface Integrated Services Digital Network (ISDN) connection
    PrimaryIsdn,
    /// The network interface using a Point-To-Point protocol (PPP) connection
    Ppp,
    /// The loopback interface (often used for testing)
    Loopback,
    /// The network interface using an Ethernet 3 megabit/second connection
    Ethernet3Megabit,
    /// The network interface using a Serial Line Internet Protocol (SLIP) connection
    Slip,
    /// The network interface using asynchronous transfer mode (ATM) for data transmission
    Atm,
    /// The network interface using a modem
    GenericModem,
    /// The network interface using a Fast Ethernet connection over twisted pair and provides a data rate of 100 megabits per second (100BASE-T)
    FastEthernetT,
    /// The network interface using a connection configured for ISDN and the X.25 protocol.
    Isdn,
    /// The network interface using a Fast Ethernet connection over optical fiber and provides a data rate of 100 megabits per second (100Base-FX)
    FastEthernetFx,
    /// The network interface using a wireless LAN connection (IEEE 802.11)
    Wireless80211,
    /// The network interface using an Asymmetric Digital Subscriber Line (ADSL)
    AsymmetricDsl,
    /// The network interface using a Rate Adaptive Digital Subscriber Line (RADSL)
    RateAdaptDsl,
    /// The network interface using a Symmetric Digital Subscriber Line (SDSL)
    SymmetricDsl,
    /// The network interface using a Very High Data Rate Digital Subscriber Line (VDSL)
    VeryHighSpeedDsl,
    /// The network interface using the Internet Protocol (IP) in combination with asynchronous transfer mode (ATM) for data transmission
    IPOverAtm,
    /// The network interface using a gigabit Ethernet connection and provides a data rate of 1,000 megabits per second (1 gigabit per second)
    GigabitEthernet,
    /// The network interface using a tunnel connection
    Tunnel,
    /// The network interface using a Multirate Digital Subscriber Line
    MultiRateSymmetricDsl,
    /// The network interface using a High Performance Serial Bus
    HighPerformanceSerialBus,
    /// The network interface using a mobile broadband interface for WiMax devices
    Wman,
    /// The network interface using a mobile broadband interface for GSM-based devices
    Wwanpp,
    /// The network interface using a mobile broadband interface for CDMA-based devices
    Wwanpp2,
    /// Transparent bridge interface
    Bridge,
    /// Controller Area Network
    Can,
}

impl InterfaceType {
    /// Returns OS-specific value of InterfaceType
    #[cfg(target_os = "windows")]
    pub fn value(&self) -> u32 {
        match *self {
            InterfaceType::Unknown => 1,
            InterfaceType::Ethernet => 6,
            InterfaceType::TokenRing => 9,
            InterfaceType::Fddi => 15,
            InterfaceType::BasicIsdn => 20,
            InterfaceType::PrimaryIsdn => 21,
            InterfaceType::Ppp => 23,
            InterfaceType::Loopback => 24,
            InterfaceType::Ethernet3Megabit => 26,
            InterfaceType::Slip => 28,
            InterfaceType::Atm => 37,
            InterfaceType::GenericModem => 48,
            InterfaceType::FastEthernetT => 62,
            InterfaceType::Isdn => 63,
            InterfaceType::FastEthernetFx => 69,
            InterfaceType::Wireless80211 => 71,
            InterfaceType::AsymmetricDsl => 94,
            InterfaceType::RateAdaptDsl => 95,
            InterfaceType::SymmetricDsl => 96,
            InterfaceType::VeryHighSpeedDsl => 97,
            InterfaceType::IPOverAtm => 114,
            InterfaceType::GigabitEthernet => 117,
            InterfaceType::Tunnel => 131,
            InterfaceType::MultiRateSymmetricDsl => 143,
            InterfaceType::HighPerformanceSerialBus => 144,
            InterfaceType::Wman => 237,
            InterfaceType::Wwanpp => 243,
            InterfaceType::Wwanpp2 => 244,
            _ => u32::MAX,
        }
    }
    /// Returns OS-specific value of InterfaceType
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn value(&self) -> u32 {
        use crate::sys;
        match *self {
            InterfaceType::Ethernet => sys::if_arp::ARPHRD_ETHER,
            InterfaceType::TokenRing => sys::if_arp::ARPHRD_IEEE802,
            InterfaceType::Fddi => sys::if_arp::ARPHRD_FDDI,
            InterfaceType::Ppp => sys::if_arp::ARPHRD_PPP,
            InterfaceType::Loopback => sys::if_arp::ARPHRD_LOOPBACK,
            InterfaceType::Ethernet3Megabit => sys::if_arp::ARPHRD_EETHER,
            InterfaceType::Slip => sys::if_arp::ARPHRD_SLIP,
            InterfaceType::Atm => sys::if_arp::ARPHRD_ATM,
            InterfaceType::Wireless80211 => sys::if_arp::ARPHRD_IEEE80211,
            InterfaceType::Tunnel => sys::if_arp::ARPHRD_TUNNEL,
            InterfaceType::Isdn => sys::if_arp::ARPHRD_X25,
            InterfaceType::HighPerformanceSerialBus => sys::if_arp::ARPHRD_IEEE1394,
            InterfaceType::Can => sys::if_arp::ARPHRD_CAN,
            _ => u32::MAX,
        }
    }
    /// Returns OS-specific value of InterfaceType
    #[cfg(any(
        target_os = "macos",
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "ios"
    ))]
    pub fn value(&self) -> u32 {
        match *self {
            InterfaceType::Ethernet => 0x6,
            InterfaceType::TokenRing => 0x9,
            InterfaceType::Fddi => 0xf,
            InterfaceType::Isdn => 0x14,
            InterfaceType::PrimaryIsdn => 0x15,
            InterfaceType::Ppp => 0x17,
            InterfaceType::Loopback => 0x18,
            InterfaceType::Ethernet3Megabit => 0x1a,
            InterfaceType::Slip => 0x1c,
            InterfaceType::Atm => 0x25,
            InterfaceType::GenericModem => 0x30,
            InterfaceType::Wireless80211 => 0x47,
            InterfaceType::AsymmetricDsl => 0x95,
            InterfaceType::RateAdaptDsl => 0x96,
            InterfaceType::SymmetricDsl => 0x97,
            InterfaceType::IPOverAtm => 0x31,
            InterfaceType::HighPerformanceSerialBus => 0x90,
            _ => u32::MAX,
        }
    }
    /// Returns name of InterfaceType
    pub fn name(&self) -> String {
        match *self {
            InterfaceType::Unknown => String::from("Unknown"),
            InterfaceType::Ethernet => String::from("Ethernet"),
            InterfaceType::TokenRing => String::from("Token Ring"),
            InterfaceType::Fddi => String::from("FDDI"),
            InterfaceType::BasicIsdn => String::from("Basic ISDN"),
            InterfaceType::PrimaryIsdn => String::from("Primary ISDN"),
            InterfaceType::Ppp => String::from("PPP"),
            InterfaceType::Loopback => String::from("Loopback"),
            InterfaceType::Ethernet3Megabit => String::from("Ethernet 3 megabit"),
            InterfaceType::Slip => String::from("SLIP"),
            InterfaceType::Atm => String::from("ATM"),
            InterfaceType::GenericModem => String::from("Generic Modem"),
            InterfaceType::FastEthernetT => String::from("Fast Ethernet T"),
            InterfaceType::Isdn => String::from("ISDN"),
            InterfaceType::FastEthernetFx => String::from("Fast Ethernet FX"),
            InterfaceType::Wireless80211 => String::from("Wireless IEEE 802.11"),
            InterfaceType::AsymmetricDsl => String::from("Asymmetric DSL"),
            InterfaceType::RateAdaptDsl => String::from("Rate Adaptive DSL"),
            InterfaceType::SymmetricDsl => String::from("Symmetric DSL"),
            InterfaceType::VeryHighSpeedDsl => String::from("Very High Data Rate DSL"),
            InterfaceType::IPOverAtm => String::from("IP over ATM"),
            InterfaceType::GigabitEthernet => String::from("Gigabit Ethernet"),
            InterfaceType::Tunnel => String::from("Tunnel"),
            InterfaceType::MultiRateSymmetricDsl => String::from("Multi-Rate Symmetric DSL"),
            InterfaceType::HighPerformanceSerialBus => String::from("High Performance Serial Bus"),
            InterfaceType::Bridge => String::from("Bridge"),
            InterfaceType::Wman => String::from("WMAN"),
            InterfaceType::Wwanpp => String::from("WWANPP"),
            InterfaceType::Wwanpp2 => String::from("WWANPP2"),
            InterfaceType::Can => String::from("CAN"),
        }
    }
}

impl TryFrom<u32> for InterfaceType {
    type Error = ();
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == InterfaceType::Unknown.value() => Ok(InterfaceType::Unknown),
            x if x == InterfaceType::Ethernet.value() => Ok(InterfaceType::Ethernet),
            x if x == InterfaceType::TokenRing.value() => Ok(InterfaceType::TokenRing),
            x if x == InterfaceType::Fddi.value() => Ok(InterfaceType::Fddi),
            x if x == InterfaceType::BasicIsdn.value() => Ok(InterfaceType::BasicIsdn),
            x if x == InterfaceType::PrimaryIsdn.value() => Ok(InterfaceType::PrimaryIsdn),
            x if x == InterfaceType::Ppp.value() => Ok(InterfaceType::Ppp),
            x if x == InterfaceType::Loopback.value() => Ok(InterfaceType::Loopback),
            x if x == InterfaceType::Ethernet3Megabit.value() => {
                Ok(InterfaceType::Ethernet3Megabit)
            }
            x if x == InterfaceType::Slip.value() => Ok(InterfaceType::Slip),
            x if x == InterfaceType::Atm.value() => Ok(InterfaceType::Atm),
            x if x == InterfaceType::GenericModem.value() => Ok(InterfaceType::GenericModem),
            x if x == InterfaceType::FastEthernetT.value() => Ok(InterfaceType::FastEthernetT),
            x if x == InterfaceType::Isdn.value() => Ok(InterfaceType::Isdn),
            x if x == InterfaceType::FastEthernetFx.value() => Ok(InterfaceType::FastEthernetFx),
            x if x == InterfaceType::Wireless80211.value() => Ok(InterfaceType::Wireless80211),
            x if x == InterfaceType::AsymmetricDsl.value() => Ok(InterfaceType::AsymmetricDsl),
            x if x == InterfaceType::RateAdaptDsl.value() => Ok(InterfaceType::RateAdaptDsl),
            x if x == InterfaceType::SymmetricDsl.value() => Ok(InterfaceType::SymmetricDsl),
            x if x == InterfaceType::VeryHighSpeedDsl.value() => {
                Ok(InterfaceType::VeryHighSpeedDsl)
            }
            x if x == InterfaceType::IPOverAtm.value() => Ok(InterfaceType::IPOverAtm),
            x if x == InterfaceType::GigabitEthernet.value() => Ok(InterfaceType::GigabitEthernet),
            x if x == InterfaceType::Tunnel.value() => Ok(InterfaceType::Tunnel),
            x if x == InterfaceType::MultiRateSymmetricDsl.value() => {
                Ok(InterfaceType::MultiRateSymmetricDsl)
            }
            x if x == InterfaceType::HighPerformanceSerialBus.value() => {
                Ok(InterfaceType::HighPerformanceSerialBus)
            }
            x if x == InterfaceType::Wman.value() => Ok(InterfaceType::Wman),
            x if x == InterfaceType::Wwanpp.value() => Ok(InterfaceType::Wwanpp),
            x if x == InterfaceType::Wwanpp2.value() => Ok(InterfaceType::Wwanpp2),
            x if x == InterfaceType::Can.value() => Ok(InterfaceType::Can),
            _ => Err(()),
        }
    }
}
