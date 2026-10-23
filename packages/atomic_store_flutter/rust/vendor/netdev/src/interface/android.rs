use once_cell::sync::OnceCell;

pub fn get_libc_ifaddrs() -> Option<(
    unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int,
    unsafe extern "C" fn(*mut libc::ifaddrs),
)> {
    match (get_getifaddrs(), get_freeifaddrs()) {
        (Some(a), Some(b)) => Some((a, b)),
        _ => None,
    }
}

fn load_symbol<T>(sym: &'static str) -> Option<T> {
    const LIB_NAME: &str = "libc.so";

    match dlopen2::raw::Library::open(LIB_NAME) {
        Ok(lib) => match unsafe { lib.symbol::<T>(sym) } {
            Ok(val) => Some(val),
            Err(err) => {
                eprintln!("failed to load symbol {} from {}: {:?}", sym, LIB_NAME, err);
                None
            }
        },
        Err(err) => {
            eprintln!("failed to load {}: {:?}", LIB_NAME, err);
            None
        }
    }
}

fn get_getifaddrs() -> Option<unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int> {
    static INSTANCE: OnceCell<
        Option<unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int>,
    > = OnceCell::new();

    *INSTANCE.get_or_init(|| load_symbol("getifaddrs"))
}

fn get_freeifaddrs() -> Option<unsafe extern "C" fn(*mut libc::ifaddrs)> {
    static INSTANCE: OnceCell<Option<unsafe extern "C" fn(*mut libc::ifaddrs)>> = OnceCell::new();

    *INSTANCE.get_or_init(|| load_symbol("freeifaddrs"))
}

pub mod netlink {
    //! Netlink based getifaddrs.
    //!
    //! Based on the logic found in https://git.musl-libc.org/cgit/musl/tree/src/network/getifaddrs.c

    use netlink_packet_core::{
        NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
    };
    use netlink_packet_route::{
        rtnl::address::nlas::Nla as AddressNla, rtnl::link::nlas::Nla as LinkNla, AddressMessage,
        LinkMessage, RtnlMessage,
    };
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket};
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::interface::{Interface, InterfaceType, Ipv4Net, Ipv6Net};
    use crate::mac::MacAddr;

    pub fn unix_interfaces() -> Vec<Interface> {
        let mut ifaces = Vec::new();
        if let Ok(socket) = Socket::new(NETLINK_ROUTE) {
            if let Err(err) = enumerate_netlink(
                &socket,
                RtnlMessage::GetLink(LinkMessage::default()),
                &mut ifaces,
                handle_new_link,
            ) {
                eprintln!("unable to list interfaces: {:?}", err);
            };
            if let Err(err) = enumerate_netlink(
                &socket,
                RtnlMessage::GetAddress(AddressMessage::default()),
                &mut ifaces,
                handle_new_addr,
            ) {
                eprintln!("unable to list addresses: {:?}", err);
            }
        }
        ifaces
    }

    fn handle_new_link(ifaces: &mut Vec<Interface>, msg: RtnlMessage) -> io::Result<()> {
        match msg {
            RtnlMessage::NewLink(link_msg) => {
                let mut interface: Interface = Interface {
                    index: link_msg.header.index,
                    name: String::new(),
                    friendly_name: None,
                    description: None,
                    if_type: InterfaceType::try_from(link_msg.header.link_layer_type as u32)
                        .unwrap_or(InterfaceType::Unknown),
                    mac_addr: None,
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    flags: link_msg.header.flags,
                    transmit_speed: None,
                    receive_speed: None,
                    gateway: None,
                    dns_servers: Vec::new(),
                    default: false,
                };

                for nla in link_msg.nlas {
                    match nla {
                        LinkNla::IfName(name) => {
                            interface.name = name;
                        }
                        LinkNla::Address(addr) => {
                            match addr.len() {
                                6 => {
                                    interface.mac_addr =
                                        Some(MacAddr::from_octets(addr.try_into().unwrap()));
                                }
                                4 => {
                                    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(addr).unwrap());
                                    match Ipv4Net::with_netmask(ip, Ipv4Addr::UNSPECIFIED) {
                                        Ok(ipv4) => interface.ipv4.push(ipv4),
                                        Err(_) => {}
                                    }
                                }
                                _ => {
                                    // unclear what these would be
                                }
                            }
                        }
                        _ => {}
                    }
                }
                ifaces.push(interface);
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_new_addr(ifaces: &mut Vec<Interface>, msg: RtnlMessage) -> io::Result<()> {
        match msg {
            RtnlMessage::NewAddress(addr_msg) => {
                if let Some(interface) =
                    ifaces.iter_mut().find(|i| i.index == addr_msg.header.index)
                {
                    for nla in addr_msg.nlas {
                        match nla {
                            AddressNla::Address(addr) => match addr.len() {
                                4 => {
                                    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(addr).unwrap());
                                    match Ipv4Net::new(ip, addr_msg.header.prefix_len) {
                                        Ok(ipv4) => interface.ipv4.push(ipv4),
                                        Err(_) => {}
                                    }
                                }
                                16 => {
                                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(addr).unwrap());
                                    match Ipv6Net::new(ip, addr_msg.header.prefix_len) {
                                        Ok(ipv6) => interface.ipv6.push(ipv6),
                                        Err(_) => {}
                                    }
                                }
                                _ => {
                                    // what else?
                                }
                            },
                            _ => {}
                        }
                    }
                } else {
                    eprintln!(
                        "found unknown interface with index: {}",
                        addr_msg.header.index
                    );
                }
            }
            _ => {}
        }

        Ok(())
    }

    struct NetlinkIter<'a> {
        socket: &'a Socket,
        /// Buffer for received data.
        buf: Vec<u8>,
        /// Size of the data available in `buf`.
        size: usize,
        /// Offset into the data currently in `buf`.
        offset: usize,
        /// Are we don iterating?
        done: bool,
    }

    impl<'a> NetlinkIter<'a> {
        fn new(socket: &'a Socket, msg: RtnlMessage) -> io::Result<Self> {
            let mut packet =
                NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::from(msg));
            packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
            packet.header.sequence_number = 1;
            packet.finalize();

            let mut buf = vec![0; packet.header.length as usize];
            if buf.len() != packet.buffer_len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Buffer length mismatch in netlink packet",
                ));
            }
            packet.serialize(&mut buf[..]);
            socket.send(&buf[..], 0)?;

            Ok(NetlinkIter {
                socket,
                offset: 0,
                size: 0,
                buf: vec![0u8; 4096],
                done: false,
            })
        }
    }

    impl<'a> Iterator for NetlinkIter<'a> {
        type Item = io::Result<RtnlMessage>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.done {
                return None;
            }

            while !self.done {
                // Outer loop
                if self.size == 0 {
                    match self.socket.recv(&mut &mut self.buf[..], 0) {
                        Ok(size) => {
                            self.size = size;
                            self.offset = 0;
                        }
                        Err(err) => {
                            self.done = true;
                            return Some(Err(err));
                        }
                    }
                }

                let bytes = &self.buf[self.offset..];
                match NetlinkMessage::<RtnlMessage>::deserialize(bytes) {
                    Ok(packet) => {
                        self.offset += packet.header.length as usize;
                        if packet.header.length == 0 || self.offset == self.size {
                            // mark this message as fully read
                            self.size = 0;
                        }
                        match packet.payload {
                            NetlinkPayload::Done(_) => {
                                self.done = true;
                                return None;
                            }
                            NetlinkPayload::Error(err) => {
                                self.done = true;
                                return Some(Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    err.to_string(),
                                )));
                            }
                            NetlinkPayload::InnerMessage(msg) => return Some(Ok(msg)),
                            _ => {
                                continue;
                            }
                        }
                    }
                    Err(err) => {
                        self.done = true;
                        return Some(Err(io::Error::new(io::ErrorKind::Other, err.to_string())));
                    }
                }
            }

            None
        }
    }

    fn enumerate_netlink<F>(
        socket: &Socket,
        msg: RtnlMessage,
        ifaces: &mut Vec<Interface>,
        cb: F,
    ) -> io::Result<()>
    where
        F: Fn(&mut Vec<Interface>, RtnlMessage) -> io::Result<()>,
    {
        let iter = NetlinkIter::new(socket, msg)?;
        for msg in iter {
            let msg = msg?;
            cb(ifaces, msg)?;
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_netlink_ifaddrs() {
            let interfaces = unix_interfaces();
            dbg!(&interfaces);
            assert!(!interfaces.is_empty());
        }
    }
}
