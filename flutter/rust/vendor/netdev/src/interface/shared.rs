use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// Retrieve the IP address of the default network interface.
///
/// This function attempts to bind a UDP socket to an unspecified IP address (0.0.0.0)
/// and port (0), which allows the system to select an appropriate IP address and port.
/// After binding, it attempts to connect the socket to a designated non-routable IP address
/// (`10.254.254.254` on port 1). This is a trick commonly used to prompt the OS to
/// populate the socket's local address with the IP address of the interface that would
/// route to the specified address.
///
/// The function returns the local IP address if these operations succeed.
/// If any operation fails (binding, connecting, or retrieving the address),
/// the function returns `None`, indicating the inability to determine the local IP.
///
/// Returns:
/// - `Some(IpAddr)`: IP address of the default network interface if successful.
/// - `None`: If any error occurs during the operations.
pub fn get_local_ipaddr() -> Option<IpAddr> {
    // Attempt to bind a UDP socket to an unspecified address and port.
    let socket = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
        Ok(s) => s,
        Err(_) => return None,
    };
    // Attempt to connect the socket to a specific non-routable IP address.
    // This does not send actual data but is used to determine the routing interface.
    match socket.connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 254, 254, 254)),
        1,
    )) {
        Ok(()) => (),
        Err(_) => return None,
    };
    // Retrieve and return the local IP address from the socket.
    match socket.local_addr() {
        Ok(addr) => return Some(addr.ip()),
        Err(_) => return None,
    };
}
