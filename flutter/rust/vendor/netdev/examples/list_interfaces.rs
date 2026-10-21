// This example shows all interfaces and their properties.

fn main() {
    let interfaces = netdev::get_interfaces();
    for interface in interfaces {
        println!("Interface:");
        println!("\tIndex: {}", interface.index);
        println!("\tName: {}", interface.name);
        println!("\tFriendly Name: {:?}", interface.friendly_name);
        println!("\tDescription: {:?}", interface.description);
        println!("\tType: {}", interface.if_type.name());
        println!("\tFlags: {:?}", interface.flags);
        println!("\t\tis UP {}", interface.is_up());
        println!("\t\tis LOOPBACK {}", interface.is_loopback());
        println!("\t\tis MULTICAST {}", interface.is_multicast());
        println!("\t\tis BROADCAST {}", interface.is_broadcast());
        println!("\t\tis POINT TO POINT {}", interface.is_point_to_point());
        println!("\t\tis TUN {}", interface.is_tun());
        println!("\t\tis RUNNING {}", interface.is_running());
        println!("\t\tis PHYSICAL {}", interface.is_physical());
        if let Some(mac_addr) = interface.mac_addr {
            println!("\tMAC Address: {}", mac_addr);
        } else {
            println!("\tMAC Address: (Failed to get mac address)");
        }
        println!("\tIPv4: {:?}", interface.ipv4);
        println!("\tIPv6: {:?}", interface.ipv6);
        println!("\tTransmit Speed: {:?}", interface.transmit_speed);
        println!("\tReceive Speed: {:?}", interface.receive_speed);
        if let Some(gateway) = interface.gateway {
            println!("Gateway");
            println!("\tMAC Address: {}", gateway.mac_addr);
            println!("\tIPv4 Address: {:?}", gateway.ipv4);
            println!("\tIPv6 Address: {:?}", gateway.ipv6);
        } else {
            println!("Gateway: (Not found)");
        }
        println!("DNS Servers: {:?}", interface.dns_servers);
        println!("Default: {}", interface.default);
        println!();
    }
}
