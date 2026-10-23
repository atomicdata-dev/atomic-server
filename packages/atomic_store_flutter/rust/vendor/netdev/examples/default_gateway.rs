// This example shows how to get the default gateway and its properties.

fn main() {
    match netdev::get_default_gateway() {
        Ok(gateway) => {
            println!("Default Gateway");
            println!("\tMAC Address: {}", gateway.mac_addr);
            println!("\tIPv4: {:?}", gateway.ipv4);
            println!("\tIPv6: {:?}", gateway.ipv6);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
