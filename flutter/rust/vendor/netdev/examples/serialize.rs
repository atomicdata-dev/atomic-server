// This example shows how to use serde feature to serialize the default network interface to JSON.
fn main() {
    match netdev::get_default_interface() {
        Ok(interface) => match serde_json::to_string_pretty(&interface) {
            Ok(json) => {
                println!("{}", json);
            }
            Err(e) => {
                println!("Serialization Error: {}", e);
            }
        },
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
