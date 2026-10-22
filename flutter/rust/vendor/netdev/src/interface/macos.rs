use crate::interface::InterfaceType;
use std::collections::HashMap;
use system_configuration::network_configuration;

fn get_if_type_from_id(type_id: String) -> InterfaceType {
    match type_id.as_str() {
        "Bridge" => InterfaceType::Bridge,
        "Ethernet" => InterfaceType::Ethernet,
        "IEEE80211" => InterfaceType::Wireless80211,
        "Loopback" => InterfaceType::Loopback,
        "Modem" => InterfaceType::GenericModem,
        "PPP" => InterfaceType::Ppp,
        _ => InterfaceType::Unknown,
    }
}

#[derive(Debug)]
pub struct SCInterface {
    #[allow(dead_code)]
    pub name: String,
    pub friendly_name: Option<String>,
    pub interface_type: InterfaceType,
}

pub fn get_if_type_map() -> HashMap<String, SCInterface> {
    let mut map: HashMap<String, SCInterface> = HashMap::new();
    let interfaces = network_configuration::get_interfaces();
    for interface in &interfaces {
        let if_name: String = if let Some(bsd_name) = interface.bsd_name() {
            bsd_name.to_string()
        } else {
            continue;
        };
        let type_id: String = if let Some(type_string) = interface.interface_type_string() {
            type_string.to_string()
        } else {
            continue;
        };
        let friendly_name: Option<String> = if let Some(name) = interface.display_name() {
            Some(name.to_string())
        } else {
            None
        };
        let sc_if = SCInterface {
            name: if_name.clone(),
            friendly_name: friendly_name,
            interface_type: get_if_type_from_id(type_id),
        };
        map.insert(if_name, sc_if);
    }
    return map;
}
