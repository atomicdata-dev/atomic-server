// Send a request to the OpenProvder API to update the IP address

use std::io::prelude::*;
use std::net::TcpStream;
use std::str;

use reqwest;
use serde_json;

use crate::config::Config;

pub fn update_ip(config: &Config) -> Result<(), String> {
    // Get the current IP address
    let ip = get_ip()?;

    // Get the current DNS records
    let records = get_records(config)?;

    // Check if there is a record for this domain
    let record = records
        .iter()
        .find(|x| x.name == config.domain && x.ttl == config.ttl);

    if let Some(record) = record {
        // Check if the IP address is the same as the current IP
        if record.content == ip {
            println!("IP address is already up to date");
            return Ok(());
        }

        // Update the record
        update_record(config, &record, &ip)?;
    } else {
        // Create a new record
        create_record(config, &ip)?;
    }

    println!("IP address updated successfully");

    Ok(())
}

fn get_ip() -> Result<String, String> {
    let client = reqwest::Client::new();
    let res = client
        .get("https://api.ipify.org")
        .send()
        .map_err(|e| e.to_string())?;
    let ip = res
        .text()
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();

    Ok(ip)
}

fn get_records(config: &Config) -> Result<Vec<Record>, String> {
    let client = reqwest::Client::new();
    let res = client
        .get(&format!(
            "https://api.openprovider.eu/v1beta/dns/records?domain={}",
            config.domain
        ))
        .basic_auth(&config.username, Some(&config.password))
        .send()
        .map_err(|e| e.to_string())?;
    let records: Vec<Record> = res
        .json()
        .map_err(|e| e.to_string())?;
