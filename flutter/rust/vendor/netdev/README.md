[crates-badge]: https://img.shields.io/crates/v/netdev.svg
[crates-url]: https://crates.io/crates/netdev
[license-badge]: https://img.shields.io/crates/l/netdev.svg
[examples-url]: https://github.com/shellrow/netdev/tree/main/examples
[doc-url]: https://docs.rs/netdev/latest/netdev
[doc-interface-url]: https://docs.rs/netdev/latest/netdev/interface/struct.Interface.html
[netdev-github-url]: https://github.com/shellrow/netdev
[default-net-github-url]: https://github.com/shellrow/default-net
[default-net-crates-io-url]: https://crates.io/crates/default-net

# netdev [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
  
`netdev` provides a cross-platform API for network interface.

## Key Features
- Get list of available network interfaces
- Get default network interface
- Access additional information related to network interface

Please refer to the [Interface][doc-interface-url] struct documentation for detail.

## Notice
This project was rebranded from [default-net][default-net-crates-io-url] by the author myself for future expansion, continuation, and better alignment with naming conventions.

## Supported platform
- Linux
- macOS
- Windows

## Usage
Add `netdev` to your dependencies  
```toml:Cargo.toml
[dependencies]
netdev = "0.31"
```

For more details, see [examples][examples-url] or [doc][doc-url].  

## Tested on
- Linux
    - Ubuntu 
        - 24.04
        - 22.04
        - 21.10 
        - 20.04 
        - 18.04
    - Kali 
        - 2024.2
        - 2023.2
        - 2022.1
        - 2021.1
    - Arch 
        - 2024.05.01
- macOS (Apple Silicon)
    - 14.5
- macOS (Intel)
    - 13.4.1
    - 11.6
- Windows 
    - 11 23H2 22631.3593
    - 11 Pro 22H2 22621.3155
    - 11 22H2 22621.3155
    - 10 21H2 19044.1586
- FreeBSD
    - 14
