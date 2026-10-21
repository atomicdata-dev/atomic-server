Vendored from crates.io netdev 0.31.0 (MIT), checksum f901362e84cd407be6f8cd9d3a46bccf09136b095792785401ea7d283c79b91d.

The only source change gates SystemConfiguration interface metadata to macOS. Apple marks SCNetworkInterfaceCopyAll, SCNetworkInterfaceGetBSDName, SCNetworkInterfaceGetInterfaceType and SCNetworkInterfaceGetLocalizedDisplayName unavailable on iOS. The existing Unix getifaddrs interface enumeration, addresses, flags and gateway handling remain active on iOS. macOS and other platforms are unchanged.

Remove this patch when the Iroh/netwatch dependency chain adopts a netdev release with native iOS support.
