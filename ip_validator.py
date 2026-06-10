#!/usr/bin/env python3
"""
IP Address Validator
Validates both IPv4 and IPv6 addresses
"""

import re
import ipaddress


def validate_ip_basic(ip_string):
    """
    Validate IP address using Python's ipaddress module (recommended method)
    
    Args:
        ip_string (str): IP address to validate
        
    Returns:
        tuple: (is_valid, ip_type, ip_object)
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return (True, "IPv4", ip_obj)
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return (True, "IPv6", ip_obj)
    except ValueError:
        return (False, None, None)


def get_default_prefix(ip_obj):
    """
    Return the default host prefix when no CIDR is provided.
    IPv4 defaults to /32 and IPv6 defaults to /128.
    """
    return 32 if isinstance(ip_obj, ipaddress.IPv4Address) else 128


def get_ipv4_class(ip_obj):
    """
    Return the classful IPv4 subnet class based on the first octet.
    """
    first_octet = int(str(ip_obj).split('.')[0])

    if 1 <= first_octet <= 126:
        return "Class A"
    if first_octet == 127:
        return "Class A (Loopback)"
    if 128 <= first_octet <= 191:
        return "Class B"
    if 192 <= first_octet <= 223:
        return "Class C"
    if 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    return "Class E (Experimental)"


def parse_network_input(ip_string):
    """
    Parse an IP address with optional CIDR notation.
    
    If no CIDR is provided, default to /32 for IPv4 and /128 for IPv6.
    
    Returns:
        tuple: (is_valid, ip_type, ip_obj, network_obj)
    """
    candidate = ip_string.strip()

    try:
        if '/' in candidate:
            network_obj = ipaddress.ip_network(candidate, strict=False)
            ip_obj = ipaddress.ip_address(candidate.split('/')[0])
        else:
            ip_obj = ipaddress.ip_address(candidate)
            network_obj = ipaddress.ip_network(
                f"{ip_obj}/{get_default_prefix(ip_obj)}",
                strict=False
            )

        ip_type = "IPv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "IPv6"
        return (True, ip_type, ip_obj, network_obj)
    except ValueError:
        return (False, None, None, None)


def validate_ipv4_regex(ip_string):
    """
    Validate IPv4 address using regex pattern
    
    Args:
        ip_string (str): IP address to validate
        
    Returns:
        bool: True if valid IPv4, False otherwise
    """
    # Pattern for IPv4: 0-255.0-255.0-255.0-255
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip_string))


def validate_ipv4_manual(ip_string):
    """
    Validate IPv4 address manually without regex
    
    Args:
        ip_string (str): IP address to validate
        
    Returns:
        bool: True if valid IPv4, False otherwise
    """
    parts = ip_string.split('.')
    
    # Must have exactly 4 parts
    if len(parts) != 4:
        return False
    
    # Each part must be a number between 0 and 255
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
            # Check for leading zeros (e.g., "192.168.01.1" is invalid)
            if len(part) > 1 and part[0] == '0':
                return False
        except ValueError:
            return False
    
    return True

def ipv4_to_ipv6_mapped(ipv4_obj):
    """
    Convert an IPv4 address to its IPv6-mapped equivalent.
    IPv4-mapped IPv6 addresses use the format ::ffff:x.x.x.x
    
    Args:
        ipv4_obj: IPv4Address object
        
    Returns:
        str: IPv6-mapped address
    """
    # Convert IPv4 to IPv6-mapped format (::ffff:x.x.x.x)
    ipv6_mapped = ipaddress.IPv6Address('::ffff:' + str(ipv4_obj))
    return str(ipv6_mapped)


def ipv4_to_ipv6_6to4(ipv4_obj):
    """
    Convert an IPv4 address to 6to4 IPv6 address format.
    6to4 uses the format 2002:xxxx:xxxx::/48 where xxxx:xxxx is the hex of the IPv4.
    
    Args:
        ipv4_obj: IPv4Address object
        
    Returns:
        str: 6to4 IPv6 address
    """
    # Convert IPv4 octets to hex
    octets = [int(x) for x in str(ipv4_obj).split('.')]
    hex_addr = ''.join(f'{octet:02x}' for octet in octets)
    # Format as 2002:xxxx:xxxx::
    ipv6_6to4 = f"2002:{hex_addr[:4]}:{hex_addr[4:]}::"
    return ipv6_6to4



def get_ip_info(ip_string):
    """
    Get detailed information about an IP address or CIDR network
    
    Args:
        ip_string (str): IP address or CIDR to analyze
        
    Returns:
        dict: Information about the IP address and subnet
    """
    is_valid, ip_type, ip_obj, network_obj = parse_network_input(ip_string)
    
    if not is_valid:
        return {
            "valid": False,
            "ip": ip_string,
            "type": None,
            "is_private": None,
            "is_loopback": None,
            "is_multicast": None,
            "is_reserved": None,
            "cidr": None,
            "subnet_class": None,
            "subnet_mask": None,
            "network_address": None,
            "ip_range": None,
            "host_count": None
        }

    assert ip_obj is not None and network_obj is not None

    # Calculate host count
    # For IPv4: total addresses minus network and broadcast (except /31 and /32)
    # For IPv6: all addresses are usable
    if ip_type == "IPv4":
        subnet_class = get_ipv4_class(ip_obj)
        subnet_mask = str(network_obj.netmask)
        
        if network_obj.prefixlen == 32:
            # Single host
            host_count = 1
            ip_range = f"{network_obj.network_address} - {network_obj.broadcast_address}"
        elif network_obj.prefixlen == 31:
            # Point-to-point link (RFC 3021) - both addresses usable
            host_count = 2
            ip_range = f"{network_obj.network_address} - {network_obj.broadcast_address}"
        else:
            # Standard subnet: total - network - broadcast
            host_count = network_obj.num_addresses - 2
            ip_range = f"{network_obj.network_address + 1} - {network_obj.broadcast_address - 1}"
    else:
        subnet_class = "N/A"
        subnet_mask = str(network_obj.netmask)
        host_count = network_obj.num_addresses
        ip_range = f"{network_obj.network_address} - {network_obj.broadcast_address}"

    # Add IPv6 conversion info for IPv4 addresses
    ipv6_mapped = None
    ipv6_6to4 = None
    if ip_type == "IPv4":
        ipv6_mapped = ipv4_to_ipv6_mapped(ip_obj)
        ipv6_6to4 = ipv4_to_ipv6_6to4(ip_obj)
    
    return {
        "valid": True,
        "ip": str(ip_obj),
        "type": ip_type,
        "is_private": ip_obj.is_private,
        "is_loopback": ip_obj.is_loopback,
        "is_multicast": ip_obj.is_multicast,
        "is_reserved": ip_obj.is_reserved,
        "is_global": ip_obj.is_global if ip_type == "IPv6" else not ip_obj.is_private,
        "cidr": f"/{network_obj.prefixlen}",
        "subnet_class": subnet_class,
        "subnet_mask": subnet_mask,
        "network_address": str(network_obj.network_address),
        "ip_range": ip_range,
        "host_count": host_count,
        "ipv6_mapped": ipv6_mapped,
        "ipv6_6to4": ipv6_6to4
    }


def main():
    """
    Main function to demonstrate IP validation
    """
    # Test cases
    test_ips = [
        "192.168.1.1",          # Valid private IPv4, defaults to /32
        "8.8.8.8/24",           # Valid public IPv4 network
        "255.255.255.255",      # Valid IPv4 (broadcast)
        "256.1.1.1",            # Invalid IPv4 (out of range)
        "192.168.1",            # Invalid IPv4 (incomplete)
        "192.168.1.1.1",        # Invalid IPv4 (too many octets)
        "192.168.01.1",         # Invalid IPv4 (leading zero)
        "::1",                  # Valid IPv6 (loopback)
        "2001:0db8:85a3::8a2e:0370:7334/64",  # Valid IPv6 network
        "fe80::1",              # Valid IPv6 (link-local)
        "not.an.ip.address",    # Invalid
        "127.0.0.1",            # Valid IPv4 (loopback)
        "0.0.0.0",              # Valid IPv4 (all zeros)
    ]
    
    print("=" * 70)
    print("IP ADDRESS VALIDATOR")
    print("=" * 70)
    
    for ip in test_ips:
        info = get_ip_info(ip)
        print(f"\nIP: {ip}")
        print(f"  Valid: {info['valid']}")
        
        if info['valid']:
            print(f"  Type: {info['type']}")
            print(f"  CIDR: {info['cidr']}")
            print(f"  Host Count: {info['host_count']}")
            print(f"  Subnet Class: {info['subnet_class']}")
            print(f"  Subnet Mask: {info['subnet_mask']}")
            print(f"  Network Address: {info['network_address']}")
            print(f"  IP Range: {info['ip_range']}")
            print(f"  Private: {info['is_private']}")
            print(f"  Loopback: {info['is_loopback']}")
            print(f"  Multicast: {info['is_multicast']}")
            print(f"  Reserved: {info['is_reserved']}")
            if info['ipv6_mapped']:
                print(f"  IPv6 Mapped: {info['ipv6_mapped']}")
                print(f"  IPv6 6to4: {info['ipv6_6to4']}")
    
    print("\n" + "=" * 70)
    
    # Interactive mode
    print("\nInteractive Mode (type 'quit' to exit)")
    print("\nThis tool takes an IP with or without a cidr mask and returns some info about it)")
    print("-" * 70)
    
    while True:
        user_input = input("\nEnter IP address or CIDR to validate: ").strip()
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("Goodbye!")
            break
        
        if not user_input:
            continue
        
        info = get_ip_info(user_input)
        
        if info['valid']:
            print(f"✓ Valid {info['type']} address")
            print(f"  CIDR: {info['cidr']}")
            print(f"  Host Count: {info['host_count']}")
            print(f"  Subnet Class: {info['subnet_class']}")
            print(f"  Subnet Mask: {info['subnet_mask']}")
            print(f"  Network Address: {info['network_address']}")
            print(f"  IP Range: {info['ip_range']}")
            print(f"  Private: {info['is_private']}")
            print(f"  Loopback: {info['is_loopback']}")
            print(f"  Multicast: {info['is_multicast']}")
            if info['ipv6_mapped']:
                print(f"  IPv6 Mapped: {info['ipv6_mapped']}")
                print(f"  IPv6 6to4: {info['ipv6_6to4']}")
        else:
            print("✗ Invalid IP address")


if __name__ == "__main__":
    main()

# Made with Bob
