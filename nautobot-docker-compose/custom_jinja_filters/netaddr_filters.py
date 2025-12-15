from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from django_jinja import library

@library.filter
def ipaddr(value, operation=None):
    """Mimic Ansible's ipaddr filter, including IP address validation."""
    # Handle IP address validation (ansible.utils.ipaddr('1') or no operation)
    if operation == '1' or operation is None:
        try:
            # Try to parse as CIDR first to handle inputs like '192.168.1.1/24'
            try:
                ip_network = IPNetwork(value)
                ip = ip_network.ip  # Extract the IP address part
            except Exception:
                ip = value  # If not CIDR, try as plain IP
            # Validate as IP address
            ip_addr = IPAddress(ip)
            return str(ip_addr)  # Return the IP address as a string if valid
        except AddrFormatError:
            return False  # Return False if not a valid IP address

    # Existing logic for CIDR-based operations
    try:
        ip = IPNetwork(value)
    except Exception:
        return value  # Fail gracefully if it's not CIDR

    if operation == "address":
        return str(ip.ip)
    elif operation == "netmask":
        return str(ip.netmask)
    elif operation == "prefix":
        return str(ip.prefixlen)
    elif operation == "network":
        return str(ip.network)
    elif operation == "broadcast":
        return str(ip.broadcast)
    elif operation == "hostmask":
        return str(ip.hostmask)
    else:
        return str(ip)  # Fallback to full CIDR notation