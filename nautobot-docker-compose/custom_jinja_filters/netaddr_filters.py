from netaddr import IPNetwork
from django_jinja import library

@library.filter
def ipaddr(value, operation=None):
    """Mimic Ansible's ipaddr filter."""
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
        return str(ip)  # fallback
