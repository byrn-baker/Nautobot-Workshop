from netaddr import IPNetwork
from django_jinja import library


@library.filter
def ipv4_address(value):
    return str(IPNetwork(value).ip)


@library.filter
def netmask(value):
    return str(IPNetwork(value).netmask)
