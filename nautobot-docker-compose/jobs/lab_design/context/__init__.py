from nautobot_design_builder.context import Context
from netaddr import IPNetwork
from collections import defaultdict

class InitialDemoDesignContext(Context):
    provider_count: int
    provider_edge_count: int
    provider_rr_count: int
    backbone_ipv4_subnet: str
    backbone_ipv6_subnet: str

    east_dc_customer_edge_count: int
    east_dc_spine_count: int
    east_dc_leaf_count: int
    east_dc_ipv4_subnet: str
    east_dc_ipv6_subnet: str

    west_dc_customer_edge_count: int
    west_dc_spine_count: int
    west_dc_leaf_count: int
    west_dc_ipv4_subnet: str
    west_dc_ipv6_subnet: str

    mgmt_ipv4_subnet: str
    mgmt_ipv6_subnet: str

    @property
    def backbone_ipv4(self): return IPNetwork(self.backbone_ipv4_subnet)
    @property
    def backbone_ipv6(self): return IPNetwork(self.backbone_ipv6_subnet)
    @property
    def east_ipv4(self): return IPNetwork(self.east_dc_ipv4_subnet)
    @property
    def east_ipv6(self): return IPNetwork(self.east_dc_ipv6_subnet)
    @property
    def west_ipv4(self): return IPNetwork(self.west_dc_ipv4_subnet)
    @property
    def west_ipv6(self): return IPNetwork(self.west_dc_ipv6_subnet)
    @property
    def mgmt_ipv4(self): return IPNetwork(self.mgmt_ipv4_subnet)
    @property
    def mgmt_ipv6(self): return IPNetwork(self.mgmt_ipv6_subnet)

    @property
    def custom_fields(self):
        return [
            {
                "name": "OSPF Network Type",
                "grouping": "OSPF",
                "description": "Network type for OSPF",
                "key": "ospf_network_type",
                "type": "select",
                "choices": [
                    "point-to-point",
                    "broadcast",
                    "non-broadcast",
                    "point-to-multipoint",
                ],
                "content_types": ["dcim.interface"],
            },
            {
                "name": "OSPF Area",
                "grouping": "OSPF",
                "description": "OSPF Area ID assigned to this interface (decimal or dotted format)",
                "key": "ospf_area",
                "type": "text",
                "validation_regex": r"^([0-9]{1,10}|([0-9]{1,3}\.){3}[0-9]{1,3})$",
                "content_types": ["dcim.interface"],
            },
            {
                "name": "MPLS Enabled",
                "grouping": "MPLS",
                "description": "Enable MPLS on this interface",
                "key": "mpls_enabled",
                "type": "boolean",
                "default": False,
                "content_types": ["dcim.interface"],
            },
        ]

    @property
    def namespaces(self):
        return [
            {"name": "clabbr220", "description": "Containerlab namespace for the in-band MGMT"},
        ]

    @property
    def vrfs(self):
        return [
            {"name": "clab-mgmt", "namespace": "clabbr220", "description": "in-band MGMT", "rd": "65000:1"}
        ]

    @property
    def manufacturers(self):
        return [
            {"name": "Arista"},
            {"name": "Cisco"},
            {"name": "docker"},
        ]

    @property
    def platforms(self):
        return [
            {"name": "EOS", "network_driver": "arista_eos", "manufacturer": "Arista"},
            {"name": "IOS", "network_driver": "cisco_ios", "manufacturer": "Cisco"},
        ]

    @property
    def software_versions(self):
        return [
            {"version": "4.34.0F", "platform": "EOS"},
            {"version": "17.12.01", "platform": "IOS"},
        ]

    @property
    def device_types(self):
        return [
            {"model": "ceos", "u_height": 1, "manufacturer": "Arista"},
            {"model": "iol", "u_height": 1, "manufacturer": "Cisco"},
            {"model": "network", "u_height": 1, "manufacturer": "docker"},
        ]

    @property
    def roles(self):
        return [
            {"name": "Customer Edge Router", "color": "3f51b5", "content_types": ["dcim.device"]},
            {"name": "Datacenter Leaf", "color": "ffeb3b", "content_types": ["dcim.device"]},
            {"name": "Datacenter Spine", "color": "d0530e", "content_types": ["dcim.device"]},
            {"name": "Provider Edge Router", "color": "6c5734", "content_types": ["dcim.device"]},
            {"name": "Provider Route Reflector", "color": "77e2f7", "content_types": ["dcim.device"]},
            {"name": "Provider Router", "color": "ac766f", "content_types": ["dcim.device"]},
        ]

    @property
    def location_types(self):
        return [
            {"name": "Site", "content_types": ["dcim.device", "ipam.prefix", "ipam.vlan"]},
        ]

    @property
    def locations(self):
        return [
            {"name": "Nautobot Workshop", "location_type": "Site", "status": "Active", "children": [
                {"name": "East Side Data Center", "description": "East DC", "location_type": "Site", "parent": "Nautobot Workshop"},
                {"name": "West Side Data Center", "description": "West DC", "location_type": "Site", "parent": "Nautobot Workshop"},
                {"name": "Backbone", "description": "Backbone", "location_type": "Site", "parent": "Nautobot Workshop"},
            ]}
        ]

    @property
    def prefixes(self):
        def split_supernet(supernet):
            new_prefix = IPNetwork(supernet).prefixlen + 1
            p2p_subnet, loop_subnet = list(IPNetwork(supernet).subnet(new_prefix))[:2]
            return str(p2p_subnet), str(loop_subnet)
        backbone_p2p_v4, backbone_lo_v4 = split_supernet(self.backbone_ipv4_subnet)
        eastdc_p2p_v4, eastdc_lo_v4 = split_supernet(self.east_dc_ipv4_subnet)
        westdc_p2p_v4, westdc_lo_v4 = split_supernet(self.west_dc_ipv4_subnet)
        return [
            {"prefix": backbone_p2p_v4, "role": "p2p", "segment": "backbone", "family": "ipv4"},
            {"prefix": backbone_lo_v4, "role": "loopback", "segment": "backbone", "family": "ipv4"},
            {"prefix": eastdc_p2p_v4, "role": "p2p", "segment": "east_dc", "family": "ipv4"},
            {"prefix": eastdc_lo_v4, "role": "loopback", "segment": "east_dc", "family": "ipv4"},
            {"prefix": westdc_p2p_v4, "role": "p2p", "segment": "west_dc", "family": "ipv4"},
            {"prefix": westdc_lo_v4, "role": "loopback", "segment": "west_dc", "family": "ipv4"},
            {"prefix": str(self.mgmt_ipv4_subnet), "role": "mgmt", "segment": "mgmt", "family": "ipv4"},
        ]

    @property
    def devices(self):
        devices = []
        providers, pes, rrs = [], [], []
        # Provider Routers
        for i in range(self.provider_count):
            name = f"P{i+1}"
            providers.append(name)
            devices.append({
                "name": name,
                "role": "Provider Router",
                "type": "iol",
                "location": "Backbone",
                "device_type": "iol",
                "platform": "IOS",
                "software_version": "17.12.01",
                "mgmt_interface": "Ethernet0/0"
            })
        # Provider Edge Routers
        for i in range(self.provider_edge_count):
            name = f"PE{i+1}"
            pes.append(name)
            devices.append({
                "name": name,
                "role": "Provider Edge Router",
                "type": "iol",
                "location": "Backbone",
                "device_type": "iol",
                "platform": "IOS",
                "software_version": "17.12.01",
                "mgmt_interface": "Ethernet0/0"
            })
        # Route Reflectors
        for i in range(self.provider_rr_count):
            name = f"RR{i+1}"
            rrs.append(name)
            devices.append({
                "name": name,
                "role": "Provider Route Reflector",
                "type": "iol",
                "location": "Backbone",
                "device_type": "iol",
                "platform": "IOS",
                "software_version": "17.12.01",
                "mgmt_interface": "Ethernet0/0"
            })
        east_ce, west_ce, east_spines, west_spines, east_leafs, west_leafs = [], [], [], [], [], []
        for i in range(self.east_dc_customer_edge_count):
            name = f"E-CE{i+1}"
            east_ce.append(name)
            devices.append({
                "name": name,
                "role": "Customer Edge Router",
                "type": "iol",
                "location": "East Side Data Center",
                "device_type": "iol",
                "platform": "IOS",
                "software_version": "17.12.01",
                "mgmt_interface": "Ethernet0/0"
            })
        for i in range(self.east_dc_spine_count):
            name = f"East-Spine{i+1}"
            east_spines.append(name)
            devices.append({
                "name": name,
                "role": "Datacenter Spine",
                "type": "ceos",
                "location": "East Side Data Center",
                "device_type": "ceos",
                "platform": "EOS",
                "software_version": "4.34.0F",
                "mgmt_interface": "eth1"
            })
        for i in range(self.east_dc_leaf_count):
            name = f"East-Leaf{i+1}"
            east_leafs.append(name)
            devices.append({
                "name": name,
                "role": "Datacenter Leaf",
                "type": "ceos",
                "location": "East Side Data Center",
                "device_type": "ceos",
                "platform": "EOS",
                "software_version": "4.34.0F",
                "mgmt_interface": "eth1"
            })
        for i in range(self.west_dc_customer_edge_count):
            name = f"W-CE{i+1}"
            west_ce.append(name)
            devices.append({
                "name": name,
                "role": "Customer Edge Router",
                "type": "iol",
                "location": "West Side Data Center",
                "device_type": "iol",
                "platform": "IOS",
                "software_version": "17.12.01",
                "mgmt_interface": "Ethernet0/0"
            })
        for i in range(self.west_dc_spine_count):
            name = f"West-Spine{i+1}"
            west_spines.append(name)
            devices.append({
                "name": name,
                "role": "Datacenter Spine",
                "type": "ceos",
                "location": "West Side Data Center",
                "device_type": "ceos",
                "platform": "EOS",
                "software_version": "4.34.0F",
                "mgmt_interface": "eth1"
            })
        for i in range(self.west_dc_leaf_count):
            name = f"West-Leaf{i+1}"
            west_leafs.append(name)
            devices.append({
                "name": name,
                "role": "Datacenter Leaf",
                "type": "ceos",
                "location": "West Side Data Center",
                "device_type": "ceos",
                "platform": "EOS",
                "software_version": "4.34.0F",
                "mgmt_interface": "eth1"
            })

        # Assign MGMT and LOOPBACK IPs
        mgmt_prefix = [p["prefix"] for p in self.prefixes if p["segment"] == "mgmt" and p["family"] == "ipv4"][0]
        mgmt_ips = list(IPNetwork(mgmt_prefix).iter_hosts())
        # Loopback Prefixes for each segment
        loopback_pfx_map = {
            "Backbone":   [p["prefix"] for p in self.prefixes if p["segment"] == "backbone" and p["role"] == "loopback"][0],
            "East Side Data Center": [p["prefix"] for p in self.prefixes if p["segment"] == "east_dc" and p["role"] == "loopback"][0],
            "West Side Data Center": [p["prefix"] for p in self.prefixes if p["segment"] == "west_dc" and p["role"] == "loopback"][0]
        }
        loopback_hosts = {loc: list(IPNetwork(pfx).iter_hosts()) for loc, pfx in loopback_pfx_map.items()}

        for idx, dev in enumerate(devices):
            dev["mgmt_ip"] = str(mgmt_ips[idx])
            # Assign a loopback IP from the location's loopback prefix
            dev["loopback_ip"] = str(loopback_hosts[dev["location"]][idx % len(loopback_hosts[dev["location"]])])

        # Interface mapping
        interface_map = self._interface_map_from_links(devices)
        for dev in devices:
            interfaces = []
            # MGMT interface
            interfaces.append({
                "name": dev["mgmt_interface"],
                "type": "virtual",
                "ipv4_address": f"{dev['mgmt_ip']}/24",
                "ospf_network_type": "point-to-point",
                "mpls_enabled": False,
            })
            # Loopback0 interface
            interfaces.append({
                "name": "Loopback0",
                "type": "virtual",
                "ipv4_address": f"{dev['loopback_ip']}/32",
                "ospf_network_type": None,
                "mpls_enabled": False,
                "ospf_area": dev.get("ospf_area"),
            })
            # Physical interfaces from interface map
            for intf_name, intf_info in interface_map[dev["name"]].items():
                intf = {
                    "name": intf_name,
                    "type": intf_info.get("type", "1000base-t"),
                    "ipv4_address": intf_info["ipv4_address"],
                    "ospf_network_type": intf_info["ospf_network_type"],
                    "mpls_enabled": intf_info["mpls_enabled"],
                    "ospf_area": intf_info.get("ospf_area"),
                    "z_device": intf_info["z_device"],
                    "z_interface": intf_info["z_interface"]
                }
                interfaces.append(intf)
            dev["interfaces"] = interfaces
        return devices

    def _interface_map_from_links(self, devices):
        interface_map = defaultdict(dict)
        for link in self.links:
            dev_a, dev_b = link["devices"]
            intf_a, intf_b = link["interfaces"][dev_a], link["interfaces"][dev_b]
            ip_a, ip_b = link["ips"][dev_a], link["ips"][dev_b]

            mpls_a, mpls_b = False, False
            ospf_area_a, ospf_area_b = None, None

            is_provider_a = dev_a.startswith("P")
            is_provider_b = dev_b.startswith("P")
            is_pe_a = dev_a.startswith("PE")
            is_pe_b = dev_b.startswith("PE")

            # Provider <-> Provider or Provider <-> PE
            if (is_provider_a and is_provider_b):
                mpls_a = mpls_b = True
                ospf_area_a = ospf_area_b = "0"
            elif (is_provider_a and is_pe_b):
                mpls_a = mpls_b = True
                if dev_b == "PE1":
                    ospf_area_a = ospf_area_b = "1"
                elif dev_b == f"PE{self.provider_edge_count}":
                    ospf_area_a = ospf_area_b = "2"
                else:
                    ospf_area_a = ospf_area_b = "0"
            elif (is_pe_a and is_provider_b):
                mpls_a = mpls_b = True
                if dev_a == "PE1":
                    ospf_area_a = ospf_area_b = "1"
                elif dev_a == f"PE{self.provider_edge_count}":
                    ospf_area_a = ospf_area_b = "2"
                else:
                    ospf_area_a = ospf_area_b = "0"
            # All other links: no OSPF, no MPLS

            interface_map[dev_a][intf_a] = {
                "z_device": dev_b,
                "z_interface": intf_b,
                "ipv4_address": f"{ip_a}/31",
                "type": self._interface_type(dev_a, intf_a),
                "ospf_network_type": "point-to-point",
                "mpls_enabled": mpls_a,
                "ospf_area": str(ospf_area_a) if ospf_area_a is not None else None,
            }
            interface_map[dev_b][intf_b] = {
                "z_device": dev_a,
                "z_interface": intf_a,
                "ipv4_address": f"{ip_b}/31",
                "type": self._interface_type(dev_b, intf_b),
                "ospf_network_type": "point-to-point",
                "mpls_enabled": mpls_b,
                "ospf_area": str(ospf_area_b) if ospf_area_b is not None else None,
            }
        return interface_map

    def _interface_type(self, dev_name, intf_name):
        # Only loopbacks and management are "virtual", everything else is "1000base-t"
        if intf_name.lower() == "loopback0" or "mgmt" in intf_name.lower():
            return "virtual"
        if dev_name.startswith("P") or dev_name.startswith("PE") or dev_name.startswith("RR") or dev_name.startswith("E-CE") or dev_name.startswith("W-CE"):
            return "1000base-t"
        elif dev_name.startswith("East-Spine") or dev_name.startswith("West-Spine") or dev_name.startswith("East-Leaf") or dev_name.startswith("West-Leaf"):
            return "1000base-t"
        else:
            return "1000base-t"

    @property
    def links(self):
        providers = [f"P{i+1}" for i in range(self.provider_count)]
        pes = [f"PE{i+1}" for i in range(self.provider_edge_count)]
        rrs = [f"RR{i+1}" for i in range(self.provider_rr_count)]
        east_ce = [f"E-CE{i+1}" for i in range(self.east_dc_customer_edge_count)]
        west_ce = [f"W-CE{i+1}" for i in range(self.west_dc_customer_edge_count)]
        east_spines = [f"East-Spine{i+1}" for i in range(self.east_dc_spine_count)]
        west_spines = [f"West-Spine{i+1}" for i in range(self.west_dc_spine_count)]
        east_leafs = [f"East-Leaf{i+1}" for i in range(self.east_dc_leaf_count)]
        west_leafs = [f"West-Leaf{i+1}" for i in range(self.west_dc_leaf_count)]

        # Helper for IOS/IOL routers
        def next_iol_intf(counter):
            group, pos = divmod(counter, 4)
            return f"Ethernet{group}/{pos}"

        # Helper for EOS/Arista cEOS routers
        def next_ceos_intf(counter):
            return f"eth{counter}"

        # Interface pointer for each device
        interface_pointers = {}
        for d in providers + pes + rrs + east_ce + west_ce:
            interface_pointers[d] = 1
        for d in east_spines + west_spines + east_leafs + west_leafs:
            interface_pointers[d] = 1

        backbone_p2p_v4 = [p["prefix"] for p in self.prefixes if p["segment"] == "backbone" and p["role"] == "p2p" and p["family"] == "ipv4"][0]
        p2p_blocks = list(IPNetwork(backbone_p2p_v4).subnet(31))
        block_idx = 0
        links = []

        # Backbone topology
        if len(providers) == 4:
            for side in [(0,2), (1,3)]:
                a, b = providers[side[0]], providers[side[1]]
                intfs = [next_iol_intf(interface_pointers[a]), next_iol_intf(interface_pointers[b])]
                ips = list(p2p_blocks[block_idx])
                links.append({
                    "devices": [a, b],
                    "interfaces": {a: intfs[0], b: intfs[1]},
                    "ips": {a: str(ips[0]), b: str(ips[1])},
                    "network": str(p2p_blocks[block_idx])
                })
                interface_pointers[a] += 1
                interface_pointers[b] += 1
                block_idx += 1
            for side in [(0,1), (2,3)]:
                a, b = providers[side[0]], providers[side[1]]
                intfs = [next_iol_intf(interface_pointers[a]), next_iol_intf(interface_pointers[b])]
                ips = list(p2p_blocks[block_idx])
                links.append({
                    "devices": [a, b],
                    "interfaces": {a: intfs[0], b: intfs[1]},
                    "ips": {a: str(ips[0]), b: str(ips[1])},
                    "network": str(p2p_blocks[block_idx])
                })
                interface_pointers[a] += 1
                interface_pointers[b] += 1
                block_idx += 1
            for rr in rrs:
                for top in [providers[0], providers[1]]:
                    intfs = [next_iol_intf(interface_pointers[rr]), next_iol_intf(interface_pointers[top])]
                    ips = list(p2p_blocks[block_idx])
                    links.append({
                        "devices": [rr, top],
                        "interfaces": {rr: intfs[0], top: intfs[1]},
                        "ips": {rr: str(ips[0]), top: str(ips[1])},
                        "network": str(p2p_blocks[block_idx])
                    })
                    interface_pointers[rr] += 1
                    interface_pointers[top] += 1
                    block_idx += 1
            for idx, pe in enumerate(pes):
                if idx % 2 == 0:
                    for side in [providers[0], providers[1]]:
                        intfs = [next_iol_intf(interface_pointers[pe]), next_iol_intf(interface_pointers[side])]
                        ips = list(p2p_blocks[block_idx])
                        links.append({
                            "devices": [pe, side],
                            "interfaces": {pe: intfs[0], side: intfs[1]},
                            "ips": {pe: str(ips[0]), side: str(ips[1])},
                            "network": str(p2p_blocks[block_idx])
                        })
                        interface_pointers[pe] += 1
                        interface_pointers[side] += 1
                        block_idx += 1
                else:
                    for side in [providers[2], providers[3]]:
                        intfs = [next_iol_intf(interface_pointers[pe]), next_iol_intf(interface_pointers[side])]
                        ips = list(p2p_blocks[block_idx])
                        links.append({
                            "devices": [pe, side],
                            "interfaces": {pe: intfs[0], side: intfs[1]},
                            "ips": {pe: str(ips[0]), side: str(ips[1])},
                            "network": str(p2p_blocks[block_idx])
                        })
                        interface_pointers[pe] += 1
                        interface_pointers[side] += 1
                        block_idx += 1

        # EAST DC P2P blocks
        eastdc_p2p_v4 = [p["prefix"] for p in self.prefixes if p["segment"] == "east_dc" and p["role"] == "p2p" and p["family"] == "ipv4"][0]
        east_p2p_blocks = list(IPNetwork(eastdc_p2p_v4).subnet(31))
        east_idx = 0
        for ce in east_ce:
            intf_ce = next_iol_intf(interface_pointers[ce])
            intf_pe = next_iol_intf(interface_pointers[pes[0]])
            ips = list(east_p2p_blocks[east_idx])
            links.append({
                "devices": [ce, pes[0]],
                "interfaces": {ce: intf_ce, pes[0]: intf_pe},
                "ips": {ce: str(ips[0]), pes[0]: str(ips[1])},
                "network": str(east_p2p_blocks[east_idx])
            })
            interface_pointers[ce] += 1
            interface_pointers[pes[0]] += 1
            east_idx += 1
        for spine in east_spines:
            intf_spine = next_ceos_intf(interface_pointers[spine])
            intf_ce = next_iol_intf(interface_pointers[east_ce[0]])
            ips = list(east_p2p_blocks[east_idx])
            links.append({
                "devices": [spine, east_ce[0]],
                "interfaces": {spine: intf_spine, east_ce[0]: intf_ce},
                "ips": {spine: str(ips[0]), east_ce[0]: str(ips[1])},
                "network": str(east_p2p_blocks[east_idx])
            })
            interface_pointers[spine] += 1
            interface_pointers[east_ce[0]] += 1
            east_idx += 1
        for leaf in east_leafs:
            for idx, spine in enumerate(east_spines):
                intf_leaf = next_ceos_intf(interface_pointers[leaf])
                intf_spine = next_ceos_intf(interface_pointers[spine])
                ips = list(east_p2p_blocks[east_idx])
                links.append({
                    "devices": [leaf, spine],
                    "interfaces": {leaf: intf_leaf, spine: intf_spine},
                    "ips": {leaf: str(ips[0]), spine: str(ips[1])},
                    "network": str(east_p2p_blocks[east_idx])
                })
                interface_pointers[leaf] += 1
                interface_pointers[spine] += 1
                east_idx += 1

        # WEST DC P2P blocks
        westdc_p2p_v4 = [p["prefix"] for p in self.prefixes if p["segment"] == "west_dc" and p["role"] == "p2p" and p["family"] == "ipv4"][0]
        west_p2p_blocks = list(IPNetwork(westdc_p2p_v4).subnet(31))
        west_idx = 0
        for ce in west_ce:
            intf_ce = next_iol_intf(interface_pointers[ce])
            intf_pe = next_iol_intf(interface_pointers[pes[-1]])
            ips = list(west_p2p_blocks[west_idx])
            links.append({
                "devices": [ce, pes[-1]],
                "interfaces": {ce: intf_ce, pes[-1]: intf_pe},
                "ips": {ce: str(ips[0]), pes[-1]: str(ips[1])},
                "network": str(west_p2p_blocks[west_idx])
            })
            interface_pointers[ce] += 1
            interface_pointers[pes[-1]] += 1
            west_idx += 1
        for spine in west_spines:
            intf_spine = next_ceos_intf(interface_pointers[spine])
            intf_ce = next_iol_intf(interface_pointers[west_ce[0]])
            ips = list(west_p2p_blocks[west_idx])
            links.append({
                "devices": [spine, west_ce[0]],
                "interfaces": {spine: intf_spine, west_ce[0]: intf_ce},
                "ips": {spine: str(ips[0]), west_ce[0]: str(ips[1])},
                "network": str(west_p2p_blocks[west_idx])
            })
            interface_pointers[spine] += 1
            interface_pointers[west_ce[0]] += 1
            west_idx += 1
        for leaf in west_leafs:
            for idx, spine in enumerate(west_spines):
                intf_leaf = next_ceos_intf(interface_pointers[leaf])
                intf_spine = next_ceos_intf(interface_pointers[spine])
                ips = list(west_p2p_blocks[west_idx])
                links.append({
                    "devices": [leaf, spine],
                    "interfaces": {leaf: intf_leaf, spine: intf_spine},
                    "ips": {leaf: str(ips[0]), spine: str(ips[1])},
                    "network": str(west_p2p_blocks[west_idx])
                })
                interface_pointers[leaf] += 1
                interface_pointers[spine] += 1
                west_idx += 1
        return links