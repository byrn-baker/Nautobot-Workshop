from nautobot.apps.jobs import register_jobs, IntegerVar, StringVar, IPNetworkVar
from nautobot_design_builder.design_job import DesignJob
from nautobot_design_builder.choices import DesignModeChoices
from nautobot_design_builder.contrib import ext
from .context import InitialDemoDesignContext

class InitialDemoDesign(DesignJob):
    # --- Backbone Segment ---
    provider_count = IntegerVar(
        description="Number of Provider Routers",
        default=4
    )
    provider_edge_count = IntegerVar(
        description="Number of Provider Edge Routers",
        default=2
    )
    provider_rr_count = IntegerVar(
        description="Number of Provider Route Reflector Routers",
        default=1
    )
    backbone_ipv4_subnet = IPNetworkVar(
        description="Backbone IPv4 Subnet (e.g., 100.0.0.0/24)",
        default="100.0.0.0/24",
    )
    backbone_ipv6_subnet = IPNetworkVar(
        description="Backbone IPv6 Subnet (e.g., 2001:db8:100::/56)",
        default="2001:db8:100::/56",
    )
    # --- East Data Center Segment ---
    east_dc_customer_edge_count = IntegerVar(
        description="Number of Customer Edge Routers in East DC",
        default=1
    )
    east_dc_spine_count = IntegerVar(
        description="Number of Spine Routers in East DC",
        default=2
    )
    east_dc_leaf_count = IntegerVar(
        description="Number of Leaf Switches in East DC",
        default=2
    )
    east_dc_ipv4_subnet = IPNetworkVar(
        description="East DC IPv4 Subnet (e.g., 172.16.10.0/24)",
        default="172.16.10.0/24",
    )
    east_dc_ipv6_subnet = IPNetworkVar(
        description="East DC IPv6 Subnet (e.g., 2001:db8:10::/56)",
        default="2001:db8:10::/56",
    )
    # --- West Data Center Segment ---
    west_dc_customer_edge_count = IntegerVar(
        description="Number of Customer Edge Routers in West DC",
        default=1
    )
    west_dc_spine_count = IntegerVar(
        description="Number of Spine Routers in West DC",
        default=2
    )
    west_dc_leaf_count = IntegerVar(
        description="Number of Leaf Switches in West DC",
        default=2
    )
    west_dc_ipv4_subnet = IPNetworkVar(
        description="West DC IPv4 Subnet (e.g., 172.16.20.0/24)",
        default="172.16.20.0/24",
    )
    west_dc_ipv6_subnet = IPNetworkVar(
        description="West DC IPv6 Subnet (e.g., 2001:db8:20::/56)",
        default="2001:db8:20::/56",
    )
    # --- Management Network (common to all) ---
    mgmt_ipv4_subnet = IPNetworkVar(
        description="Management IPv4 Subnet (e.g., 192.168.100.0/24)",
        default="192.168.100.0/24",
    )
    mgmt_ipv6_subnet = IPNetworkVar(
        description="Management IPv6 Subnet (e.g., 2001:db8:beef::/64)",
        default="2001:db8:beef::/64",
    )

    class Meta:
        """Metadata needed to implement the site design."""
        design_mode = DesignModeChoices.DEPLOYMENT
        name = "Nautobot Workshop Dynamic Demo Initial Data"
        commit_default = False
        celery_worker = "default"
        design_files = [
          "designs/0001_extensible_ipam.yaml.j2",
          "designs/0002_org_devices.yaml.j2",
          "designs/0003_primary_ip.yaml.j2"
        ]
        context_class = InitialDemoDesignContext
        extensions = [ext.BGPPeeringExtension]
        version = "1.0.0"
        description = "Establish the devices and site information for three sites: East Side Data Center, West Side Data Center, and Backbone."
        docs = """This design creates the following objects in the source of truth to establish the initial network environment in three sites: East Side Data Center (esdc), West Side Data Center (wsdc), and Backbone.

- East Side Data Center includes:
  - 2 Datacenter Spine devices (East-Spine01, East-Spine02; Arista ceos)
  - 2 Datacenter Leaf devices (East-Leaf01, East-Leaf02; Arista ceos)
  - 1 Customer Edge Router (CE2; Cisco iol)
- West Side Data Center includes:
  - 2 Datacenter Spine devices (West-Spine01, West-Spine02; Arista ceos)
  - 2 Datacenter Leaf devices (West-Leaf01, West-Leaf02; Arista ceos)
  - 1 Customer Edge Router (CE1; Cisco iol)
- Backbone includes:
  - 4 Provider Routers (P1, P2, P3, P4; Cisco iol)
  - 3 Provider Edge Routers (PE1, PE2, PE3; Cisco iol)
  - 1 Provider Route Reflector (RR1; Cisco iol)

The design includes detailed configurations for devices, interfaces, IP addresses, OSPF settings, MPLS settings, VRF assignments, and cable connections, all statically defined in the design template.
"""

name = "Nautobot Workshop Demo Dynamic Design"
register_jobs(InitialDemoDesign)