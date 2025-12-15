This design creates the following objects in the source of truth to establish the initial network environment in three sites: East Side Data Center (esdc), West Side Data Center (wsdc), and Backbone.

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