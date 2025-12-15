import os
import yaml
from nautobot.apps.jobs import register_jobs
from nautobot_design_builder.design_job import DesignJob
from nautobot_design_builder.choices import DesignModeChoices
from nautobot_design_builder.contrib import ext
from .context import InitialDesignContext


# Define a simple !ref constructor
def ref_constructor(loader, node):
    return loader.construct_scalar(node)

# Register the constructor
yaml.SafeLoader.add_constructor('!ref', ref_constructor)

class InitialDesign(DesignJob):
    """Initialize the database with default values needed by the Nautobot Workshop Demo."""
    has_sensitive_variables = False

    def render_design(self, context, design_file):
        """Override render_design to log the rendered YAML."""
        self.rendered = self.render(context, design_file)
        try:
            with open("/tmp/rendered_yaml.txt", "w") as f:
                f.write("Rendered YAML:\n")
                f.write(self.rendered)
            print("Rendered YAML written to /tmp/rendered_yaml.txt")
        except Exception as e:
            print(f"Failed to write rendered YAML to file: {e}")
        design = yaml.safe_load(self.rendered)
        self.rendered_design = design_file
        return design

    class Meta:
        """Metadata needed to implement the site design."""
        design_mode = DesignModeChoices.DEPLOYMENT
        name = "Nautobot Workshop Demo Initial Data"
        commit_default = False
        celery_worker = "default"
        design_files = [
          "designs/0001_extensible_ipam.yaml.j2",
          "designs/0002_org_devices.yaml.j2",
          "designs/0003_primary_ip.yaml.j2",
          "designs/0004_bgp_routing.yaml.j2"
        ]
        context_class = InitialDesignContext
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

name = "Nautobot Workshop Demo Designs"
register_jobs(InitialDesign)