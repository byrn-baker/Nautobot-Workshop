from collections import defaultdict

from nautobot.apps.jobs import (
    Job,
    register_jobs,
    BooleanVar,
    IntegerVar,
    MultiObjectVar,
    StringVar,
)
from nautobot.dcim.models import Device, Interface, Location
from nautobot.extras.models import Role

from nornir import InitNornir
from nornir.core.plugins.inventory import InventoryPluginRegister
from nautobot_plugin_nornir.plugins.inventory.nautobot_orm import NautobotORMInventory

from nornir.core.task import Task, Result
from nornir.core.filter import F
from nornir_napalm.plugins.tasks import napalm_ping


# Register the ORM inventory plugin under a known name (no URL/token needed)
try:
    InventoryPluginRegister.register("nautobot-inventory", NautobotORMInventory)
except Exception:
    pass


class L3NeighborPingValidationNornir(Job):
    """
    Validate L3 adjacency by pinging neighbor interface IPs across cabled router-to-router links using Nornir.
    Logs an approximate IOS/EOS CLI for visibility and structured results from napalm_ping.
    """

    class Meta:
        name = "L3 Neighbor Ping Validation (Nornir)"
        description = "Use Nornir to ping between directly connected routers (IPv4 and optionally IPv6); log CLI and results."
        commit_default = False

    # Scope selection
    sites = MultiObjectVar(
        model=Location,
        query_params={"location_type": "Site"},
        required=False,
        label="Limit to Sites",
    )
    roles = MultiObjectVar(
        model=Role,
        query_params={"content_types": ["dcim.device"]},
        required=False,
        label="Limit to Roles",
    )
    ipv6 = BooleanVar(default=False, label="Test IPv6")
    bidirectional = BooleanVar(default=True, label="Test Both Directions")
    vrf = StringVar(
        required=False,
        label="VRF (optional)",
        description="If set, use this VRF for the ping command (useful for mgmt VRFs).",
    )
    count = IntegerVar(default=3, min_value=1, max_value=20, label="ICMP Count")
    timeout = IntegerVar(default=2, min_value=1, max_value=10, label="Per-ping Timeout (seconds)")

    def _get_ip_on_interface(self, interface: Interface, want_ipv6: bool):
        """
        Return the first IP string on the interface matching the requested IP family.
        """
        for ip in interface.ip_addresses.all().order_by("pk"):
            host_ip = ip.address.ip
            if (host_ip.version == 6) == want_ipv6:
                return str(host_ip)
        return None

    def _approx_cli(self, napalm_driver: str | None, family: str, dest: str, source: str | None, count: int, timeout: int, vrf: str | None) -> str:
        """
        Build an approximate on-box CLI for visibility. Best-effort for IOS/EOS.
        """
        is_v6 = family == "IPv6"
        drv = (napalm_driver or "").lower()

        if drv == "ios":
            parts = ["ping"]
            if is_v6:
                parts.append("ipv6")
            if vrf:
                parts.extend(["vrf", vrf])
            parts.append(dest)
            if source:
                parts.extend(["source", source])
            parts.extend(["repeat", str(count)])
            parts.extend(["timeout", str(timeout)])
            return " ".join(parts)

        if drv == "eos":
            parts = ["ping"]
            if is_v6:
                parts.append("ipv6")
            if vrf:
                parts.extend(["vrf", vrf])
            parts.append(dest)
            if source:
                parts.extend(["source", source])
            parts.extend(["count", str(count)])
            parts.extend(["timeout", str(timeout)])
            return " ".join(parts)

        parts = ["ping"]
        if is_v6:
            parts.append("ipv6")
        if vrf:
            parts.extend(["vrf", vrf])
        parts.append(dest)
        if source:
            parts.extend(["source", source])
        parts.extend(["count", str(count), "timeout", str(timeout)])
        return " ".join(parts)

    # Keyword-only args must match the field names above
    def run(self, *, sites, roles, ipv6, bidirectional, vrf, count, timeout):
        self.logger.info("Starting L3 Neighbor Ping Validation.")

        want_ipv6 = bool(ipv6)
        bidir = bool(bidirectional)
        icmp_count = int(count)
        per_ping_timeout = int(timeout)
        vrf_name = (vrf or "").strip() or None

        # Base device queryset (filter by status Name)
        devices = Device.objects.filter(status__name="Active")

        # Scope by Sites (Locations)
        if sites:
            devices = devices.filter(location__in=sites)

        # Scope by Role(s)
        if roles:
            devices = devices.filter(role__in=roles)

        # Prefetch related objects
        devices = devices.prefetch_related("interfaces__ip_addresses", "platform").distinct()
        device_ids = {d.id for d in devices}

        # Build tests per host from cabled L3 links
        seen_links = set()
        tests_by_host = defaultdict(list)

        for iface in (
            Interface.objects.filter(device__in=devices, enabled=True)
            .prefetch_related("ip_addresses", "device__platform")
        ):
            peer = getattr(iface, "connected_endpoint", None)
            if peer is None or not isinstance(peer, Interface):
                continue
            if iface.device_id not in device_ids or peer.device_id not in device_ids:
                continue

            key = tuple(sorted((iface.pk, peer.pk)))
            if key in seen_links:
                continue
            seen_links.add(key)

            napalm_driver = getattr(getattr(iface.device, "platform", None), "napalm_driver", None)

            # Families to test
            families = [False]  # False => IPv4; True => IPv6
            if want_ipv6:
                families.append(True)

            for is_v6 in families:
                src_ip = self._get_ip_on_interface(iface, want_ipv6=is_v6)
                dst_ip = self._get_ip_on_interface(peer, want_ipv6=is_v6)
                if not src_ip or not dst_ip:
                    continue

                tests_by_host[iface.device.name].append(
                    {
                        "src_if_name": iface.name,
                        "src_ip": src_ip,
                        "dst_dev_name": peer.device.name,
                        "dst_if_name": peer.name,
                        "dst_ip": dst_ip,
                        "family": "IPv6" if is_v6 else "IPv4",
                        "napalm_driver": napalm_driver,
                    }
                )
                if bidir:
                    peer_driver = getattr(getattr(peer.device, "platform", None), "napalm_driver", napalm_driver)
                    tests_by_host[peer.device.name].append(
                        {
                            "src_if_name": peer.name,
                            "src_ip": dst_ip,
                            "dst_dev_name": iface.device.name,
                            "dst_if_name": iface.name,
                            "dst_ip": src_ip,
                            "family": "IPv6" if is_v6 else "IPv4",
                            "napalm_driver": peer_driver,
                        }
                    )

        if not tests_by_host:
            self.logger.warning("No eligible L3 links with IPs found for the selected scope.")
            return

        # Initialize Nornir with the ORM inventory; bump workers for speed
        nr = InitNornir(
            logging={"enabled": False},
            runner={"options": {"num_workers": 20}},
            inventory={
                "plugin": "nautobot-inventory",
                "options": {
                    # Adjust credentials provider to your environment as needed
                    "credentials_class": "nautobot_plugin_nornir.plugins.credentials.env_vars.CredentialsEnvVars",
                    "queryset": devices,
                },
            },
        )

        target_hostnames = list(tests_by_host.keys())
        nr_filtered = nr.filter(F(name__in=target_hostnames))

        # Attach per-host tests
        for host_name, tests in tests_by_host.items():
            if host_name in nr_filtered.inventory.hosts:
                nr_filtered.inventory.hosts[host_name].data["tests_for_host"] = tests

        if not nr_filtered.inventory.hosts:
            self.logger.warning("No Nornir hosts found based on selected scope.")
            return

        def ping_neighbors(task: Task, icmp_count: int, per_ping_timeout: int) -> Result:
            """
            Per-host task that runs napalm_ping and logs an approximate CLI and structured results.
            """
            tests_for_host = task.host.data.get("tests_for_host", [])
            for test in tests_for_host:
                desc = f"{test['family']} {task.host.name}({test['src_if_name']}) -> {test['dst_ip']} on {test['dst_dev_name']}({test['dst_if_name']})"

                approx_cmd = L3NeighborPingValidationNornir._approx_cli(
                    self,
                    napalm_driver=test.get("napalm_driver"),
                    family=test["family"],
                    dest=test["dst_ip"],
                    source=test["src_ip"],
                    count=icmp_count,
                    timeout=per_ping_timeout,
                    vrf=vrf_name if vrf_name else None,
                )
                self.logger.info("About to run: %s | CLI: %s", desc, approx_cmd)

                kwargs = {
                    "dest": test["dst_ip"],
                    "source": test["src_ip"],
                    "count": icmp_count,
                    "timeout": per_ping_timeout,
                }
                if vrf_name:
                    kwargs["vrf"] = vrf_name

                sub = task.run(name=f"PING {desc}", task=napalm_ping, **kwargs)

                # Log structured details
                data = sub.result
                if isinstance(data, dict):
                    if "success" in data and isinstance(data["success"], dict):
                        s = data["success"]
                        self.logger.info(
                            "Result: %s | sent=%s recv=%s loss=%s rtt(ms) min/avg/max=%s/%s/%s",
                            desc,
                            s.get("probes_sent"),
                            s.get("packet_receive"),
                            s.get("packet_loss"),
                            s.get("rtt_min"),
                            s.get("rtt_avg"),
                            s.get("rtt_max"),
                        )
                    elif "packet_loss" in data:
                        self.logger.info("Result: %s | %s", desc, data)

            return Result(host=task.host, result=f"Executed {len(tests_for_host)} pings")

        # Execute and log results
        agg = nr_filtered.run(
            name="L3 Neighbor Ping Validation",
            task=ping_neighbors,
            icmp_count=icmp_count,
            per_ping_timeout=per_ping_timeout,
        )

        # Summarize results in the job log
        total = 0
        successes = 0
        failures = 0

        for host_name, multi_result in agg.items():
            subtasks = list(multi_result)[1:]  # skip parent result
            planned = tests_by_host.get(host_name, [])
            for idx, sub in enumerate(subtasks):
                if not sub.name.startswith("PING "):
                    continue

                total += 1
                if idx < len(planned):
                    t = planned[idx]
                    desc = f"{t['family']} {host_name}({t['src_if_name']}) -> {t['dst_ip']} on {t['dst_dev_name']}({t['dst_if_name']})"
                else:
                    desc = sub.name

                ok = False
                data = sub.result
                if isinstance(data, dict):
                    if "success" in data and isinstance(data["success"], dict):
                        ok = data["success"].get("packet_loss") in (0, 0.0)
                    elif "packet_loss" in data:
                        ok = data.get("packet_loss") in (0, 0.0)

                if sub.failed:
                    failures += 1
                    self.logger.error(f"FAIL: {desc} - task failed: {sub.exception or sub.result}")
                elif ok:
                    successes += 1
                    self.logger.info(f"PASS: {desc}")
                else:
                    failures += 1
                    self.logger.error(f"FAIL: {desc} - ping result: {data}")

        self.logger.info(f"Summary: {successes}/{total} tests passed, {failures} failed.")
        if failures > 0:
            raise RuntimeError(f"{failures} ping tests failed.")


register_jobs(L3NeighborPingValidationNornir)