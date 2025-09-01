from collections import defaultdict
import re

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
from nornir_napalm.plugins.tasks import napalm_ping, napalm_get, napalm_cli

# Register the ORM inventory plugin under a known name (no URL/token needed)
try:
    InventoryPluginRegister.register("nautobot-inventory", NautobotORMInventory)
except Exception:
    pass


class IGPProviderLoopbackValidation(Job):
    """
    Validate IGP by:
      1) Ensuring each selected 'provider' loopback appears in the OSPF routing table.
      2) Pinging each provider loopback from the local device's loopback IP.

    Includes IPv6 CLI fallback for route checks and enhanced logging.
    Returns results under result.result.results.igp_validation so templates can render a tab.
    """

    class Meta:
        name = "IGP Provider Loopback Validation (Nornir)"
        description = "Verify provider loopbacks are learned via OSPF and reachable from local loopback. Includes IPv6 CLI fallback and table report."
        commit_default = False

    # Scope for source devices (where we run checks from)
    sites = MultiObjectVar(
        model=Location,
        query_params={"location_type": "Site"},
        required=False,
        label="Limit Source Devices to Sites",
    )
    roles = MultiObjectVar(
        model=Role,
        query_params={"content_types": ["dcim.device"]},
        required=False,
        label="Limit Source Devices to Roles",
    )

    # Which devices define the 'provider' loopbacks we must see/reach
    provider_roles = MultiObjectVar(
        model=Role,
        query_params={"content_types": ["dcim.device"]},
        required=False,
        label="Provider Device Roles (loopbacks to validate)",
        description="If unset, all source devices are treated as providers (i.e., validate all loopbacks in scope).",
    )

    loopback_name = StringVar(
        default="Loopback0",
        label="Loopback Interface Name",
        description="Interface name containing the loopback IP on both source and provider devices.",
    )

    ipv6 = BooleanVar(default=False, label="Validate IPv6")
    vrf = StringVar(
        required=False,
        label="VRF (optional)",
        description="If set, use this VRF for ping and (where supported) for route lookup.",
    )
    count = IntegerVar(default=3, min_value=1, max_value=20, label="ICMP Count")
    timeout = IntegerVar(default=2, min_value=1, max_value=10, label="Per-ping Timeout (seconds)")

    # Optional: allow skipping IPv6 route validation if platform/driver lacks support
    skip_ipv6_route_check = BooleanVar(
        default=False,
        label="Skip IPv6 Route Validation",
        description="If enabled, IPv6 route checks are skipped (ping-only for IPv6).",
    )

    def _get_first_ip_on_interface(self, iface: Interface, want_ipv6: bool):
        for ip in iface.ip_addresses.all().order_by("pk"):
            host_ip = ip.address.ip
            if (host_ip.version == 6) == want_ipv6:
                return ip  # return the IPAddress object
        return None

    def _get_loopback_ip(self, device: Device, loopback_name: str, want_ipv6: bool):
        iface = device.interfaces.filter(name=loopback_name).prefetch_related("ip_addresses").first()
        if not iface:
            return None
        return self._get_first_ip_on_interface(iface, want_ipv6=want_ipv6)

    def _collect_provider_targets(self, devices_qs, loopback_name: str, want_ipv6: bool):
        targets = []
        for dev in devices_qs:
            ip_obj_v4 = self._get_loopback_ip(dev, loopback_name, want_ipv6=False)
            if ip_obj_v4:
                targets.append(
                    {
                        "dst_dev_name": dev.name,
                        "dst_ip_str": str(ip_obj_v4.address.ip),
                        "dst_prefix": str(ip_obj_v4.address),
                        "family": "IPv4",
                    }
                )
            if want_ipv6:
                ip_obj_v6 = self._get_loopback_ip(dev, loopback_name, want_ipv6=True)
                if ip_obj_v6:
                    targets.append(
                        {
                            "dst_dev_name": dev.name,
                            "dst_ip_str": str(ip_obj_v6.address.ip),
                            "dst_prefix": str(ip_obj_v6.address),
                            "family": "IPv6",
                        }
                    )
        return targets

    def run(self, *, sites, roles, provider_roles, loopback_name, ipv6, vrf, count, timeout, skip_ipv6_route_check):
        self.logger.info("Starting IGP Provider Loopback Validation.")
        want_ipv6 = bool(ipv6)
        icmp_count = int(count)
        per_ping_timeout = int(timeout)
        vrf_name = (vrf or "").strip() or None
        skip_ipv6_routes = bool(skip_ipv6_route_check)

        # Base queryset for source devices
        src_devices = Device.objects.filter(status__name="Active")
        if sites:
            src_devices = src_devices.filter(location__in=sites)
        if roles:
            src_devices = src_devices.filter(role__in=roles)

        # Determine providers (devices whose loopbacks we must see/reach)
        if provider_roles:
            provider_devices = Device.objects.filter(status__name="Active", role__in=provider_roles)
            if sites:
                provider_devices = provider_devices.filter(location__in=sites)
        else:
            provider_devices = src_devices

        # Prefetch once
        src_devices = src_devices.prefetch_related("interfaces__ip_addresses", "platform").distinct()
        provider_devices = provider_devices.prefetch_related("interfaces__ip_addresses").distinct()

        if not src_devices.exists():
            self.logger.warning("No source devices found for the selected scope.")
            return {"results": {"igp_validation": {"columns": [], "rows": [], "summary": {"total": 0, "passes": 0, "fails": 0}}}}

        # Build provider targets
        provider_targets = self._collect_provider_targets(provider_devices, loopback_name, want_ipv6=want_ipv6)
        if not provider_targets:
            self.logger.warning("No provider loopback targets found (check roles/loopback name/IPs).")
            return {"results": {"igp_validation": {"columns": [], "rows": [], "summary": {"total": 0, "passes": 0, "fails": 0}}}}

        # Build per-host test plan
        tests_by_host = defaultdict(list)
        napalm_driver_by_host = {}
        for dev in src_devices:
            local_v4 = self._get_loopback_ip(dev, loopback_name, want_ipv6=False)
            local_v6 = self._get_loopback_ip(dev, loopback_name, want_ipv6=True) if want_ipv6 else None
            local_ip_by_family = {
                "IPv4": str(local_v4.address.ip) if local_v4 else None,
                "IPv6": str(local_v6.address.ip) if local_v6 else None,
            }
            napalm_driver_by_host[dev.name] = getattr(getattr(dev, "platform", None), "napalm_driver", None)

            for tgt in provider_targets:
                if tgt["dst_dev_name"] == dev.name:
                    continue
                src_ip = local_ip_by_family.get(tgt["family"])
                if not src_ip:
                    self.logger.error(
                        "Device %s missing %s loopback IP on %s; cannot test targets in this family.",
                        dev.name,
                        tgt["family"],
                        loopback_name,
                    )
                    continue

                tests_by_host[dev.name].append(
                    {
                        "family": tgt["family"],
                        "src_dev_name": dev.name,
                        "src_ip": src_ip,
                        "dst_dev_name": tgt["dst_dev_name"],
                        "dst_ip": tgt["dst_ip_str"],
                        "dst_prefix": tgt["dst_prefix"],
                    }
                )

        if not tests_by_host:
            self.logger.warning("No eligible tests generated (missing loopbacks or no cross-device targets).")
            return {"results": {"igp_validation": {"columns": [], "rows": [], "summary": {"total": 0, "passes": 0, "fails": 0}}}}

        # Initialize Nornir
        nr = InitNornir(
            logging={"enabled": False},
            runner={"options": {"num_workers": 20}},
            inventory={
                "plugin": "nautobot-inventory",
                "options": {
                    "credentials_class": "nautobot_plugin_nornir.plugins.credentials.env_vars.CredentialsEnvVars",
                    "queryset": src_devices,
                },
            },
        )

        target_hostnames = list(tests_by_host.keys())
        nr_filtered = nr.filter(F(name__in=target_hostnames))
        for host_name, tests in tests_by_host.items():
            if host_name in nr_filtered.inventory.hosts:
                nr_filtered.inventory.hosts[host_name].data["tests_for_host"] = tests
                nr_filtered.inventory.hosts[host_name].data["napalm_driver"] = napalm_driver_by_host.get(host_name)

        if not nr_filtered.inventory.hosts:
            self.logger.warning("No Nornir hosts found after filtering.")
            return {"results": {"igp_validation": {"columns": [], "rows": [], "summary": {"total": 0, "passes": 0, "fails": 0}}}}

        # Helpers for route checks
        def _ospf_route_check_via_napalm_get(task: Task, dst_prefix: str, vrf_name: str | None) -> tuple[bool, list]:
            getters = ["get_route_to"]
            getters_options = {"get_route_to": {"destination": dst_prefix}}
            if vrf_name:
                getters_options["get_route_to"]["vrf"] = vrf_name
            r = task.run(name=f"ROUTE napalm_get {dst_prefix}", task=napalm_get, getters=getters, getters_options=getters_options)
            route_data = r.result.get("get_route_to", {})
            routes = route_data.get(dst_prefix)
            if routes is None and route_data:
                routes = next(iter(route_data.values()))
            routes = routes or []
            ok = False
            for entry in routes:
                prot = str(entry.get("protocol", "")).lower()
                active = bool(entry.get("current_active"))
                if active and "ospf" in prot:
                    ok = True
                    break
            return ok, routes

        def _ospf_route_check_via_cli(task: Task, family: str, dst_prefix: str, vrf_name: str | None) -> tuple[bool, str]:
            is_v6 = (family == "IPv6")
            base = "show ipv6 route" if is_v6 else "show ip route"
            cmd = f"{base} {('vrf ' + vrf_name + ' ') if vrf_name else ''}{dst_prefix}"
            res = task.run(name=f"ROUTE cli {dst_prefix}", task=napalm_cli, commands=[cmd])
            out = res.result.get(cmd, "") if isinstance(res.result, dict) else str(res.result)
            text = str(out)
            low = text.lower()
            if dst_prefix.split("/")[0] not in low and dst_prefix not in low:
                return False, text
            ospf_hit = ("ospf" in low)
            code_hit = False
            code_patterns = [
                r"^\s*o[ a-z0-9]*\s+.*" + re.escape(dst_prefix.split("/")[0]),
                r"^\s*o[ a-z0-9]*\s+" + re.escape(dst_prefix),
            ]
            for pat in code_patterns:
                if re.search(pat, text, flags=re.IGNORECASE | re.MULTILINE):
                    code_hit = True
                    break
            ok = bool(ospf_hit or code_hit)
            return ok, text

        # Per-host task with enhanced logging and table-row building
        def verify_igp_to_providers(task: Task, icmp_count: int, per_ping_timeout: int) -> Result:
            tests_for_host = task.host.data.get("tests_for_host", [])
            composite_results = []
            table_rows = []

            # Per-source tracking
            success_rows = []
            fail_rows = []
            success_dst_devices = set()
            failed_dst_devices = set()

            for test in tests_for_host:
                desc = f"{test['family']} {task.host.name}(lo) -> {test['dst_ip']} on {test['dst_dev_name']}(lo)"

                # Route check (with IPv6-aware fallback)
                route_ok = False
                route_method = None
                if test["family"] == "IPv6" and bool(skip_ipv6_routes):
                    self.logger.info("OSPF SKIP: %s - IPv6 route validation skipped by setting.", desc)
                    route_ok = None  # None means skipped
                    route_method = "SKIP"
                else:
                    try:
                        ok, routes = _ospf_route_check_via_napalm_get(task, test["dst_prefix"], vrf_name)
                        route_ok, route_method = ok, "napalm_get"
                        if not ok:
                            self.logger.warning("OSPF MISS: %s - no active OSPF route via napalm_get; attempting CLI fallback.", desc)
                            try:
                                ok_cli, _text = _ospf_route_check_via_cli(task, test["family"], test["dst_prefix"], vrf_name)
                                route_ok, route_method = ok_cli, "cli"
                            except Exception as e_cli:
                                self.logger.error("OSPF FAIL: %s - CLI fallback error: %s", desc, e_cli)
                    except Exception as e_get:
                        self.logger.warning("OSPF WARN: %s - napalm_get error: %s; trying CLI fallback.", desc, e_get)
                        try:
                            ok_cli, _text = _ospf_route_check_via_cli(task, test["family"], test["dst_prefix"], vrf_name)
                            route_ok, route_method = ok_cli, "cli"
                        except Exception as e_cli2:
                            self.logger.error("OSPF FAIL: %s - route lookup error (CLI fallback): %s", desc, e_cli2)

                # Ping check from local loopback
                ping_ok = False
                try:
                    kwargs = {
                        "dest": test["dst_ip"],
                        "source": test["src_ip"],
                        "count": icmp_count,
                        "timeout": per_ping_timeout,
                    }
                    if vrf_name:
                        kwargs["vrf"] = vrf_name
                    p = task.run(name=f"PING {desc}", task=napalm_ping, **kwargs)
                    data = p.result
                    if isinstance(data, dict):
                        if "success" in data and isinstance(data["success"], dict):
                            ping_ok = data["success"].get("packet_loss") in (0, 0.0)
                        elif "packet_loss" in data:
                            ping_ok = data.get("packet_loss") in (0, 0.0)
                    if not ping_ok:
                        self.logger.error("PING FAIL: %s - result: %s", desc, data)
                except Exception as e:
                    self.logger.error("PING FAIL: %s - ping error: %s", desc, e)

                # Final verdict (both must pass; unless route check skipped for IPv6)
                if test["family"] == "IPv6" and skip_ipv6_routes:
                    final_ok = bool(ping_ok)
                else:
                    final_ok = bool(route_ok) and bool(ping_ok)

                # Enhanced PASS/FAIL logs
                if final_ok:
                    self.logger.info(
                        "SUCCESS: %s -> %s (%s) [%s -> %s]",
                        task.host.name,
                        test["dst_dev_name"],
                        test["family"],
                        test["src_ip"],
                        test["dst_ip"],
                    )
                    success_rows.append(test)
                    success_dst_devices.add(test["dst_dev_name"])
                else:
                    self.logger.error(
                        "FAIL: %s -> %s (%s) [%s -> %s] (route_ok=%s, ping_ok=%s)",
                        task.host.name,
                        test["dst_dev_name"],
                        test["family"],
                        test["src_ip"],
                        test["dst_ip"],
                        route_ok,
                        ping_ok,
                    )
                    fail_rows.append(test)
                    failed_dst_devices.add(test["dst_dev_name"])

                composite_results.append(
                    {
                        "desc": desc,
                        "route_ok": route_ok,
                        "ping_ok": ping_ok,
                        "final_ok": final_ok,
                    }
                )

                # Build a row for the HTML report
                table_rows.append(
                    {
                        "source_device": test["src_dev_name"],
                        "source_ip": test["src_ip"],
                        "target_device": test["dst_dev_name"],
                        "target_ip": test["dst_ip"],
                        "target_prefix": test["dst_prefix"],
                        "family": test["family"],
                        "vrf": vrf_name or "",
                        "route_method": route_method or "",
                        "route_status": "SKIP" if route_ok is None else ("PASS" if route_ok else "FAIL"),
                        "ping_status": "PASS" if ping_ok else "FAIL",
                        "result": "PASS" if final_ok else "FAIL",
                    }
                )

            # Per-source rollup logs
            total_per_host = len(tests_for_host)
            succ = len(success_rows)
            if succ:
                success_list = ", ".join(sorted(success_dst_devices))
                if succ == total_per_host:
                    self.logger.info("SUMMARY SUCCESS: %s reached all %s targets: %s", task.host.name, succ, success_list)
                else:
                    self.logger.info("SUMMARY SUCCESS: %s reached %s/%s targets: %s", task.host.name, succ, total_per_host, success_list)
            if fail_rows:
                fail_list = ", ".join(sorted(failed_dst_devices))
                self.logger.error("SUMMARY FAIL: %s had failures to %s/%s targets: %s", task.host.name, len(fail_rows), total_per_host, fail_list)

            task.host.data["composite_results"] = composite_results
            task.host.data["table_rows"] = table_rows
            return Result(host=task.host, result=f"Executed {len(tests_for_host)} provider checks")

        # Execute
        agg = nr_filtered.run(
            name="IGP Provider Loopback Validation",
            task=verify_igp_to_providers,
            icmp_count=icmp_count,
            per_ping_timeout=per_ping_timeout,
        )

        # Summarize and collect rows
        total = 0
        passes = 0
        fails = 0
        all_rows = []
        for host_name, _multi_result in agg.items():
            host_obj = nr_filtered.inventory.hosts.get(host_name)
            rows = host_obj.data.get("table_rows", []) if host_obj else []
            total += len(rows)
            for r in rows:
                if r.get("result") == "PASS":
                    passes += 1
                else:
                    fails += 1
            all_rows.extend(rows)

        # Build payload for JobResult.data['results']['igp_validation']
        report_payload = {
            "columns": [
                "Source Device",
                "Src Loopback",
                "Target Device",
                "Target Loopback",
                "Family",
                "VRF",
                "Route Check",
                "Ping",
                "Result",
            ],
            "rows": [
                {
                    "Source Device": r["source_device"],
                    "Src Loopback": r["source_ip"],
                    "Target Device": r["target_device"],
                    "Target Loopback": f"{r['target_ip']} ({r['target_prefix']})",
                    "Family": r["family"],
                    "VRF": r["vrf"],
                    "Route Check": f"{r['route_status']}{'/' + r['route_method'] if r['route_method'] else ''}",
                    "Ping": r["ping_status"],
                    "Result": r["result"],
                }
                for r in all_rows
            ],
            "summary": {"total": total, "passes": passes, "fails": fails},
        }

        # Persist under data['results']['igp_validation'] so returning + failure still shows data
        try:
            self.job_result.data_update({"results": {"igp_validation": report_payload}})
        except Exception:
            try:
                data = getattr(self.job_result, "data", {}) or {}
                results_key = data.get("results") or {}
                results_key["igp_validation"] = report_payload
                data["results"] = results_key
                self.job_result.data = data
                self.job_result.save()
            except Exception as e:
                self.logger.error("Could not persist report data to JobResult: %s", e)

        self.logger.info(f"Summary: {passes}/{total} checks passed, {fails} failed.")

        # Optionally mark failure while still returning results for UI
        if fails > 0:
            # Return results AND raise to mark job failed
            # Nautobot will keep data because we wrote it via data_update; return also includes it.
            return {"results": {"igp_validation": report_payload}}
        return {"results": {"igp_validation": report_payload}}


register_jobs(IGPProviderLoopbackValidation)