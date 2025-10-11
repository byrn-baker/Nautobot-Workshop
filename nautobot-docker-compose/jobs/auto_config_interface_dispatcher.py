"""
AutoConfigureInterfaceDispatcher JobHook
----------------------------------------
Interface-driven Nautobot JobHook using Nornir (nautobot-plugin-nornir 2.3.x).

Behavior:
- Pull interface data via saved GraphQL.
- Render intended interface config with Jinja2 and push via Netmiko.
- Retrieve FULL running-config once (dispatcher), then slice ONLY the target interface block.
- Clean/normalize Cisco outputs (remove headers/prompts, synthesize admin-state for diff).
- Normalize IOS command order to avoid false drift.
- Persist compliance against existing GoldenConfig 'intf' rule (no per-interface rules created).
- Send Discord alert with compact, accurate unified diff.
- INFO-level logging only (no ANSI banners).
"""

import json
import re
import requests
from difflib import unified_diff
from datetime import datetime
import os
from pathlib import Path
from time import sleep

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from custom_jinja_filters import netaddr_filters

from nautobot.apps.jobs import JobHookReceiver, register_jobs
from nautobot.dcim.models import Interface, Device
from nautobot.extras.models import ExternalIntegration, GraphQLQuery
from nautobot_golden_config.models import ComplianceRule, ConfigCompliance

from nornir import InitNornir
from nornir.core.plugins.inventory import InventoryPluginRegister
from nornir.core.filter import F
from nornir.core.task import MultiResult, Result
from nornir_netmiko.tasks import netmiko_send_config, netmiko_send_command
from nautobot_plugin_nornir.plugins.inventory.nautobot_orm import NautobotORMInventory
from nornir_nautobot.plugins.tasks.dispatcher import dispatcher

from types import SimpleNamespace
from django.contrib.auth import get_user_model
from graphene_django.settings import graphene_settings
from graphql import get_default_backend

GQL_QUERY_NAME = "interface_config_template_query"
BASE_DIR = Path(__file__).resolve().parent

TEMPLATE_CANDIDATES = [
    BASE_DIR / "templates",
    Path("/opt/nautobot/jobs/templates"),
    Path("./templates"),
]
templates_root = next((p for p in TEMPLATE_CANDIDATES if (p / "platforms").exists()), BASE_DIR / "templates")
templates_root = os.getenv("NAUTOBOT_JOB_TEMPLATES_DIR", str(templates_root))


class AutoConfigureInterfaceDispatcher(JobHookReceiver):
    """Synchronize Nautobot interface intent to device config and track compliance."""

    class Meta:
        name = "Auto Configure Interface (Dispatcher + Compliance + Alerts)"
        description = (
            "Synchronizes Nautobot interface state to devices via Nornir, "
            "runs compliance diff checks, and sends Discord alerts on drift."
        )
        commit_default = True
        grouping = "JobHooks"

    # -----------------------------
    # Platform helpers
    # -----------------------------
    def _is_cisco(self, device) -> bool:
        pname = (getattr(device.platform, "name", "") or "").lower()
        pdrv = (getattr(device.platform, "network_driver", "") or "").lower()
        return any(s in pname for s in ("ios", "nx-os", "nxos")) or any(s in pdrv for s in ("ios", "nxos"))

    # -----------------------------
    # Running-config cleaning & slicing
    # -----------------------------
    _HEADER_PATTERNS = (
        re.compile(r"^Building\s+configuration.*$", re.I),
        re.compile(r"^Current\s+configuration\s*:.*$", re.I),
    )
    _PROMPT_PATTERN = re.compile(r"^[\w\-.()/#\s]+#$")
    _END_PATTERN = re.compile(r"^end$", re.I)

    def _clean_running_text(self, text: str) -> list[str]:
        """Remove headers, prompts, stray 'end' lines."""
        lines = [ln.rstrip() for ln in (text or "").splitlines()]
        cleaned = []
        for ln in lines:
            if not ln.strip():
                continue
            if any(p.search(ln) for p in self._HEADER_PATTERNS):
                continue
            if self._PROMPT_PATTERN.match(ln.strip()):
                continue
            if self._END_PATTERN.match(ln.strip()):
                continue
            cleaned.append(ln)
        return cleaned

    def _slice_interface_block(self, lines: list[str], ifname: str) -> list[str]:
        """Return only interface <ifname> block."""
        try:
            start = lines.index(f"interface {ifname}")
        except ValueError:
            return []
        end = next(
            (i for i, l in enumerate(lines[start + 1:], start=start + 1)
             if l.startswith("interface ") or l.strip() == "!"),
            len(lines),
        )
        return lines[start:end]

    def _canonicalize_indent(self, lines: list[str]) -> list[str]:
        out = []
        for ln in lines:
            s = ln.strip()
            if s.startswith("interface "):
                out.append(s)
            elif s == "!":
                out.append("!")
            else:
                out.append(f"  {s}")
        return out

    def _normalize_admin_state(self, ifname: str, lines: list[str], enabled: bool, is_cisco: bool) -> list[str]:
        """Inject synthetic admin-state for Cisco."""
        if not is_cisco or not lines:
            return lines
        content = [ln for ln in lines[1:]]
        has_any = any(ln.strip() in ("shutdown", "no shutdown") for ln in content)
        if has_any:
            return lines
        injected = "  no shutdown" if enabled else "  shutdown"
        if lines and lines[-1].strip() == "!":
            return lines[:-1] + [injected, "!"]
        return lines + [injected]

    # -----------------------------
    # IOS ordering normalization
    # -----------------------------
    def _normalize_interface_order(self, lines: list[str]) -> list[str]:
        """Normalize IOS interface block ordering to prevent false drift."""
        if not lines or not lines[0].startswith("interface "):
            return lines
        header = lines[0]
        body = [ln for ln in lines[1:] if ln.strip() and ln.strip() != "!"]
        footer = ["!"] if lines and lines[-1].strip() == "!" else []
        def sort_key(line):
            l = line.strip()
            if l.startswith("description"):
                return "00_description"
            if l.startswith("ip address"):
                return "01_ip_address"
            if l.startswith("ipv6 address"):
                return "02_ipv6_address"
            if l.startswith("ipv6 enable"):
                return "03_ipv6_enable"
            if l.startswith("ip ospf network"):
                return "10_ospf_nettype"
            if l.startswith("ip ospf "):
                return "11_ospf_v4"
            if l.startswith("mpls ip"):
                return "12_mpls"
            if l.startswith("ipv6 ospf"):
                return "13_ospf_v6"
            if l.startswith("no shutdown") or l.startswith("shutdown"):
                return "99_admin"
            return l
        sorted_body = sorted(body, key=sort_key)
        return [header] + sorted_body + footer

    # -----------------------------
    # GraphQL + Jinja rendering
    # -----------------------------
    def _collect_first_ips(self, interface):
        v4, v6 = None, None
        for ip in interface.ip_addresses.all():
            if not getattr(ip, "address", None):
                continue
            if ip.address.version == 4 and not v4:
                v4 = str(ip.address)
            elif ip.address.version == 6 and not v6:
                v6 = str(ip.address)
        return v4, v6

    def _build_intended_config(self, interface, v4, v6, enabled):
        gql_query = GraphQLQuery.objects.get(name=GQL_QUERY_NAME)
        backend = get_default_backend()
        schema = graphene_settings.SCHEMA
        variables = {"id": str(interface.id)}
        User = get_user_model()
        active_user = User.objects.filter(username="admin").first() or User.objects.first()
        context = SimpleNamespace(user=active_user)
        document = backend.document_from_string(schema, gql_query.query)
        result = document.execute(context_value=context, variable_values=variables)
        if result.errors:
            raise RuntimeError(f"GraphQL execution failed: {result.errors}")
        gql_interface = result.data.get("interface")
        if not gql_interface:
            raise RuntimeError(f"No interface data returned for {interface.name}")
        platform_name = interface.device.platform.name.lower() if interface.device and interface.device.platform else "generic"
        env = Environment(loader=FileSystemLoader(templates_root),
                          trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined)
        env.filters["ipaddr"] = netaddr_filters.ipaddr
        template = env.get_template("interface_config.j2")
        rendered = template.render(interface=gql_interface, ipv4=v4, ipv6=v6,
                                   enabled=enabled, platform_name=platform_name)
        raw_lines = [ln for ln in rendered.splitlines() if ln.strip()]
        return self._canonicalize_indent(raw_lines)

    # -----------------------------
    # GoldenConfig persistence
    # -----------------------------
    def _persist_compliance(self, device, diff_output, intended_text, running_text):
        rule = ComplianceRule.objects.filter(feature__name__iexact="intf",
                                             platform=device.platform).first()
        if not rule:
            self.logger.info(
                f"No GoldenConfig 'intf' rule found for {device.platform}, skipping compliance.")
            return None
        missing_lines = "\n".join(l[1:] for l in diff_output.splitlines()
                                  if l.startswith("+") and not l.startswith("+++"))
        extra_lines = "\n".join(l[1:] for l in diff_output.splitlines()
                                if l.startswith("-") and not l.startswith("---"))
        compliance, created = ConfigCompliance.objects.get_or_create(
            device=device,
            rule=rule,
            defaults={
                "compliance": not bool(diff_output.strip()),
                "actual": running_text,
                "intended": intended_text,
                "missing": missing_lines,
                "extra": extra_lines,
            },
        )
        if not created:
            compliance.compliance = not bool(diff_output.strip())
            compliance.actual = running_text
            compliance.intended = intended_text
            compliance.missing = missing_lines
            compliance.extra = extra_lines
            compliance.save()
        return compliance

    # -----------------------------
    # Cleanup helpers
    # -----------------------------
    def _strip_extraneous_bang_lines(self, lines):
        cleaned = []
        for line in lines:
            if line.strip() == "!" and (not cleaned or cleaned[-1].strip() == "!"):
                continue
            cleaned.append(line)
        while cleaned and cleaned[0].strip() == "!":
            cleaned.pop(0)
        while cleaned and cleaned[-1].strip() == "!":
            cleaned.pop(-1)
        return cleaned

    def _strip_non_persistent_ios_lines(self, lines):
        skip_patterns = (re.compile(r"^no ipv6 (address|enable)$", re.I),)
        return [l for l in lines if not any(p.match(l.strip()) for p in skip_patterns)]

    def _compute_diff(self, intended, running):
        return "\n".join(unified_diff(
            running, intended, fromfile="running_config",
            tofile="intended_config", lineterm=""
        ))

    # -----------------------------
    # Discord helpers
    # -----------------------------
    def _get_discord_webhook(self):
        try:
            integration = ExternalIntegration.objects.get(
                name__iexact="Discord Compliance Alerts"
            )
        except ExternalIntegration.DoesNotExist:
            return None
        return integration.remote_url or None

    def _send_discord_alert(self, webhook_url, device, interface, diff_output):
        payload = {
            "username": "Nautobot Compliance Bot",
            "embeds": [{
                "title": f"⚠️ Configuration Drift Detected: {device.name} {interface}",
                "description": (
                    f"**Device:** {device.name}\n"
                    f"**Interface:** {interface}\n"
                    f"**Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                    f"```diff\n{diff_output[:1900]}\n```"
                ),
                "color": 16734296,
                "footer": {"text": "Nautobot JobHook Compliance Monitor"},
            }],
        }
        try:
            r = requests.post(webhook_url, json=payload, timeout=10)
            if r.status_code not in (200, 204):
                self.logger.info(f"Discord webhook returned {r.status_code}: {r.text}")
        except Exception as e:
            self.logger.info(f"Discord webhook error: {e}")

    # -----------------------------
    # Main
    # -----------------------------
    def run(self, object_change=None, **kwargs):
        if not object_change:
            raise RuntimeError("JobHookReceiver requires 'object_change'.")

        action = (object_change.action or "").lower()
        if not any(x in action for x in ("create", "update", "delete")):
            self.logger.info("Ignoring non-mutation object_change action.")
            return "No operation."

        device, name, enabled, intended_cfg = None, None, False, []
        nr = None
        discord_webhook = self._get_discord_webhook()

        try:
            # Build intended config
            if action in ("create", "update"):
                interface = Interface.objects.select_related(
                    "device__platform").get(id=object_change.changed_object_id)
                device = interface.device
                v4, v6 = self._collect_first_ips(interface)
                enabled = bool(interface.enabled)
                name = interface.name
                intended_cfg = self._build_intended_config(interface, v4, v6, enabled)
            else:
                data = object_change.object_data or {}
                device = Device.objects.filter(id=data.get("device")).first()
                name = data.get("name")
                if not device or not name:
                    self.logger.info("Delete event missing device/name; nothing to do.")
                    return "No changes."
                intended_cfg = self._canonicalize_indent(
                    [f"interface {name}", "no ip address", "no ipv6 address", "shutdown", "!"])

            intended_text = "\n".join(intended_cfg)
            self.logger.info(f"Intended configuration prepared for {device.name} {name}")

            # Init Nornir
            try:
                InventoryPluginRegister.register("nautobot-inventory", NautobotORMInventory)
            except Exception:
                pass
            nr = InitNornir(inventory={
                "plugin": "nautobot-inventory",
                "options": {"queryset": Device.objects.filter(name=device.name)}
            })
            target = nr.filter(F(name=device.name))
            if not target.inventory.hosts:
                raise RuntimeError(f"Device '{device.name}' not found in Nornir inventory.")

            # Push intended config
            config_block = [line for line in intended_cfg if line.strip()]
            if config_block:
                _ = target.run(
                    task=netmiko_send_config,
                    name=f"Push Interface Configuration ({name})",
                    config_commands=config_block,
                )
                self.logger.info(f"Pushed interface configuration to {device.name}:{name}")
                sleep(2)
                nr.close_connections()

            # Retrieve FULL running config via dispatcher
            full = target.run(
                task=dispatcher,
                obj=device,
                logger=self.logger,
                method="get_config",
                framework="netmiko",
                backup_file=None,
                remove_lines=[{"regex": r"^Building\\s+configuration.*\\n"}],
                substitute_lines=[{"regex": r"^(enable (password|secret)( level \\d+)? \\d) .+$",
                                   "replace": r"\\1 <removed>"}],
            )

            # Extract text
            host = next(iter(full.keys()))
            host_result = full[host]
            running_config = ""
            if isinstance(host_result, MultiResult):
                for r in host_result:
                    if isinstance(r.result, dict) and "running" in r.result:
                        running_config = r.result["running"] or ""
                        break
                if not running_config:
                    for r in host_result:
                        if isinstance(r.result, str):
                            running_config = r.result or ""
                            break
            elif isinstance(host_result, Result):
                if isinstance(host_result.result, dict) and "running" in host_result.result:
                    running_config = host_result.result["running"] or ""
                elif isinstance(host_result.result, str):
                    running_config = host_result.result or ""

            cleaned = self._clean_running_text(running_config)
            running_block = self._slice_interface_block(cleaned, name)
            if not running_block:
                self.logger.info(f"Interface {name} not found; falling back to 'show run interface'.")
                fb = target.run(task=netmiko_send_command,
                                command_string=f"show running-config interface {name}")
                fb_text = next(iter(fb.values())).result or ""
                running_block = self._clean_running_text(fb_text)

            running_block = self._canonicalize_indent(running_block)
            running_block = self._normalize_admin_state(name, running_block, enabled, self._is_cisco(device))
            running_block = self._strip_non_persistent_ios_lines(running_block)
            intended_cfg = self._strip_non_persistent_ios_lines(intended_cfg)
            running_block = self._strip_extraneous_bang_lines(running_block)
            intended_cfg = self._strip_extraneous_bang_lines(intended_cfg)

            # Normalize IOS command order before diff
            running_block = self._normalize_interface_order(running_block)
            intended_cfg = self._normalize_interface_order(intended_cfg)

            running_text = "\n".join(running_block)
            diff_output = self._compute_diff(intended_cfg, running_block)
            drift_detected = bool(diff_output.strip())

            _ = self._persist_compliance(device, diff_output, intended_text, running_text)
            self.logger.info(f"{device.name} {name} compliance: {'❌ Drift' if drift_detected else '✅ Compliant'}")

            if drift_detected and discord_webhook:
                self._send_discord_alert(discord_webhook, device, name, diff_output)

            return f"Interface {name} on {device.name}: action={action}, compliance={not drift_detected}"
        finally:
            if nr:
                nr.close_connections()


register_jobs(AutoConfigureInterfaceDispatcher)
