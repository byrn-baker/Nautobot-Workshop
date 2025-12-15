# jobs/auto_config_interface.py
import os
from ipaddress import ip_interface

from nautobot.apps.jobs import JobHookReceiver, register_jobs
from nautobot.dcim.models import Interface, Device


class AutoConfigureInterface(JobHookReceiver):
    """
    Interface-driven job that keeps Cisco/Arista device config in sync with Nautobot.

    Triggers: DCIM > Interface (Updated, Deleted)
    Behavior:
      * If the interface has any IPs (v4 and/or v6) in Nautobot, configure those IPs on the device.
      * Admin state: only 'no shutdown' if interface.enabled is True; otherwise 'shutdown' (even if IPs exist).
      * If the interface has no IPs, remove any IP config ('no ip address' / 'no ipv6 address') and 'shutdown'.

    Vendors: Cisco IOS/NX-OS and Arista EOS (uses Platform.network_driver)
    Connect: device.primary_ip4, else primary_ip6, else device.name
    """

    class Meta:
        name = "Auto Configure Interface (Interface-driven Cisco/Arista v4/v6)"
        description = "On Interface update/delete: set/remove IPv4/IPv6 and admin state (gates no-shut by enabled flag)."
        commit_default = True
        grouping = "JobHooks"

    # -----------------------
    # Helpers
    # -----------------------
    def _get_host_for_device(self, device):
        if device.primary_ip4:
            return str(device.primary_ip4.address.ip)
        if device.primary_ip6:
            return str(device.primary_ip6.address.ip)
        return device.name

    def _driver_family(self, driver):
        """
        Return 'cisco', 'arista', or None for unsupported.
        Accepts common variants.
        """
        d = (driver or "").lower().strip()
        if any(x in d for x in ("cisco_ios", "cisco_nxos", "cisco_xe", "ios", "nxos", "xe", "cisco")):
            return "cisco"
        if any(x in d for x in ("arista_eos", "eos", "arista")):
            return "arista"
        return None

    def _collect_first_ips(self, interface):
        """
        Return (ipv4_cidr_or_none, ipv6_cidr_or_none) from Interface.ip_addresses.
        Prefers the first address of each family.
        """
        v4 = None
        v6 = None
        for ip in interface.ip_addresses.all():
            if not getattr(ip, "address", None):
                continue
            ver = getattr(ip.address, "version", None)
            if ver == 4 and v4 is None:
                v4 = str(ip.address)
            elif ver == 6 and v6 is None:
                v6 = str(ip.address)
            if v4 and v6:
                break
        return v4, v6

    def _is_l3_capable_phys(self, if_name):
        """
        True for typical L2/L3 physical or aggregated ports that may need 'no switchport' for L3 config.
        Skip SVI (Vlan) and Loopback.
        """
        name = (if_name or "").lower()
        if name.startswith("vlan") or name.startswith("lo") or name.startswith("loopback"):
            return False
        return True

    def _build_cfg_from_state(self, driver, interface_name, v4_cidr, v6_cidr, enabled_flag):
        """
        Build config lines so device matches Nautobot state:
        - If any IP present (v4 and/or v6): add those IPs.
        - If no IPs: remove any existing IP config.
        - Admin state: 'no shutdown' only if enabled_flag is True; otherwise 'shutdown'.
        """
        fam = self._driver_family(driver)
        if fam is None:
            raise RuntimeError(f"Unsupported network_driver '{driver}'.")

        cfg = [f"interface {interface_name}"]
        has_any_ip = bool(v4_cidr or v6_cidr)

        # If adding IPs on a physical/port-channel, ensure routed mode
        if has_any_ip and self._is_l3_capable_phys(interface_name):
            cfg.append("no switchport")

        # IPv4
        if v4_cidr:
            v4 = ip_interface(v4_cidr)
            if fam == "cisco":
                cfg.append(f"ip address {v4.ip} {v4.netmask}")
            else:
                # Arista prefers prefix format for IPv4
                cfg.append(f"ip address {v4.ip}/{v4.network.prefixlen}")
        else:
            # Remove any IPv4 if none in Nautobot
            cfg.append("no ip address")

        # IPv6
        if v6_cidr:
            v6 = ip_interface(v6_cidr)
            if fam == "cisco":
                cfg.append(f"ipv6 address {v6.with_prefixlen}")
            else:
                # EOS commonly needs ipv6 enabled on the interface
                cfg.append("ipv6 enable")
                cfg.append(f"ipv6 address {v6.with_prefixlen}")
        else:
            cfg.append("no ipv6 address")

        # Admin state gated by 'enabled' boolean
        cfg.append("no shutdown" if enabled_flag and has_any_ip else "shutdown")
        return cfg

    def _build_cleanup_for_deleted_interface(self, driver, interface_name):
        """
        Best-effort cleanup when the Interface was deleted in Nautobot.
        Remove any IPs and shut the port.
        """
        fam = self._driver_family(driver)
        if fam is None:
            raise RuntimeError(f"Unsupported network_driver '{driver}'.")

        cfg = [f"interface {interface_name}"]
        cfg.append("no ip address")
        cfg.append("no ipv6 address")
        cfg.append("shutdown")
        return cfg

    def _connect(self, host, username, password, device_type):
        from netmiko import ConnectHandler
        return ConnectHandler(
            host=host,
            username=username,
            password=password,
            device_type=device_type,
            timeout=30,
        )

    def _norm_action(self, action):
        a = (action or "").lower()
        if a.startswith("creat"):
            return "create"
        if a.startswith("updat"):
            return "update"
        if a.startswith("delet"):
            return "delete"
        return a

    # -----------------------
    # Core
    # -----------------------
    def run(self, object_change=None, **kwargs):
        if object_change is None:
            raise RuntimeError("JobHookReceiver requires 'object_change' in kwargs.")

        ct = object_change.changed_object_type  # ContentType
        action = self._norm_action(getattr(object_change, "action", ""))
        obj_id = object_change.changed_object_id

        # Only handle DCIM.Interface events (Updated, Deleted)
        if not (ct.app_label == "dcim" and ct.model == "interface"):
            self.logger.info(f"Ignoring {ct.app_label}.{ct.model} action={action}; only DCIM.Interface is handled.")
            return "No changes."

        # Credentials
        username = (
            os.getenv("NET_USERNAME")
            or os.getenv("NAUTOBOT_NET_USERNAME")
            or os.getenv("NAPALM_USERNAME")
        )
        password = (
            os.getenv("NET_PASSWORD")
            or os.getenv("NAUTOBOT_NET_PASSWORD")
            or os.getenv("NAPALM_PASSWORD")
        )
        if not (username and password):
            raise RuntimeError("Set NET_USERNAME and NET_PASSWORD (or equivalent) for device access.")

        if action in ("update", "create"):
            # Interface exists in DB
            interface = Interface.objects.select_related("device__platform").get(id=obj_id)
            device = interface.device
            platform = device.platform
            driver = getattr(platform, "network_driver", None) if platform else None
            if not driver or self._driver_family(driver) is None:
                self.logger.warning(
                    f"Skipping {device.name} {interface.name}: unsupported or missing network_driver '{driver}'."
                )
                return "No changes."

            host = self._get_host_for_device(device)

            # Collect current desired addressing and admin state from Nautobot
            v4_cidr, v6_cidr = self._collect_first_ips(interface)
            enabled_flag = bool(getattr(interface, "enabled", True))

            cfg = self._build_cfg_from_state(driver, interface.name, v4_cidr, v6_cidr, enabled_flag)

            self.logger.info(
                f"Connecting to {device.name} ({host}) as {username}; driver '{driver}'. "
                f"Desired: v4={v4_cidr}, v6={v6_cidr}, enabled={enabled_flag}"
            )
            try:
                conn = self._connect(host, username, password, driver)
                self.logger.info(f"Sending configuration to {device.name}: {cfg}")
                output = conn.send_config_set(cfg)
                self.logger.info(output)
                # Save best-effort
                try:
                    save_output = conn.save_config()
                except Exception:
                    try:
                        save_output = conn.send_command_timing("write memory")
                    except Exception:
                        save_output = "Save not supported or failed."
                self.logger.info(f"Configuration saved on {device.name}. Output: {save_output}")
                conn.disconnect()
            except Exception as exc:
                self.logger.error(f"Failed to configure {device.name} {interface.name}: {exc}")
                raise

            state_desc = (
                f"{'IP set' if (v4_cidr or v6_cidr) else 'IP removed'}; "
                f"{'no shut' if (enabled_flag and (v4_cidr or v6_cidr)) else 'shutdown'}"
            )
            return f"Applied on {device.name} {interface.name}: {state_desc}"

        elif action == "delete":
            # Interface deleted: cleanup using object_data
            data = getattr(object_change, "object_data", {}) or {}
            if_name = data.get("name")
            device_id = data.get("device")
            if not if_name or not device_id:
                self.logger.warning("Interface delete missing 'name' or 'device' in object_data; skipping.")
                return "No changes."

            try:
                device = Device.objects.select_related("platform").get(id=device_id)
            except Device.DoesNotExist:
                self.logger.warning(f"Device {device_id} not found; skipping cleanup for deleted interface {if_name}.")
                return "No changes."

            driver = getattr(device.platform, "network_driver", None) if device.platform else None
            if not driver or self._driver_family(driver) is None:
                self.logger.warning(f"Skipping {device.name} {if_name}: unsupported or missing network_driver '{driver}'.")
                return "No changes."

            host = self._get_host_for_device(device)
            cfg = self._build_cleanup_for_deleted_interface(driver, if_name)

            self.logger.info(f"Connecting to {device.name} ({host}) as {username}; driver '{driver}' for delete cleanup")
            try:
                conn = self._connect(host, username, password, driver)
                self.logger.info(f"Sending cleanup to {device.name}: {cfg}")
                output = conn.send_config_set(cfg)
                self.logger.info(output)
                # Save best-effort
                try:
                    save_output = conn.save_config()
                except Exception:
                    try:
                        save_output = conn.send_command_timing("write memory")
                    except Exception:
                        save_output = "Save not supported or failed."
                self.logger.info(f"Cleanup saved on {device.name}. Output: {save_output}")
                conn.disconnect()
            except Exception as exc:
                self.logger.error(f"Failed cleanup on {device.name} {if_name}: {exc}")
                raise

            return f"Cleanup applied on {device.name} {if_name}: IPs removed; shutdown"

        else:
            self.logger.info(f"Ignoring interface action={action}; only update/create/delete handled.")
            return "No changes."


register_jobs(AutoConfigureInterface)