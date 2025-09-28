# jobs/software_cve_discovery.py
#
# Vendor CVE Discovery Job using NAPALM for software discovery.
# - Select Devices and the Secrets Group to use
# - Uses Platform Name (not slug)
# - Discovers software versions on Cisco/Arista via NAPALM get_facts()
# - Fetches Cisco PSIRT advisories via OAuth2 (Client Credentials) using env vars:
#       CISCO_CLIENT_ID, CISCO_CLIENT_SECRET
# - Uses Cisco Software Checker v2 endpoints at apix.cisco.com with proper OSType paths
# - Scrapes Arista security advisories page for matching versions
# - Persists results to DLM v2.x:
#     - CVELCM rows keyed by name=<CVE-ID>, populating CVE fields,
#       and associating CVE to the Affected Software (not platform).
#     - VulnerabilityLCM rows linked to the correct software model expected by your DLM version
#       (software=<instance resolved dynamically; SoftwareLCM / SoftwareImageLCM / other>).
# - Optional: Pull Cisco EoX/Hardware Notices and populate HardwareLCM for device types.
#
# Dry-run support:
# - Uses run(self, data, commit, **kwargs) with a DryRunVar.
# - Effective commit = commit and not dry_run.
# - In dry-run, only logs intended changes; no DB writes.
#
# Logging uses self.logger.info/warning/error.

import os
import re
import requests
from datetime import date, datetime
from types import SimpleNamespace

from bs4 import BeautifulSoup

from nautobot.apps.jobs import Job, MultiObjectVar, ObjectVar, DryRunVar, BooleanVar, register_jobs
from nautobot.dcim.models import Device, Platform
from nautobot.extras.models import Status, SecretsGroup
from nautobot.extras.choices import (
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)

from nautobot_device_lifecycle_mgmt.models import (
    SoftwareLCM,           # platform + version
    CVELCM,
    VulnerabilityLCM,      # software FK points to a model that varies by DLM version
    HardwareLCM
)

from napalm import get_network_driver


class VendorCVEDiscoveryJob(Job):
    """Discover software via NAPALM, fetch vendor CVEs, and update DLM models."""

    devices = MultiObjectVar(
        model=Device,
        required=False,
        description="Select devices to process (optional). If empty, the job will process all Active devices.",
    )

    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=True,
        description="Secrets Group providing device credentials. Associations for username and password are recommended.",
    )

    dry_run = DryRunVar(
        description="Enable dry run mode to preview changes without committing them."
    )

    include_hardware_notices = BooleanVar(
        description="Pull Cisco EoX (End-of-Sale/Support/Software/Security) and update HardwareLCM for device types.",
        default=False,
        required=False,
    )

    class Meta:
        name = "Vendor CVE Discovery (NAPALM)"
        description = "Discover software, fetch CVEs (Cisco/Arista), and optionally EoX hardware notices; update DLM models"
        read_only = False
        field_order = ("devices", "secrets_group", "include_hardware_notices", "dry_run")

    # ---------------------
    # Secrets helpers
    # ---------------------
    @staticmethod
    def _choice_value(choices_cls, candidate_attrs, default_value):
        for attr in candidate_attrs:
            if hasattr(choices_cls, attr):
                return getattr(choices_cls, attr)
        return default_value

    def _fetch_from_assoc(self, group: SecretsGroup, assoc) -> str | None:
        access_type = getattr(assoc, "access_type", None) or self._choice_value(
            SecretsGroupAccessTypeChoices, ["TYPE_GENERIC"], "generic"
        )
        secret_type = getattr(assoc, "secret_type", None)
        name = getattr(assoc, "name", None)
        if name and secret_type:
            try:
                return group.get_secret_value(
                    access_type=access_type,
                    secret_type=secret_type,
                    secret_name=name,
                )
            except Exception:
                pass
        if hasattr(assoc, "get_secret_value"):
            try:
                return assoc.get_secret_value()
            except Exception:
                pass
        if hasattr(assoc, "get_value"):
            try:
                return assoc.get_value()
            except Exception:
                pass
        return None

    def _get_secret_from_group(self, group: SecretsGroup, secret_type, obj=None) -> str | None:
        # Try SSH first, then Generic, in case your Secrets Group uses SSH scoping
        access_type_candidates = []
        for attr in ("TYPE_SSH", "TYPE_GENERIC"):
            access_type_candidates.append(
                getattr(SecretsGroupAccessTypeChoices, attr, attr.split("_", 1)[1].lower())
            )
        for access_type in access_type_candidates:
            try:
                val = group.get_secret_value(
                    access_type=access_type,
                    secret_type=secret_type,
                    obj=obj,  # pass the device if available; many backends don't need it, but it's safe
                )
                if val:
                    return val
            except Exception:
                # Try the next access_type
                continue
        return None

    def _get_username_from_group(self, group: SecretsGroup, obj=None) -> str | None:
        secret_type = getattr(SecretsGroupSecretTypeChoices, "TYPE_USERNAME", "username")
        return self._get_secret_from_group(group, secret_type, obj=obj) or os.getenv("NAPALM_USERNAME")

    def _get_password_from_group(self, group: SecretsGroup, obj=None) -> str | None:
        secret_type = getattr(SecretsGroupSecretTypeChoices, "TYPE_PASSWORD", "password")
        return self._get_secret_from_group(group, secret_type, obj=obj) or os.getenv("NAPALM_PASSWORD")

    def _get_net_credentials(self, group: SecretsGroup, obj=None) -> tuple[str | None, str | None]:
        username = self._get_username_from_group(group, obj=obj)
        password = self._get_password_from_group(group, obj=obj)
        if not username or not password:
            self.logger.warning(
                f"Missing device credentials from Secrets Group '{getattr(group, 'name', group)}'. "
                "Ensure it has associations for username and password, or set NAPALM_USERNAME/NAPALM_PASSWORD."
            )
        return username, password

    def _get_cisco_credentials(self) -> tuple[str | None, str | None]:
        return os.getenv("CISCO_CLIENT_ID"), os.getenv("CISCO_CLIENT_SECRET")

    # ---------------------
    # Platform/host helpers
    # ---------------------
    def _platform_to_napalm_driver(self, platform: Platform) -> str | None:
        explicit = getattr(platform, "napalm_driver", None)
        if explicit:
            return str(explicit)
        name = (platform.name or "").lower()
        if "cisco" in name or "ios" in name:
            return "ios"
        if "arista" in name or "eos" in name:
            return "eos"
        return None

    def _map_platform_to_cisco_ostype(self, device: Device) -> str | None:
        name = (device.platform.name or "").lower() if device.platform else ""
        if "ios xe" in name or "ios-xe" in name or "xe" in name:
            return "iosxe"
        if "ios" in name:
            return "ios"
        return None

    def _device_host(self, device: Device) -> str:
        try:
            if device.primary_ip and getattr(device.primary_ip, "address", None):
                return str(device.primary_ip.address.ip)
        except Exception:
            pass
        return device.name

    # ---------------------
    # Version helpers
    # ---------------------
    @staticmethod
    def _extract_version_token(os_version_text: str) -> str | None:
        s = (os_version_text or "").strip()
        m = re.search(r"(\d{1,2}\.\d{1,2}\([^)]*\)[A-Za-z0-9]*)", s)
        if m:
            return m.group(1)
        m = re.search(r"(\d{1,2}\.\d{1,2}\.\d{1,2}[A-Za-z]?)", s)
        if m:
            return m.group(1)
        m = re.search(r"(\d{1,2}\.\d{1,2})", s)
        if m:
            return m.group(1)
        return None

    # ---------------------
    # Software model handling for VulnerabilityLCM.software
    # ---------------------
    @staticmethod
    def _model_has_fields(model, required: list[str]) -> bool:
        field_names = {f.name for f in model._meta.get_fields()}
        return all(name in field_names for name in required)

    def _software_fk_target_model(self):
        try:
            field = VulnerabilityLCM._meta.get_field("software")
            return field.remote_field.model
        except Exception:
            return None

    def _get_platform_field_name(self, model) -> str | None:
        field_names = {f.name for f in model._meta.get_fields()}
        if "platform" in field_names:
            return "platform"
        if "device_platform" in field_names:
            return "device_platform"
        return None

    def _resolve_software_instance_for_vuln(self, sv_lcm: SoftwareLCM | SimpleNamespace, commit: bool):
        target_model = self._software_fk_target_model()
        if target_model is None:
            self.logger.warning("Could not resolve VulnerabilityLCM.software target model; skipping vulnerability link.")
            return None

        if target_model is SoftwareLCM:
            return sv_lcm if isinstance(sv_lcm, SoftwareLCM) else None

        fields = {f.name for f in target_model._meta.get_fields()}

        platform_field = self._get_platform_field_name(target_model)
        if platform_field and ("version" in fields):
            filter_kwargs = {
                platform_field: getattr(sv_lcm, "device_platform", None) or getattr(sv_lcm, "platform", None),
                "version": sv_lcm.version,
            }
            if not commit:
                exists = target_model.objects.filter(**filter_kwargs).exists()
                if exists:
                    self.logger.info(f"[Dry-run] Would use existing {target_model.__name__} for {filter_kwargs}")
                else:
                    self.logger.info(f"[Dry-run] Would create {target_model.__name__} for {filter_kwargs}")
                return None
            try:
                obj, _ = target_model.objects.get_or_create(**filter_kwargs)
                return obj
            except Exception as exc:
                self.logger.warning(f"Failed to get_or_create {target_model.__name__} with {filter_kwargs}: {exc}")
                return None

        if "software" in fields:
            if not isinstance(sv_lcm, SoftwareLCM):
                self.logger.warning("Cannot resolve 'software' FK without a SoftwareLCM instance.")
                return None
            obj = target_model.objects.filter(software=sv_lcm).first()
            if obj:
                return obj
            self.logger.warning(f"No {target_model.__name__} found for software='{sv_lcm}'. Skipping vulnerability link.")
            return None

        self.logger.warning(f"Unsupported VulnerabilityLCM.software FK model ({target_model.__name__}); skipping link.")
        return None

    # ---------------------
    # Associate CVE with 'Affected Software' M2M where supported
    # ---------------------
    def _associate_cve_with_affected_software(
        self,
        cve_obj,
        sv_lcm,
        software_target,
        commit: bool,
    ):
        m2m_fields = [f for f in cve_obj._meta.get_fields() if getattr(f, "many_to_many", False)]
        if not m2m_fields:
            self.logger.info(f"No compatible 'Affected Software' M2M on CVE {getattr(cve_obj, 'name', '?')}; skipping software association.")
            return

        candidates = []
        if sv_lcm is not None:
            candidates.append(sv_lcm)
        if software_target is not None and software_target is not sv_lcm:
            candidates.append(software_target)

        added_any = False
        for field in m2m_fields:
            remote_model = getattr(field.remote_field, "model", None)
            if remote_model is None:
                continue

            instance = next((c for c in candidates if isinstance(c, remote_model)), None)
            if instance is None:
                continue

            if not commit:
                self.logger.info(
                    f"[Dry-run] Would add software '{getattr(instance, 'version', str(instance))}' to CVE {getattr(cve_obj, 'name', '?')} via field '{field.name}'"
                )
                added_any = True
                continue

            try:
                getattr(cve_obj, field.name).add(instance)
                self.logger.info(
                    f"Added software '{getattr(instance, 'version', str(instance))}' to CVE {cve_obj.name} (field '{field.name}')"
                )
                added_any = True
            except Exception as exc:
                self.logger.warning(f"Failed to add affected software on CVE {cve_obj.name} via '{field.name}': {exc}")

        if not added_any:
            self.logger.info(f"No compatible 'Affected Software' target type on CVE {getattr(cve_obj, 'name', '?')}.")

    # ---------------------
    # HardwareLCM helpers (EoX)
    # ---------------------
    def _hardware_part_field_name(self) -> str | None:
        if not HAS_HARDWARE_LCM:
            return None
        field_names = {f.name for f in HardwareLCM._meta.get_fields()}
        for candidate in ("inventory_item_part_id", "part_number", "part_id", "inventory_part_id"):
            if candidate in field_names:
                return candidate
        return None

    def _hardware_date_field_map(self) -> dict:
        # Map our canonical names to actual model fields (if present)
        if not HAS_HARDWARE_LCM:
            return {}
        field_names = {f.name for f in HardwareLCM._meta.get_fields()}
        mapping = {}
        mapping["release_date"] = "release_date" if "release_date" in field_names else None
        mapping["end_of_sale"] = "end_of_sale" if "end_of_sale" in field_names else None
        mapping["end_of_support"] = "end_of_support" if "end_of_support" in field_names else None
        mapping["end_of_sw_releases"] = "end_of_sw_releases" if "end_of_sw_releases" in field_names else None
        mapping["end_of_security_patches"] = "end_of_security_patches" if "end_of_security_patches" in field_names else None
        mapping["documentation_url"] = "documentation_url" if "documentation_url" in field_names else None
        mapping["comments"] = "comments" if "comments" in field_names else None
        return mapping

    @staticmethod
    def _parse_any_date(value) -> date | None:
        if not value:
            return None
        if isinstance(value, date):
            return value
        s = str(value).strip()
        # Try ISO
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        except Exception:
            pass
        # Common formats from Cisco EoX
        for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d", "%d-%b-%Y", "%b %d, %Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                continue
        # Extract YYYY-MM-DD substring
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
        if m:
            try:
                return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except Exception:
                pass
        return None

    def _eox_record_to_hardware_fields(self, record: dict) -> dict:
        """Map Cisco EoX fields to our HardwareLCM canonical dict."""
        # Cisco fields of interest:
        # EOXExternalAnnouncementDate, EndOfSaleDate, EndOfSWMaintenanceReleases,
        # EndOfSecurityVulSupportDate, LastDateOfSupport, LinkToProductBulletinURL (EOXExternalURL)
        return {
            "release_date": self._parse_any_date(record.get("EOXExternalAnnouncementDate")),
            "end_of_sale": self._parse_any_date(record.get("EndOfSaleDate")),
            "end_of_support": self._parse_any_date(record.get("LastDateOfSupport")),
            "end_of_sw_releases": self._parse_any_date(record.get("EndOfSWMaintenanceReleases")),
            "end_of_security_patches": self._parse_any_date(record.get("EndOfSecurityVulSupportDate")),
            "documentation_url": record.get("LinkToProductBulletinURL") or record.get("EOXExternalURL") or "",
            "comments": record.get("BulletinNumber") or "",
        }

    # ---------------------
    # Discovery via NAPALM -> SoftwareLCM
    # ---------------------
    def _get_or_create_software_lcm(self, platform: Platform, version: str, commit: bool) -> SoftwareLCM | SimpleNamespace | None:
        if not commit:
            exists = SoftwareLCM.objects.filter(device_platform=platform, version=version).exists()
            if exists:
                self.logger.info(f"[Dry-run] Would use existing SoftwareLCM '{version}' for platform '{platform.name}'")
            else:
                self.logger.info(f"[Dry-run] Would create SoftwareLCM '{version}' for platform '{platform.name}'")
            return SimpleNamespace(id=None, version=version, device_platform=platform)
        try:
            obj, created = SoftwareLCM.objects.get_or_create(
                device_platform=platform,
                version=version,
                defaults={"alias": version},
            )
            self.logger.info(f"{'Created' if created else 'Found'} SoftwareLCM '{version}' for platform '{platform.name}'")
            return obj
        except Exception as exc:
            self.logger.warning(f"Failed to get_or_create SoftwareLCM ({platform.name}, {version}): {exc}")
            return None

    def discover_software(self, device: Device, group: SecretsGroup, commit: bool) -> SoftwareLCM | SimpleNamespace | None:
        if not device.platform:
            self.logger.warning(f"{device.name}: No platform set; skipping discovery.")
            return None
        driver_name = self._platform_to_napalm_driver(device.platform)
        if not driver_name:
            self.logger.warning(f"{device.name}: Unsupported platform for NAPALM; skipping.")
            return None

        # Pass device as obj so Secrets backends that scope by object can resolve properly
        username, password = self._get_net_credentials(group, obj=device)
        if not username or not password:
            return None

        host = self._device_host(device)
        try:
            driver = get_network_driver(driver_name)
            conn = driver(hostname=host, username=username, password=password, optional_args={})
            conn.open()
            try:
                facts = conn.get_facts()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except Exception as exc:
            self.logger.warning(f"{device.name}: NAPALM connection/get_facts failed: {exc}")
            return None

        raw_version = (facts or {}).get("os_version") or ""
        version_token = self._extract_version_token(raw_version)
        if not version_token:
            self.logger.warning(f"{device.name}: Could not parse a clean version from '{raw_version}'")
            return None

        sv_lcm = self._get_or_create_software_lcm(device.platform, version_token, commit=commit)
        if sv_lcm and version_token != raw_version.strip():
            self.logger.info(f"{device.name}: Normalized discovered version to '{version_token}' (from '{raw_version}')")
        return sv_lcm

    # ---------------------
    # Cisco PSIRT OAuth + Advisories (v2 API on apix.cisco.com)
    # ---------------------
    def get_cisco_token(self) -> str | None:
        client_id, client_secret = self._get_cisco_credentials()
        if not client_id or not client_secret:
            self.logger.warning("Missing Cisco API credentials in env: CISCO_CLIENT_ID and CISCO_CLIENT_SECRET.")
            return None

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        okta_url = "https://id.cisco.com/oauth2/default/v1/token"
        for data in (
            {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret, "audience": "https://api.cisco.com"},
            {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret},
        ):
            try:
                r = requests.post(okta_url, data=data, headers=headers, timeout=30)
                if r.ok:
                    token = r.json().get("access_token")
                    if token:
                        return token
                else:
                    self.logger.warning(f"Cisco token (Okta) attempt failed: {r.status_code} {r.text[:200]}")
            except Exception as exc:
                self.logger.warning(f"Cisco token request error (Okta): {exc}")

        legacy_url = "https://cloudsso.cisco.com/as/token.oauth2"
        try:
            r = requests.post(legacy_url, data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}, headers=headers, timeout=30)
            if r.ok:
                token = r.json().get("access_token")
                if token:
                    return token
            else:
                self.logger.warning(f"Cisco token fetch failed (legacy): {r.status_code} {r.text[:200]}")
        except Exception as exc:
            self.logger.warning(f"Cisco token request error (legacy): {exc}")
        return None

    # ---------------------
    # Version mapping for Cisco API (honor minor like 16.12.x)
    # ---------------------
    @staticmethod
    def _parse_version_tuple(version_text: str) -> tuple[int | None, int | None, int | None]:
        s = version_text.strip()
        m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
        if not m:
            return (None, None, None)
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) else None
        if patch is None:
            m2 = re.search(r"\(\s*(\d+)\s*\)", s)
            if m2:
                patch = int(m2.group(1))
        return (major, minor, patch)

    @staticmethod
    def _parse_available_version_tuple(v: str) -> tuple[int | None, int | None, int | None]:
        m = re.match(r"^\s*(\d+)\.(\d+)(?:\.\s*(\d+))?", v.strip())
        if not m:
            m = re.match(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?", v.strip())
        if not m:
            return (None, None, None)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)) if m.group(3) else None)

    def _select_best_available_version(self, desired: tuple[int | None, int | None, int | None], available: list[str]) -> str | None:
        dmaj, dmin, dpat = desired
        if dmaj is None or dmin is None:
            return None
        candidates = []
        for v in available:
            maj, minr, pat = self._parse_available_version_tuple(v)
            if maj == dmaj and minr == dmin:
                candidates.append((pat if pat is not None else -1, v))
        if not candidates:
            return None
        if dpat is not None:
            exacts = [v for (p, v) in candidates if p == dpat]
            if exacts:
                return sorted(exacts)[-1]
        candidates.sort(key=lambda x: (x[0], x[1]))
        return candidates[-1][1]

    def _get_cisco_versions(self, token: str, ostype: str) -> list[str]:
        if not hasattr(self, "_cisco_versions_cache"):
            self._cisco_versions_cache = {}
        if ostype in self._cisco_versions_cache:
            return self._cisco_versions_cache[ostype]
        url = "https://apix.cisco.com/security/advisories/v2/OS_version/OS_data"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "nautobot-vendor-cve-job"}
        versions = set()
        try:
            resp = requests.get(url, headers=headers, params={"OSType": ostype}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            self._cisco_versions_cache[ostype] = []
            self.logger.warning(f"Cisco OS_version list request error for {ostype}: {exc}")
            return []
        def _walk(x):
            if isinstance(x, str):
                if re.match(r"^\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-()]*$", x):
                    versions.add(x)
            elif isinstance(x, list):
                for y in x:
                    _walk(y)
            elif isinstance(x, dict):
                for v in x.values():
                    _walk(v)
        _walk(data)
        sorted_versions = sorted(
            versions,
            key=lambda vs: (
                tuple(val if val is not None else -1 for val in self._parse_available_version_tuple(vs)),
                vs,
            )
        )
        self._cisco_versions_cache[ostype] = sorted_versions
        return sorted_versions

    def _map_version_for_cisco(self, token: str, ostype: str, sw_version: str) -> tuple[str | None, str]:
        desired = self._parse_version_tuple(sw_version)
        versions = self._get_cisco_versions(token, ostype)
        best = self._select_best_available_version(desired, versions)
        if best:
            return best, f"Mapped device '{sw_version}' -> '{best}' for OSType {ostype}"
        dmaj, dmin, _ = desired
        if dmaj is not None and dmin is not None:
            fallback = f"{dmaj}.{dmin}"
            return fallback, f"No exact {dmaj}.{dmin}.* match found. Falling back to '{fallback}' for OSType {ostype}"
        return None, "Could not parse a usable version from device; skipping Cisco query."

    # ---------------------
    # Cisco advisories
    # ---------------------
    def pull_cisco_cves(self, software: SoftwareLCM | SimpleNamespace, device: Device) -> list[dict]:
        token = self.get_cisco_token()
        if not token:
            return []
        ostype = self._map_platform_to_cisco_ostype(device)
        if not ostype:
            self.logger.info(f"{device.name}: Platform '{device.platform.name if device.platform else ''}' not mapped to a Cisco OSType; skipping Cisco PSIRT.")
            return []
        mapped_version, mapping_msg = self._map_version_for_cisco(token, ostype, software.version)
        if not mapped_version:
            self.logger.warning(f"{device.name}: {mapping_msg}")
            return []
        self.logger.info(f"{device.name}: {mapping_msg}")

        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "nautobot-vendor-cve-job"}
        base_url = f"https://apix.cisco.com/security/advisories/v2/OSType/{ostype}"
        try:
            resp = requests.get(base_url, headers=headers, params={"version": mapped_version}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            self.logger.warning(f"Cisco API v2 failed ({ostype}, v={mapped_version}): {exc}")
            return []
        advisories = data.get("advisories", []) or []
        self.logger.info(f"Cisco API v2 returned {len(advisories)} advisories for {device.name} ({ostype} v={mapped_version}).")
        return advisories

    # ---------------------
    # Arista advisories (scrape)
    # ---------------------
    def pull_arista_cves(self, software: SoftwareLCM | SimpleNamespace) -> list[dict]:
        url = "https://www.arista.com/en/support/advisories-notices/security-advisories"
        try:
            resp = requests.get(url, headers={"User-Agent": "nautobot-vendor-cve-job"}, timeout=30)
            if not resp.ok:
                self.logger.warning(f"Arista scrape failed: {resp.status_code}")
                return []
        except Exception as exc:
            self.logger.warning(f"Arista advisories request error: {exc}")
            return []
        soup = BeautifulSoup(resp.text, "lxml")
        advisories = []
        for item in soup.select(".advisory-item, .item, article, li"):
            title_el = item.find(["h2", "h3", "a"])
            para_el = item.find("p")
            title = title_el.get_text(strip=True) if title_el else ""
            desc = para_el.get_text(strip=True) if para_el else ""
            text = f"{title}\n{desc}"
            if software.version in text:
                cve_ids = set(re.findall(r"CVE-\d{4}-\d{4,7}", text))
                for cve_id in cve_ids:
                    advisories.append(
                        {
                            "advisoryIdentifier": cve_id,
                            "summary": title or desc or "Arista security advisory",
                            "cves": [cve_id],
                            "publicationUrl": url,
                            "firstPublished": None,
                            "lastUpdated": None,
                            "severity": "Unknown",
                        }
                    )
        return advisories

    # ---------------------
    # Date parsing helpers for CVELCM fields
    # ---------------------
    def _extract_date_from_keys(self, advisory: dict, keys: list[str], default: date | None = None) -> date | None:
        value = None
        for key in keys:
            if key in advisory and advisory[key]:
                value = advisory[key]
                break
        if isinstance(value, str):
            s = value.strip()
            try:
                s2 = s.replace("Z", "+00:00")
                dt = datetime.fromisoformat(s2)
                return dt.date()
            except Exception:
                pass
        # try common formats and substrings
        for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d", "%d-%b-%Y", "%b %d, %Y"):
            try:
                return datetime.strptime(str(value), fmt).date()
            except Exception:
                continue
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(value or ""))
        if m:
            try:
                return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except Exception:
                pass
        return default

    def _extract_published_date(self, advisory: dict) -> date:
        d = self._extract_date_from_keys(
            advisory,
            ["firstPublished", "firstPublishedDate", "publicationDate", "advisoryPublicationDate", "published"],
            default=None,
        )
        return d or date.today()

    def _extract_last_modified_date(self, advisory: dict, fallback: date | None) -> date | None:
        d = self._extract_date_from_keys(
            advisory,
            ["lastUpdated", "lastModified", "lastModifiedDate", "advisoryLastUpdatedDate"],
            default=None,
        )
        return d or fallback

    # ---------------------
    # CVSS parsing helpers
    # ---------------------
    @staticmethod
    def _to_float(val) -> float | None:
        try:
            return float(val)
        except Exception:
            return None

    def _extract_cvss_for_cve(self, advisory: dict, cve_id: str) -> tuple[float | None, float | None, float | None]:
        cvss_base = cvss_v2 = cvss_v3 = None
        if isinstance(advisory.get("cve"), list):
            for c in advisory["cve"]:
                if isinstance(c, dict) and c.get("id") == cve_id:
                    for k in ["cvssBaseScore", "baseScore", "cvss_score", "cvss"]:
                        val = c.get(k)
                        if isinstance(val, dict) and "baseScore" in val:
                            cvss_base = self._to_float(val["baseScore"]) or cvss_base
                        else:
                            cvss_base = self._to_float(val) or cvss_base
                    for k in ["cvssV3BaseScore", "cvss_v3", "cvssV3"]:
                        val = c.get(k)
                        if isinstance(val, dict) and "baseScore" in val:
                            cvss_v3 = self._to_float(val["baseScore"]) or cvss_v3
                        else:
                            cvss_v3 = self._to_float(val) or cvss_v3
                    for k in ["cvssV2BaseScore", "cvss_v2", "cvssV2"]:
                        val = c.get(k)
                        if isinstance(val, dict) and "baseScore" in val:
                            cvss_v2 = self._to_float(val["baseScore"]) or cvss_v2
                        else:
                            cvss_v2 = self._to_float(val) or cvss_v2
                    break
        if cvss_base is None:
            for k in ["cvssBaseScore", "baseScore", "cvss_score", "cvss"]:
                val = advisory.get(k)
                if isinstance(val, dict) and "baseScore" in val:
                    cvss_base = self._to_float(val["baseScore"])
                else:
                    cvss_base = self._to_float(val)
                if cvss_base is not None:
                    break
        if cvss_v3 is None:
            for k in ["cvssV3BaseScore", "cvss_v3", "cvssV3"]:
                val = advisory.get(k)
                if isinstance(val, dict) and "baseScore" in val:
                    cvss_v3 = self._to_float(val["baseScore"])
                else:
                    cvss_v3 = self._to_float(val)
                if cvss_v3 is not None:
                    break
        if cvss_v2 is None:
            for k in ["cvssV2BaseScore", "cvss_v2", "cvssV2"]:
                val = advisory.get(k)
                if isinstance(val, dict) and "baseScore" in val:
                    cvss_v2 = self._to_float(val["baseScore"])
                else:
                    cvss_v2 = self._to_float(val)
                if cvss_v2 is not None:
                    break
        if cvss_base is None:
            cvss_base = cvss_v3 if cvss_v3 is not None else cvss_v2
        return cvss_base, cvss_v2, cvss_v3

    # ---------------------
    # DLM v2.x persistence (CVEs + Vulnerabilities with Affected Software association)
    # ---------------------
    def _get_status_for_model(self, model, candidates: list[str]) -> Status | None:
        try:
            qs = Status.objects.get_for_model(model)
            for name in candidates:
                s = qs.filter(name__iexact=name).first()
                if s:
                    return s
            return qs.first() if qs.exists() else None
        except Exception:
            return None

    def create_cves_and_vulns_for_software(
        self,
        advisories: list[dict],
        sv_lcm: SoftwareLCM | SimpleNamespace,
        vendor: str,
        commit: bool,
    ):
        """Create/update CVEs and Vulnerabilities for the given software; associate Affected Software, not platform."""
        if not advisories:
            return

        open_status = self._get_status_for_model(VulnerabilityLCM, ["Open", "Active"]) if commit else None
        cve_status_default = self._get_status_for_model(CVELCM, ["Active", "Published"]) if commit else None

        software_target = self._resolve_software_instance_for_vuln(sv_lcm, commit=commit)
        if commit and software_target is None:
            self.logger.warning("Cannot resolve suitable software instance for VulnerabilityLCM.software; skipping vulnerability creation.")
        if not commit and software_target is None:
            self.logger.info("[Dry-run] Would link vulnerability to resolved software instance (skipped FK resolution).")

        created_cves = 0
        created_vulns = 0

        for adv in advisories:
            cve_ids = []
            if isinstance(adv.get("cves"), list):
                cve_ids = [c for c in adv["cves"] if isinstance(c, str)]
            elif isinstance(adv.get("cve"), list):
                cve_ids = [c.get("id") for c in adv["cve"] if isinstance(c, dict) and c.get("id")]
            elif isinstance(adv.get("advisoryIdentifier", ""), str) and adv["advisoryIdentifier"].startswith("CVE-"):
                cve_ids = [adv["advisoryIdentifier"]]

            description = adv.get("summary") or adv.get("advisoryTitle") or ""
            link = adv.get("publicationUrl") or adv.get("url") or ""
            severity = adv.get("severity") or adv.get("sir") or ""
            published_date = self._extract_published_date(adv)
            last_modified_date = self._extract_last_modified_date(adv, fallback=published_date)

            for cve_id in set(filter(None, cve_ids)):
                cvss_base, cvss_v2, cvss_v3 = self._extract_cvss_for_cve(adv, cve_id)

                if not commit:
                    exists = CVELCM.objects.filter(name=cve_id).exists()
                    self.logger.info(
                        f"[Dry-run] Would {'update' if exists else 'create'} CVE {cve_id} with "
                        f"published_date={published_date}, last_modified_date={last_modified_date}, link={link or '-'}, "
                        f"severity={severity or '-'}, cvss={cvss_base}, cvss_v2={cvss_v2}, cvss_v3={cvss_v3}, "
                        f"status={(adv.get('status') or getattr(cve_status_default, 'name', '')) or '-'}; "
                        f"and {'ensure' if exists else 'create'} Vulnerability (software='{getattr(sv_lcm, 'version', '?')}'), "
                        f"plus associate CVE->Affected Software."
                    )
                    self._associate_cve_with_affected_software(
                        cve_obj=SimpleNamespace(name=cve_id, _meta=CVELCM._meta),
                        sv_lcm=sv_lcm,
                        software_target=software_target,
                        commit=False,
                    )
                    continue

                try:
                    cve_status_obj = None
                    adv_status_name = adv.get("status")
                    if adv_status_name:
                        cve_status_obj = self._get_status_for_model(CVELCM, [str(adv_status_name)])
                    if not cve_status_obj:
                        cve_status_obj = cve_status_default

                    defaults = {
                        "published_date": published_date,
                        "last_modified_date": last_modified_date,
                        "severity": severity or "",
                        "cvss": cvss_base,
                        "cvss_v2": cvss_v2,
                        "cvss_v3": cvss_v3,
                        "status": cve_status_obj,
                    }
                    if description:
                        defaults["description"] = description[:1024]
                    if link:
                        defaults["link"] = link

                    cve_obj, created = CVELCM.objects.get_or_create(name=cve_id, defaults=defaults)
                    if created:
                        created_cves += 1
                        self.logger.info(f"Created CVE {cve_id} from {vendor}")
                    else:
                        patch_needed = False
                        if not getattr(cve_obj, "published_date", None):
                            cve_obj.published_date = published_date
                            patch_needed = True
                        if last_modified_date and not getattr(cve_obj, "last_modified_date", None):
                            cve_obj.last_modified_date = last_modified_date
                            patch_needed = True
                        if link and not getattr(cve_obj, "link", ""):
                            cve_obj.link = link
                            patch_needed = True
                        if description and not getattr(cve_obj, "description", ""):
                            cve_obj.description = description[:1024]
                            patch_needed = True
                        if severity and not getattr(cve_obj, "severity", ""):
                            cve_obj.severity = severity
                            patch_needed = True
                        if cvss_base is not None and getattr(cve_obj, "cvss", None) in (None, 0):
                            cve_obj.cvss = cvss_base
                            patch_needed = True
                        if cvss_v2 is not None and getattr(cve_obj, "cvss_v2", None) in (None, 0):
                            cve_obj.cvss_v2 = cvss_v2
                            patch_needed = True
                        if cvss_v3 is not None and getattr(cve_obj, "cvss_v3", None) in (None, 0):
                            cve_obj.cvss_v3 = cvss_v3
                            patch_needed = True
                        if cve_status_obj and not getattr(cve_obj, "status", None):
                            cve_obj.status = cve_status_obj
                            patch_needed = True
                        if patch_needed:
                            cve_obj.save()

                    # Associate "Affected Software" on the CVE when supported
                    self._associate_cve_with_affected_software(
                        cve_obj=cve_obj,
                        sv_lcm=sv_lcm,
                        software_target=software_target,
                        commit=True,
                    )

                    if software_target is None:
                        continue

                    vuln_defaults = {}
                    if open_status:
                        vuln_defaults["status"] = open_status

                    vuln, v_created = VulnerabilityLCM.objects.get_or_create(
                        cve=cve_obj,
                        software=software_target,
                        defaults=vuln_defaults,
                    )
                    if v_created:
                        created_vulns += 1
                        self.logger.info(
                            f"Created vulnerability {cve_id} for software {getattr(software_target, 'version', getattr(sv_lcm, 'version', '?'))}"
                        )
                except Exception as exc:
                    self.logger.warning(
                        f"Failed to persist CVE/Vulnerability for {cve_id} on software {getattr(sv_lcm, 'version', '?')}: {exc}"
                    )

        suffix = "[Dry-run] " if not commit else ""
        self.logger.info(
            f"{suffix}Persisted CVEs: +{created_cves}, Vulnerabilities: +{created_vulns} for software {getattr(sv_lcm, 'version', '?')}"
        )

    # ---------------------
    # Cisco EoX (Hardware Notices)
    # ---------------------
    def pull_cisco_eox_for_pid(self, pid: str) -> list[dict]:
        """Query Cisco EoX v5 API for a single product ID (PID)."""
        token = self.get_cisco_token()
        if not token:
            return []
        url = f"https://apix.cisco.com/supporttools/eox/rest/5/EOXByProductID/1/{pid}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "nautobot-vendor-cve-job"}
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if not resp.ok:
                self.logger.warning(f"Cisco EoX API failed for PID={pid}: {resp.status_code} {resp.text[:200]}")
                return []
            data = resp.json() or {}
            # Records array can be under "EOXRecord" or similar top-level
            records = data.get("EOXRecord") or data.get("EOXRecords") or data.get("Records") or []
            if isinstance(records, dict):
                records = [records]
            return records
        except Exception as exc:
            self.logger.warning(f"Cisco EoX API request error for PID={pid}: {exc}")
            return []

    def upsert_hardware_notice_for_device(self, device: Device, commit: bool):
        """Create/update HardwareLCM for device.device_type using its part number via Cisco EoX."""
        if not HAS_HARDWARE_LCM:
            self.logger.info("HardwareLCM not available in this DLM version; skipping hardware notices.")
            return

        if not device.device_type:
            self.logger.info(f"{device.name}: No DeviceType; skipping EoX.")
            return

        pid = getattr(device.device_type, "part_number", None) or getattr(device.device_type, "model", None)
        if not pid:
            self.logger.info(f"{device.name}: DeviceType has no part_number; skipping EoX.")
            return

        records = self.pull_cisco_eox_for_pid(pid)
        if not records:
            self.logger.info(f"{device.name}: No EoX records for PID={pid}.")
            return

        part_field = self._hardware_part_field_name()
        if not part_field:
            self.logger.info("Could not determine HardwareLCM part-number field; skipping.")
            return
        field_map = self._hardware_date_field_map()

        for rec in records:
            mapped = self._eox_record_to_hardware_fields(rec)

            # Build filter for get_or_create
            filter_kwargs = {"device_type": device.device_type, part_field: pid}

            if not commit:
                exists = HardwareLCM.objects.filter(**filter_kwargs).exists()
                action = "update" if exists else "create"
                self.logger.info(
                    f"[Dry-run] Would {action} HardwareLCM for device_type='{device.device_type.model}' "
                    f"part='{pid}' with dates: release={mapped['release_date']}, "
                    f"eosale={mapped['end_of_sale']}, eosupport={mapped['end_of_support']}, "
                    f"eosw={mapped['end_of_sw_releases']}, eosec={mapped['end_of_security_patches']}, "
                    f"url={mapped['documentation_url'] or '-'}"
                )
                continue

            try:
                obj, created = HardwareLCM.objects.get_or_create(**filter_kwargs)
                # Update fields if present in model
                changed = False
                for key, model_field in field_map.items():
                    if not model_field:
                        continue
                    new_value = mapped.get(key)
                    if new_value is None:
                        continue
                    if getattr(obj, model_field, None) != new_value:
                        setattr(obj, model_field, new_value)
                        changed = True
                if changed:
                    obj.save()
                self.logger.info(
                    f"{'Created' if created else 'Updated'} HardwareLCM for device_type='{device.device_type.model}' part='{pid}'"
                )
            except Exception as exc:
                self.logger.warning(f"Failed to upsert HardwareLCM for {device.device_type} / {pid}: {exc}")

    # ---------------------
    # Run (data, commit, **kwargs) with DryRunVar support and kwargs normalization
    # ---------------------
    def run(self, data=None, commit=True, **kwargs):
        # Accept both legacy (data dict) and new-style keyword args
        def _param(key, default=None):
            if key in kwargs:
                return kwargs.get(key, default)
            return (data or {}).get(key, default)

        devices = _param("devices")
        secrets_group = _param("secrets_group")
        dry_run = bool(_param("dry_run", False))
        include_hw = bool(_param("include_hardware_notices", False))

        effective_commit = bool(commit) and not dry_run
        if not effective_commit:
            self.logger.info("Dry-run enabled: no changes will be written to the database.")

        if not isinstance(secrets_group, SecretsGroup):
            self.logger.error("You must choose a valid Secrets Group for credentials.")
            return

        # Devices queryset
        if devices:
            try:
                qs = devices
            except Exception:
                try:
                    pks = [d.pk for d in devices]
                except Exception:
                    pks = list(devices)
                qs = Device.objects.filter(pk__in=pks)
        else:
            active_status = Status.objects.get_for_model(Device).filter(name__iexact="Active").first()
            if not active_status:
                self.logger.warning("No 'Active' status found; processing all devices.")
                devices_qs = Device.objects.all()
            else:
                devices_qs = Device.objects.filter(status=active_status)
            qs = devices_qs.distinct()

        processed = 0
        for device in qs:
            plat_name = (device.platform.name or "").lower() if device.platform else ""
            is_cisco_like = any(s in plat_name for s in ("cisco", "ios", "nx", "asa"))
            is_arista_like = any(s in plat_name for s in ("arista", "eos"))

            # Software CVEs
            if is_cisco_like or is_arista_like:
                sv_lcm = self.discover_software(device, secrets_group, commit=effective_commit)
                if sv_lcm:
                    if is_cisco_like:
                        advisories = self.pull_cisco_cves(sv_lcm, device)
                        self.create_cves_and_vulns_for_software(advisories, sv_lcm, vendor="Cisco", commit=effective_commit)
                    if is_arista_like:
                        advisories = self.pull_arista_cves(sv_lcm)
                        self.create_cves_and_vulns_for_software(advisories, sv_lcm, vendor="Arista", commit=effective_commit)

            # Hardware notices (Cisco EoX)
            if include_hw and is_cisco_like:
                self.upsert_hardware_notice_for_device(device, commit=effective_commit)

            processed += 1

        self.logger.info(f"Processed {processed} devices. Tip: run the NIST CVE enrichment job separately for comprehensive coverage.")


register_jobs(VendorCVEDiscoveryJob)