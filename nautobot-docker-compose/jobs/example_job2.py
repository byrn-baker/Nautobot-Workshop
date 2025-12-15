# jobs/device_config_validator.py

from nautobot.apps.jobs import Job, register_jobs
from nautobot.dcim.models import Device
from nautobot.extras.models import Status


class DeviceConfigValidator(Job):
    """Validate NTP configurations for active devices in Nautobot."""

    class Meta:
        name = "Validate Device Configurations"
        description = "Check if devices have valid NTP configurations"
        read_only = True

    def validate_config(self, device):
        """Return True if device has NTP servers defined in its merged config context."""
        context = {}
        try:
            context = device.get_config_context() or {}
        except Exception as exc:
            self.logger.warning(f"Unable to retrieve config context for {device}: {exc}")
            return False

        ntp_servers = context.get("ntp_servers", [])
        return bool(ntp_servers)

    def run(self):
        """Execute the job to validate NTP configurations for active devices."""
        try:
            active_status = Status.objects.get_for_model(Device).get(name="Active")
        except Status.DoesNotExist:
            msg = "Status 'Active' not found"
            self.logger.failure(msg)
            raise RuntimeError(msg)

        devices = Device.objects.filter(status=active_status)

        valid = 0
        invalid = 0
        for device in devices:
            if self.validate_config(device):
                valid += 1
                self.logger.success(f"{device.name} has valid NTP config")
            else:
                invalid += 1
                self.logger.failure(f"{device.name} has invalid NTP config")

        result = f"Validated {devices.count()} devices: {valid} valid, {invalid} invalid"
        self.logger.info(result)
        return result


register_jobs(DeviceConfigValidator)