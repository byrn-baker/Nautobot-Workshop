# jobs/device_tag_checker.py

from nautobot.apps.jobs import Job, register_jobs
from nautobot.dcim.models import Device
from nautobot.extras.models import Status, Tag


class DeviceTagCheckerJob(Job):
    """Check if all active devices have the 'Critical' tag in Nautobot."""

    class Meta:
        name = "Device Tag Checker"
        description = "Check if all devices have the 'Critical' tag"
        read_only = True

    def get_active_devices(self):
        """Retrieve all devices with 'Active' status."""
        active_status = Status.objects.get_for_model(Device).get(name="Active")
        return Device.objects.filter(status=active_status)

    def run(self):
        """Execute the job to check for the 'Critical' tag on active devices."""
        try:
            tag = Tag.objects.get(name="Critical")
        except Tag.DoesNotExist:
            msg = "Tag 'Critical' not found"
            self.logger.failure(msg)
            raise RuntimeError(msg)

        try:
            devices = self.get_active_devices()
        except Status.DoesNotExist:
            msg = "Status 'Active' not found"
            self.logger.failure(msg)
            raise RuntimeError(msg)

        missing_tag_count = devices.exclude(tags=tag).count()
        result = f"{missing_tag_count} device(s) missing the 'Critical' tag"
        self.logger.success(result)
        return result


register_jobs(DeviceTagCheckerJob)