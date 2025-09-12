from nautobot.apps.jobs import Job, register_jobs
from nautobot.dcim.models import Device
from nautobot.extras.models import Status

class DeviceReportJob(Job):
    """Generate a report of all active devices in Nautobot."""

    class Meta:
        name = "Device Report"
        description = "Generate a report of active devices"
        read_only = True

    def run(self):
        """Execute the job to count active devices."""
        active_status = Status.objects.get_for_model(Device).get(name="Active")
        devices = Device.objects.filter(status=active_status)
        self.logger.success(message=f"Found {devices.count()} active devices")

register_jobs(DeviceReportJob)