# jobs/tests/test_device_tag_job.py

from django.contrib.contenttypes.models import ContentType

from nautobot.apps.testing import TransactionTestCase, run_job_for_testing
from nautobot.dcim.models import (
    Device,
    Location,
    LocationType,
    Manufacturer,
    DeviceType,
)
from nautobot.extras.models import Status, Tag, Job, JobLogEntry, Role

# Ensure the job module is imported so register_jobs() is executed
from jobs.device_tag_checker import DeviceTagCheckerJob  # noqa: F401


class DeviceTagCheckerJobTestCase(TransactionTestCase):
    # Allow both the default DB and the job_logs DB used for JobLogEntry
    databases = ("default", "job_logs")

    def setUp(self):
        super().setUp()

        # Status used by Devices and Locations
        self.active_status, _ = Status.objects.get_or_create(name="Active")
        ct_device = ContentType.objects.get_for_model(Device)
        ct_location = ContentType.objects.get_for_model(Location)
        self.active_status.content_types.add(ct_device, ct_location)

        # Tag
        self.tag, _ = Tag.objects.get_or_create(name="Critical")

        # Location hierarchy (minimal)
        self.location_type, _ = LocationType.objects.get_or_create(name="Site")
        self.location = Location.objects.create(
            name="Test-Site",
            location_type=self.location_type,
            status=self.active_status,
        )

        # Device Type prerequisites
        self.manufacturer = Manufacturer.objects.create(name="Acme")
        self.device_type = DeviceType.objects.create(
            manufacturer=self.manufacturer,
            model="Router-1",
        )

        # Role for Devices
        self.role, _ = Role.objects.get_or_create(name="Network")
        self.role.content_types.add(ct_device)

    def _create_device(self, name):
        return Device.objects.create(
            name=name,
            status=self.active_status,
            location=self.location,
            role=self.role,
            device_type=self.device_type,
        )

    def _get_job_model(self):
        # module_name should match the filename jobs/device_tag_checker.py
        return Job.objects.get(
            job_class_name="DeviceTagCheckerJob",
            module_name="device_tag_checker",
        )

    def test_device_tag_checker(self):
        """Test DeviceTagCheckerJob identifies devices missing the 'Critical' tag."""
        device1 = self._create_device("device1")
        device1.tags.add(self.tag)
        self._create_device("device2")  # no tag

        job = self._get_job_model()
        job_result = run_job_for_testing(job)

        # Status uses Celery states in Nautobot 2.4
        self.assertEqual(job_result.status, "SUCCESS")
        self.assertEqual(job_result.result, "1 device(s) missing the 'Critical' tag")

        expected_message = "1 device(s) missing the 'Critical' tag"
        log_entries = JobLogEntry.objects.filter(job_result=job_result, message=expected_message)
        self.assertTrue(log_entries.exists(), "Expected success log entry not found.")
        self.assertEqual(log_entries.first().log_level, "success")

    def test_device_tag_checker_no_devices(self):
        """Test DeviceTagCheckerJob when no devices exist."""
        job = self._get_job_model()
        job_result = run_job_for_testing(job)

        self.assertEqual(job_result.status, "SUCCESS")
        self.assertEqual(job_result.result, "0 device(s) missing the 'Critical' tag")

        expected_message = "0 device(s) missing the 'Critical' tag"
        log_entries = JobLogEntry.objects.filter(job_result=job_result, message=expected_message)
        self.assertTrue(log_entries.exists(), "Expected success log entry not found.")
        self.assertEqual(log_entries.first().log_level, "success")

    def test_device_tag_checker_missing_tag(self):
        """Test DeviceTagCheckerJob when the 'Critical' tag does not exist."""
        Tag.objects.filter(name="Critical").delete()

        job = self._get_job_model()
        job_result = run_job_for_testing(job)

        self.assertEqual(job_result.status, "FAILURE")

        expected_message = "Tag 'Critical' not found"
        log_entries = JobLogEntry.objects.filter(job_result=job_result, message=expected_message)
        self.assertTrue(log_entries.exists(), "Expected failure log entry not found.")
        self.assertEqual(log_entries.first().log_level, "failure")