"""Wrapper class for DNS actions"""

import weakref


class ZoneController(object):

    def __init__(self, zone):
        """Initialize zone controller given a zone"""
        self._zone = weakref.ref(zone)

    @property
    def zone(self):
        return self._zone()

    def create_zone(self, **kwargs):
        """Create a zone under the specific cloud"""
        return self.zone.cloud.ctl.dns.create_zone(self.zone, **kwargs)

    def list_records(self):
        """Wrapper for the DNS cloud controller list_records() functionality
        """
        return self.zone.cloud.ctl.dns.list_records(self.zone)

    def delete_zone(self):
        """Wrapper for the DNS cloud controller delete_zone() functionality
        """
        return self.zone.cloud.ctl.dns.delete_zone(self.zone)


class RecordController(object):

    def __init__(self, record):
        """Initialize record controller given a record"""
        self._record = weakref.ref(record)

    @property
    def record(self):
        return self._record()

    def create_record(self, **kwargs):
        """Wrapper for the DNS cloud controller create_record() functionality
        """
        return self.record.zone.cloud.ctl.dns.create_record(self.record,
                                                            **kwargs)

    def delete_record(self):
        """Wrapper for the delete_record DNSController functionality."""
        return self.record.zone.cloud.ctl.dns.delete_record(self.record)
