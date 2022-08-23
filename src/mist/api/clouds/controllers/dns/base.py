"""Definition of `BaseDNSController`

The `BaseDNSController` is a sub-controller, which is set as an attribute to a
`BaseController` class. The `BaseDNSController` is responsible for interacting
with libcloud's DNS API.

"""
import ssl
import logging
import datetime
import time

import jsonpatch

import mongoengine as me

import mist.api.exceptions

from mist.api.concurrency.models import PeriodicTaskInfo

from mist.api.clouds.controllers.base import BaseController

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

from libcloud.common.types import InvalidCredsError
from libcloud.dns.types import ZoneDoesNotExistError, RecordDoesNotExistError

from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import ZoneNotFoundError
from mist.api.exceptions import RecordNotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import RecordExistsError
from mist.api.exceptions import ZoneExistsError
from mist.api.exceptions import ZoneCreationError
from mist.api.exceptions import RecordCreationError


log = logging.getLogger(__name__)


class BaseDNSController(BaseController):
    """Base class to be inherited by every clouds that supports a DNS
    sub-controller.

    This base controller factors out all the basic steps common to all or
    most clouds into a base class, and defines an interface for provider or
    technology specific cloud controllers.

    Subclasses are meant to extend or override methods of this base class to
    account for differencies between different cloud types.

    Care should be taken when considering to add new methods to a subclass.
    All controllers should have the same interface, to the degree this is
    feasible. That is to say, don't add a new method to a subclass unless
    there is a very good reason to do so.

    The following convention is followed:

    Any methods and attributes that don't start with an underscore are the
    controller's public API.

    In the `BaseDNSController`, these public methods will in most cases contain
    a basic implementation that works for most clouds, along with the proper
    logging and error handling. In almost all cases, subclasses SHOULD NOT
    override or extend the public methods of `BaseController`. To account for
    cloud/subclass specific behaviour, one is expected to override the
    internal/private methods of `BaseDNSController`.

    Any methods and attributes that start with an underscore are the
    controller's internal/private API.

    To account for cloud/subclass specific behaviour, the public methods of
    `BaseDNSController` call a number of private methods. These methods will
    always start with an underscore, such as `_list_zones`.

    This `BaseDNSController` defines a strict interface to controlling clouds
    that allow for DNS specific actions.
    For each different cloud type, a subclass needs to be defined. Each
    subclass MUST receive its main controller as its sole init argument

    """

    def list_zones(self, persist=True):
        """Return list of zones for cloud

        A list of zones is fetched from libcloud, data is processed, stored
        on zone models, and a list of zone models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_zones` which contains the core
        implementation.

        """
        task_key = 'cloud:list_zones:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        first_run = False if task.last_success else True
        with task.task_runner(persist=persist):
            cached_zones = {'%s-%s' % (z.id, z.external_id): z.as_dict()
                            for z in self.list_cached_zones()}

            zones = self._list_zones()
            for zone in zones:
                self.list_records(zone)

        # Initialize AMQP connection to reuse for multiple messages.
        if amqp_owner_listening(self.cloud.owner.id):
            zones_dict = [z.as_dict() for z in zones]
            if cached_zones or zones_dict:
                # Publish patches to rabbitmq.
                new_zones = {'%s-%s' % (z['id'], z['external_id']): z
                             for z in zones_dict}
                patch = jsonpatch.JsonPatch.from_diff(cached_zones,
                                                      new_zones).patch
                if patch:
                    if not first_run and self.cloud.observation_logs_enabled:
                        from mist.api.logs.methods import log_observations
                        log_observations(self.cloud.owner.id, self.cloud.id,
                                         'zone', patch, cached_zones,
                                         new_zones)
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_zones',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
        return zones

    def _list_zones(self):
        """
        Requesting all the DNS zones
        under a specific cloud.
        """
        from mist.api.dns.models import Zone

        # Fetch zones from libcloud connection.
        pr_zones = self._list_zones__fetch_zones()

        zones = []
        new_zones = []
        for pr_zone in pr_zones:
            try:
                zone = Zone.objects.get(cloud=self.cloud,
                                        external_id=pr_zone.id)
            except Zone.DoesNotExist:
                log.info("Zone: %s/domain: %s not in the database, creating.",
                         pr_zone.id, pr_zone.domain)
                zone = Zone(cloud=self.cloud, owner=self.cloud.owner,
                            external_id=pr_zone.id)
                zone.first_seen = datetime.datetime.utcnow()
                new_zones.append(zone)
            zone.deleted = None
            zone.domain = pr_zone.domain
            zone.type = pr_zone.type
            zone.ttl = pr_zone.ttl
            zone.extra = pr_zone.extra
            # Get zone creation date.
            try:
                created = self._list_zones__zone_creation_date(pr_zone)
                if created:
                    created = get_datetime(created)
                    if zone.created != created:
                        zone.created = created
            except Exception as exc:
                log.exception("Error finding creation date for %s in %s.\n%r",
                              self.cloud, zone, exc)
            try:
                zone.save()
            except me.ValidationError as exc:
                log.error("Error updating %s: %s", zone, exc.to_dict())
                raise BadRequestError({'msg': str(exc),
                                       'errors': exc.to_dict()})
            except me.NotUniqueError as exc:
                log.error("Zone %s not unique error: %s", zone, exc)
                raise ZoneExistsError()
            zones.append(zone)
        if new_zones:
            self.cloud.owner.mapper.update(new_zones)
        now = datetime.datetime.utcnow()
        # Set missing_since on zones not returned by libcloud
        Zone.objects(
            cloud=self.cloud, missing_since=None,
            external_id__nin=[z.external_id for z in zones]
        ).update(missing_since=now)
        # Set last_seen, unset missing_since on zones we just saw
        Zone.objects(cloud=self.cloud,
                     external_id__in=[
                         z.external_id for z in zones]).update(
            last_seen=now, missing_since=None)

        # Format zone information.
        return zones

    def list_cached_zones(self):
        """Returns zones stored in database
        for a specific cloud
        """
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.dns.models import Zone
        return Zone.objects(cloud=self.cloud, missing_since=None)

    def _list_zones__zone_creation_date(self, libcloud_zone):
        return libcloud_zone.extra.get('created_at')

    def _list_zones__fetch_zones(self):
        """
        Returns a list of available DNS zones for the cloud.
        This should not be overridden as the implementation is the same across
        all implemented DNS providers.

        """
        # Try to get the list of DNS zones from provider API.
        try:
            zones = self.connection.list_zones()
            log.info("List zones returned %d results for %s.",
                     len(zones), self.cloud)
            return zones
        except InvalidCredsError as exc:
            log.warning("Invalid creds on running list_zones on %s: %s",
                        self.cloud, exc)
            raise CloudUnauthorizedError()
        except ssl.SSLError as exc:
            log.error("SSLError on running list_zones on %s: %s",
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)
        except Exception as exc:
            log.exception("Error while running list_zones on %s", self.cloud)
            raise CloudUnavailableError(exc=exc)

    def list_records(self, zone):
        """
        Public method to return a list of  records under a specific zone.
        """
        # Fetch records from libcloud connection.
        pr_records = self._list_records__fetch_records(zone.external_id)

        # TODO: Adding here for circular dependency issue. Need to fix this.
        from mist.api.dns.models import Record, RECORDS

        records = []
        new_records = []
        for pr_record in pr_records:
            dns_cls = RECORDS[pr_record.type]
            try:
                record = Record.objects.get(zone=zone,
                                            external_id=pr_record.id,
                                            missing_since=None)
                changed = False
            except Record.DoesNotExist:
                log.info("Record: %s not in the database, creating.",
                         pr_record.id)
                if pr_record.type not in RECORDS:
                    log.error("Unsupported record type '%s'", pr_record.type)
                    continue

                record = dns_cls(external_id=pr_record.id, zone=zone)
                record.first_seen = datetime.datetime.utcnow()
                new_records.append(record)
                changed = True
            # We need to check if any of the information returned by the
            # provider is different than what we have in the DB
            if record.name != pr_record.name:
                record.name = pr_record.name or ""
                changed = True
            if record.type != pr_record.type:
                record.type = pr_record.type
                changed = True
            if record.ttl != pr_record.ttl:
                record.ttl = pr_record.ttl
                changed = True
            if record.extra != pr_record.extra:
                record.extra = pr_record.extra
                changed = True
            # Get record creation date.
            try:
                created = self._list_records__record_creation_date(pr_record)
                if created:
                    created = get_datetime(created)
                    if record.created != created:
                        record.created = created
                        changed = True
            except Exception as exc:
                log.exception("Error finding creation date for %s in %s.\n%r",
                              self.cloud, record, exc)

            self._list_records__postparse_data(pr_record, record)
            try:
                if changed:
                    try:
                        record.save()
                    except Exception as exc:
                        log.exception("Could not save %s record %s for cloud "
                                      "%s (%s): %r" % (
                                          record.type, record.name,
                                          self.cloud.name, self.cloud.id, exc
                                      ))
            except me.ValidationError as exc:
                log.error("Error updating %s: %s", record, exc.to_dict())
                raise BadRequestError({'msg': str(exc),
                                       'errors': exc.to_dict()})
            except me.NotUniqueError as exc:
                log.error("Record %s not unique error: %s", record, exc)
                raise RecordExistsError()
            # There's a chance that we have received duplicate records as for
            # example for Route NS records, so skip adding it to the list if we
            # already have it
            for rec in records:
                if rec.external_id == record.external_id:
                    records.remove(rec)
                    break
            records.append(record)
        if new_records:
            self.cloud.owner.mapper.update(new_records)
        now = datetime.datetime.utcnow()
        # Set missing_since on records not returned by libcloud
        Record.objects(
            owner=self.cloud.org, zone=zone, missing_since=None,
            id__nin=[r.id for r in records]
        ).update(missing_since=now)
        # Set last_seen on records we just saw
        Record.objects(owner=self.cloud.org, zone=zone,
                       id__in=[r.id for r in records]).update(
            last_seen=now, missing_since=None)

        # Format zone information.
        return records

    def _list_records__fetch_records(self, zone_id):
        """Returns all available records on a specific zone. """

        # Try to get the list of DNS records under a specific zone from
        # the provider API.
        # We cannot call list_records() with the zone_id, we need to provide
        # a zone object. We will get that by calling the get_zone() method.
        try:
            records = self.connection.get_zone(zone_id).list_records()
            log.info("List records returned %d results for %s.",
                     len(records), self.cloud)
            return records
        except InvalidCredsError as exc:
            log.warning("Invalid creds on running list_recordss on %s: %s",
                        self.cloud, exc)
            raise CloudUnauthorizedError()
        except ssl.SSLError as exc:
            log.error("SSLError on running list_recordss on %s: %s",
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)
        except ZoneDoesNotExistError as exc:
            log.warning("No zone found for %s in: %s ", zone_id, self.cloud)
            raise ZoneNotFoundError(exc=exc)
        except Exception as exc:
            log.exception("Error while running list_records on %s", self.cloud)
            raise CloudUnavailableError(exc=exc)

    def _list_records__postparse_data(self, pr_record, record):
        """Postparse the records returned from the provider"""
        data = pr_record.data
        if pr_record.type == "CNAME":
            if not data.endswith('.'):
                data += '.'
        if data not in record.rdata:
            record.rdata.append(data)

    def _list_records__record_creation_date(self, libcloud_record):
        return libcloud_record.extra.get('created_at')

    def delete_record(self, record, expire=False):
        """
        Public method to be called with a zone and record ids to delete the
        specific record under the specified zone.
        """
        self._delete_record__from_id(record.zone.external_id,
                                     record.external_id)
        self.list_zones()
        from mist.api.poller.models import ListZonesPollingSchedule
        ListZonesPollingSchedule.add(cloud=self.cloud, interval=10, ttl=120)

    def _delete_record__from_id(self, zone_id, record_id):
        """
        We use the zone and record ids to delete the specific record under the
        specified zone.
        """
        try:
            self.connection.get_record(zone_id, record_id).delete()
        except ZoneDoesNotExistError as exc:
            log.warning("No zone found for %s in: %s ", zone_id, self.cloud)
            raise ZoneNotFoundError(exc=exc)
        except RecordDoesNotExistError as exc:
            log.warning("No record found for id: %s under zone %s",
                        record_id, zone_id)
            raise RecordNotFoundError(exc=exc)
        except Exception as exc:
            log.exception("Error while running delete_record on %s",
                          self.cloud)
            raise CloudUnavailableError(exc=exc)

    def delete_zone(self, zone, expire=False):
        """
        Public method called to delete the specific zone for the provided id.
        """
        self._delete_zone__for_cloud(zone.external_id)
        from mist.api.poller.models import ListZonesPollingSchedule
        ListZonesPollingSchedule.add(cloud=self.cloud, interval=10, ttl=120)

    def _delete_zone__for_cloud(self, external_id):
        """
        We use the zone id to retrieve and delete it for this cloud.
        """
        try:
            self.connection.get_zone(external_id).delete()
        except ZoneDoesNotExistError as exc:
            log.warning(
                "No zone found for %s in: %s ", external_id, self.cloud)
            raise ZoneNotFoundError(exc=exc)
        except Exception as exc:
            log.exception("Error while running delete_zone on %s", self.cloud)
            raise CloudUnavailableError("Failed to delete zone: %s " % exc)

    def create_zone(self, zone, **kwargs):
        """
        This is the public method that is called to create a new DNS zone.
        """
        self._create_zone__prepare_args(kwargs)
        libcloud_zone = self._create_zone__for_cloud(**kwargs)

        # Invoke `self.list_zones` to update the UI and return the Zone
        # object at the API. Try 3 times before failing
        for _ in range(3):
            for z in self.list_zones():
                if z.external_id == libcloud_zone.id:
                    return z
            time.sleep(1)
        raise mist.api.exceptions.ZoneListingError()

    def _create_zone__prepare_args(self, kwargs):
        """ This private method to prepare the args for the zone creation."""
        if not kwargs['domain'].endswith('.'):
            kwargs['domain'] += '.'

    def _create_zone__for_cloud(self, **kwargs):
        """
        This is the private method called to create a record under a specific
        zone. The underlying functionality is implement in the same way for
        all available providers so there shouldn't be any reason to override
        this.
        ----
        """
        try:
            zone = self.connection.create_zone(**kwargs)
            log.info("Zone %s created successfully for %s.",
                     zone.domain, self.cloud)
            return zone
        except InvalidCredsError as exc:
            log.warning("Invalid creds on running create_zone on %s: %s",
                        self.cloud, exc)
            raise CloudUnauthorizedError()
        except ssl.SSLError as exc:
            log.error("SSLError on running create_zone on %s: %s",
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)
        except Exception as exc:
            log.exception("Error while running create_zone on %s", self.cloud)
            raise ZoneCreationError("Failed to create zone, "
                                    "got error: %s" % exc, exc)

    def create_record(self, record, **kwargs):
        """
        This is the public method that is called to create a new DNS record
        under a specific zone.
        """
        from mist.api.dns.models import Record
        record.name = kwargs['name']
        record.type = kwargs['type']
        if isinstance(kwargs['data'], list):
            record.rdata = kwargs['data']
        else:
            record.rdata = [kwargs['data']]
        record.ttl = kwargs['ttl']

        try:
            record.clean()
        except me.ValidationError as exc:
            log.error("Error validating %s: %s", record, exc.to_dict())
            raise BadRequestError({'msg': str(exc),
                                   'errors': exc.to_dict()})

        self._create_record__prepare_args(record.zone, kwargs)
        libcloud_record = self._create_record__for_zone(record.zone, **kwargs)
        # Invoke `zone.ctl.list_records` to update the UI and return the Record
        # object at the API. Try 3 times before failing
        for _ in range(3):
            # FIXME: Replace with record.zone.ctl.list_records()
            # we run list_zones instead because it also emits patches to the UI
            self.list_zones()
            try:
                return Record.objects.get(
                    owner=self.cloud.owner, zone=record.zone,
                    external_id=libcloud_record.id,
                    missing_since=None)
            except Record.DoesNotExist:
                time.sleep(1)
        raise mist.api.exceptions.RecordListingError()

    def _create_record__for_zone(self, zone, **kwargs):
        """
        This is the private method called to create a record under a specific
        zone. The underlying functionality is implement in the same way for
        all available providers so there shouldn't be any reason to override
        this.
        ----
        """
        try:
            zone = self.connection.get_zone(zone.external_id)
            record = zone.create_record(**kwargs)
            log.info("Type %s record created successfully for %s.",
                     record.type, self.cloud)
            return record
        except InvalidCredsError as exc:
            log.warning("Invalid creds on running create_record on %s: %s",
                        self.cloud, exc)
            raise CloudUnauthorizedError()
        except ssl.SSLError as exc:
            log.error("SSLError on running create_record on %s: %s",
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)
        except ZoneDoesNotExistError as exc:
            log.warning("No zone found for %s in: %s ", zone.external_id,
                        self.cloud)
            raise ZoneNotFoundError(exc=exc)
        except Exception as exc:
            log.exception("Error while running create_record on %s",
                          self.cloud)
            raise RecordCreationError("Failed to create record, "
                                      "got error: %s" % exc, exc)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method that should be implemented for each specific
        provider depending on how they expect the record data.
        ---
        """
        if kwargs['type'] == 'CNAME':
            kwargs['data'] = kwargs['data'].rstrip('.')
        if kwargs['type'] == 'TXT':
            if not kwargs['data'].endswith('"'):
                kwargs['data'] += '"'
            if not kwargs['data'].startswith('"'):
                kwargs['data'] = '"' + kwargs['data']
        if kwargs['name'].endswith(zone.domain):
            kwargs['name'] = kwargs['name'][:-(len(zone.domain) + 1)]
        kwargs.pop('ttl')

    @staticmethod
    def find_best_matching_zone(owner, name):
        """
        This is a static method that tries to extract a valid domain from
        the name provided, trying to find the best matching DNS zone. This only
        works with 'A', 'AAAA' and 'CNAME' type records.
        This is common for all providers, there's no need to override this.
        ---
        """
        # TODO: Adding here for circular dependency issue. Need to fix this.
        from mist.api.dns.models import Zone

        # Split hostname in dot separated parts.
        parts = [part for part in name.split('.') if part]
        # Find all possible domains for this domain name,
        # longest first
        all_domains = {}
        for i in range(1, len(parts) - 1):
            subdomain = '.'.join(parts[:i])
            domain = '.'.join(parts[i:]) + '.'
            all_domains[domain] = subdomain
        if not all_domains:
            raise BadRequestError("Couldn't extract a valid domain from "
                                  "the provided '%s'." % name)

        zones = Zone.objects(owner=owner)
        # We need to iterate over all the cloud DNS zones to find
        # any that is matching based on the domain. If one is found
        # then create an "A" type record with the provided name.
        for zone_candidate in zones:
            for domain, subdomain in all_domains.items():
                if zone_candidate.domain == domain:
                    return zone_candidate
        raise BadRequestError("No DNS zone found, can't proceed with "
                              "creating record '%s'." % name)
