"""Cloud DNS Sub-Controllers

A cloud's DNS sub-controller handles all calls to libcloud's DNS API by
subclassing and extending the `BaseDNSController`.

Most often for each different cloud type, there is a corresponding DNS
controller defined here. All the different classes inherit `BaseDBSController`
and share a common interface, with the exception that some controllers may
not have implemented all methods. It is also possible that certain cloud types
do not possess their own DNS controller, but rather utilize the base
`BaseDNSController`.

A DNS controller is initialized given a cloud's main controller, which is
derived from `BaseController`. That way, all sub-controllers of a given cloud
will be interconnected at the main controller's level.

Most of the time a sub-controller will be accessed through a cloud's main
controller, using the `ctl` abbreviation, like this:

    cloud = mist.api.clouds.models.Cloud.objects.get(id=cloud_id)
    print cloud.ctl.dns.list_zones()

"""

import logging

from libcloud.dns.types import Provider
from libcloud.dns.providers import get_driver

from mist.api.clouds.controllers.dns.base import BaseDNSController

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import RequiredParameterMissingError


log = logging.getLogger(__name__)


class AmazonDNSController(BaseDNSController):
    """
    Amazon Route53 specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.ROUTE53)(self.cloud.apikey,
                                            self.cloud.apisecret.value)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        kwargs['extra'] = {'ttl': kwargs.get('ttl', 0)}
        super(AmazonDNSController, self)._create_record__prepare_args(
            zone, kwargs)
        if kwargs['type'] == 'CNAME':
            kwargs['data'] += '.'


class GoogleDNSController(BaseDNSController):
    """
    Google DNS provider specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.GOOGLE)(self.cloud.email,
                                           self.cloud.private_key.value,
                                           project=self.cloud.project_id)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        if kwargs['type'] == 'CNAME':
            kwargs['data'] += '.'
        # For MX records Google requires the data in the form:
        # XX DOMAIN.COM. where XX is the record priority (an integer)
        # and the domain needs to end with a dot, so if it's not there
        # we need to append it.
        if kwargs['type'] == 'MX' and not kwargs['data'].endswith('.'):
            kwargs['data'] += '.'
        data = kwargs.pop('data')
        kwargs['data'] = {'ttl': kwargs.pop('ttl', 0), 'rrdatas': []}
        kwargs['data']['rrdatas'].append(data)

    def _list_records__postparse_data(self, pr_record, record):
        """Get the provider specific information into the Mongo model"""
        record.rdata = pr_record.data['rrdatas']


class LinodeDNSController(BaseDNSController):
    """
    Linode specific overrides.
    """

    def _connect(self):
        if self.cloud.apiversion is None:
            return get_driver(Provider.LINODE)(self.cloud.apikey.value)
        else:
            return get_driver(Provider.LINODE)(
                self.cloud.apikey.value,
                api_version=self.cloud.apiversion)

    def _create_zone__prepare_args(self, kwargs):
        """
        Parse keyword arguments. The request can contain
        either `SOA_Email` or `SOA_email` and `master_ips`
        independently of type
        """
        if 'SOA_email' in kwargs:
            soa_email = kwargs.pop('SOA_email', '')
        elif 'SOA_Email' in kwargs:
            soa_email = kwargs.pop('SOA_Email', '')
        if 'master_ips' in kwargs:
            ips = kwargs.pop('master_ips', '')

        if kwargs['type'] == "master":
            if self.cloud.apiversion is None:
                kwargs['extra'] = {'soa_email': soa_email}
            else:
                kwargs['extra'] = {'SOA_Email': soa_email}
        if kwargs['type'] == "slave":
            if not isinstance(ips, list):
                ips = ips.split()
            kwargs['extra'] = {'master_ips': ips}

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        super(LinodeDNSController, self)._create_record__prepare_args(
            zone, kwargs)
        if kwargs['type'] == 'MX':
            parts = kwargs['data'].split(' ')
            if len(parts) == 2:
                kwargs['data'] = parts[1]
            elif len(parts) == 1:
                kwargs['data'] = parts[0]
            else:
                raise BadRequestError('Please provide only the '
                                      'mailserver hostname')

    def _list_zones__fetch_zones(self):
        """
        Overridden to convert datetime objects to isoformat in order to
        be json serializable
        """
        zones = super(LinodeDNSController, self)._list_zones__fetch_zones()
        from datetime import datetime
        for zone in zones:
            if 'created' in zone.extra and \
                    isinstance(zone.extra['created'], datetime):
                zone.extra['created'] = zone.extra['created'].isoformat()
            if 'updated' in zone.extra and \
                    isinstance(zone.extra['updated'], datetime):
                zone.extra['updated'] = zone.extra['updated'].isoformat()
        return zones

    def _list_records__fetch_records(self, zone_id):
        """
        Overridden to convert datetime objects to isoformat in order to
        be json serializable
        """
        records = super(
            LinodeDNSController, self)._list_records__fetch_records(zone_id)
        from datetime import datetime
        for record in records:
            if 'created' in record.extra and \
                    isinstance(record.extra['created'], datetime):
                record.extra['created'] = record.extra['created'].isoformat()
            if 'updated' in record.extra and \
                    isinstance(record.extra['updated'], datetime):
                record.extra['updated'] = record.extra['updated'].isoformat()
        return records


class RackSpaceDNSController(BaseDNSController):
    """
    RackSpace specific overrides.
    """

    def _connect(self):
        if self.cloud.region in ('dfw', 'ord', 'iad'):
            region = 'us'
        elif self.cloud.region == 'lon':
            region = 'uk'
        driver = get_driver(Provider.RACKSPACE)
        return driver(self.cloud.username, self.cloud.apikey.value,
                      region=region)

    def _create_zone__prepare_args(self, kwargs):
        kwargs['extra'] = {'email': kwargs.pop('email', "")}

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        super(RackSpaceDNSController, self)._create_record__prepare_args(
            zone, kwargs)
        if kwargs['type'] == 'MX':
            parts = kwargs['data'].split(' ')
            kwargs['extra'] = {'priority': parts[0]}
            kwargs['data'] = parts[1]


class DigitalOceanDNSController(RackSpaceDNSController):
    """
    DigitalOcean specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.DIGITAL_OCEAN)(self.cloud.token.value)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        super(DigitalOceanDNSController, self)._create_record__prepare_args(
            zone, kwargs)
        if kwargs['type'] in ['CNAME', 'MX']:
            kwargs['data'] += '.'

    def _create_zone__prepare_args(self, kwargs):
        kwargs['domain'] = kwargs['domain'].rstrip('.')


class SoftLayerDNSController(BaseDNSController):
    """
    SoftLayer specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.SOFTLAYER)(self.cloud.username,
                                              self.cloud.apikey.value)

    def _create_zone__prepare_args(self, kwargs):
        kwargs.pop('type')


class VultrDNSController(BaseDNSController):
    """
    Vultr specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.VULTR)(self.cloud.apikey.value)

    def _create_zone__prepare_args(self, kwargs):
        if not kwargs.get('ip'):
            raise RequiredParameterMissingError('ip')
        kwargs['extra'] = {'ip': kwargs.pop('ip')}

    def _create_record__prepare_args(self, zone, kwargs):
        super()._create_record__prepare_args(zone, kwargs)
        if kwargs['type'] == 'MX':
            parts = kwargs['data'].split(' ')
            kwargs['extra'] = {'priority': parts[0]}
            kwargs['data'] = parts[1]
