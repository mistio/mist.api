"""Cloud DNS Sub-Controllers

A cloud's DNS sub-controller handles all calls to libcloud's DNS API by
subclassing and extending the `BaseDNSController`.

Most often for each different cloud type, there is a corresponding DNS
controller defined here. All the different classes inherit `BaseDBSController`
and share a commmon interface, with the exception that some controllers may
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

log = logging.getLogger(__name__)


class AmazonDNSController(BaseDNSController):
    """
    Amazon Route53 specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.ROUTE53)(self.cloud.apikey,
                                            self.cloud.apisecret)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        # Route53 requires just the subdomain for A, AAAA, CNAME, MX records.
        if kwargs['name'].endswith(zone.domain):
            kwargs['name'] = kwargs['name'][:-(len(zone.domain) + 1)]
        if kwargs['type'] == 'CNAME' and not kwargs['data'].endswith('.'):
            kwargs['data'] += '.'
        # Route 53 requires TXT rdata to be whitin quotes
        if kwargs['type'] == 'TXT':
            if not kwargs['data'].endswith('"'):
                kwargs['data'] += '"'
            if not kwargs['data'].startswith('"'):
                kwargs['data'] = '"' + kwargs['data']
        kwargs['extra'] = {'ttl': kwargs.pop('ttl', 0)}

    def _create_zone__prepare_args(self, kwargs):
        if not kwargs['domain'].endswith('.'):
            kwargs['domain'] += '.'

    def _list_records__postparse_data(self, pr_record, record):
        """Get the provider specific information into the Mongo model"""
        if pr_record.data not in record.rdata:
            record.rdata.append(pr_record.data)


class DigitalOceanDNSController(BaseDNSController):
    """
    DigitalOcean specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.DIGITAL_OCEAN)(self.cloud.token)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        if kwargs['type'] == 'CNAME' and not kwargs['data'].endswith('.'):
            kwargs['data'] += '.'
        # DO requires TXT rdata to be whitin quotes
        if kwargs['type'] == 'TXT':
            if not kwargs['data'].endswith('"'):
                kwargs['data'] += '"'
            if not kwargs['data'].startswith('"'):
                kwargs['data'] = '"' + kwargs['data']
        if kwargs['type'] == 'MX':
            parts = kwargs['data'].split(' ')
            kwargs['extra'] = {'priority': parts[0]}
            kwargs['data'] = parts[1]
        # DO does not accept a ttl, if there is then remove it
        kwargs.pop('ttl', 0)

    def _create_zone__prepare_args(self, kwargs):
        if kwargs['domain'].endswith('.'):
            kwargs['domain'] = kwargs['domain'][:-1]

    def _list_records__postparse_data(self, pr_record, record):
        """Get the provider specific information into the Mongo model"""
        if pr_record.type == "CNAME" and not pr_record.data.endswith('.'):
            pr_record.data += '.'
        if pr_record.data not in record.rdata:
            record.rdata.append(pr_record.data)


class GoogleDNSController(BaseDNSController):
    """
    Google DNS provider specific overrides.
    """
    def _connect(self):
        return get_driver(Provider.GOOGLE)(self.cloud.email,
                                           self.cloud.private_key,
                                           project=self.cloud.project_id)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        # Google requires the full subdomain+domain for A, AAAA, and CNAME
        # records with a trailing dot.
        if (kwargs['type'] in ['A', 'AAAA', 'CNAME'] and
                not kwargs['name'].endswith('.')):
            kwargs['name'] += "."
        if kwargs['type'] == 'CNAME' and not kwargs['data'].endswith('.'):
            kwargs['data'] += '.'

        data = kwargs.pop('data', '')
        kwargs['data'] = {'ttl': kwargs.pop('ttl', 0), 'rrdatas': []}
        kwargs['data']['rrdatas'].append(data)

    def _create_zone__prepare_args(self, kwargs):
        if not kwargs['domain'].endswith('.'):
            kwargs['domain'] += '.'

    def _list_records__postparse_data(self, pr_record, record):
        """Get the provider specific information into the Mongo model"""
        record.rdata = pr_record.data['rrdatas']


class LinodeDNSController(BaseDNSController):
    """
    Linode specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.LINODE)(self.cloud.apikey)

    def _create_zone__prepare_args(self, kwargs):
        if kwargs['type'] == "master":
            kwargs['extra'] = {'SOA_Email': kwargs.pop('SOA_Email', "")}
        if kwargs['type'] == "slave":
            kwargs['extra'] = {'master_ips': kwargs.pop('master_ips', "")}

    def _list_records__postparse_data(self, pr_record, record):
        """Get the provider specific information into the Mongo model"""
        if pr_record.type in ["CNAME", "MX"] and not pr_record.data.endswith('.'):
            pr_record.data += '.'
        if pr_record.data not in record.rdata:
            record.rdata.append(pr_record.data)

    def _create_record__prepare_args(self, zone, kwargs):
        """
        This is a private method to transform the arguments to the provider
        specific form.
        ---
        """
        # Linode requires just the subdomain for A, AAAA, CNAME, MX records.
        if kwargs['name'].endswith(zone.domain) and kwargs['type']:
            kwargs['name'] = kwargs['name'][:-(len(zone.domain) + 1)]
        # if kwargs['type'] == 'CNAME' and not kwargs['data'].endswith('.'):
        #     kwargs['data'] += '.'
        if kwargs['type'] == 'CNAME' and kwargs['data'].endswith('.'):
            kwargs['data'] = kwargs['data'][:-1]
        print "kwargs: %s" % kwargs
        # Linode requires TXT rdata to be whitin quotes
        if kwargs['type'] == 'TXT':
            if not kwargs['data'].endswith('"'):
                kwargs['data'] += '"'
            if not kwargs['data'].startswith('"'):
                kwargs['data'] = '"' + kwargs['data']
        # Linode does not accept a ttl, if there is then remove it
        kwargs.pop('ttl', 0)


class RackSpaceDNSController(BaseDNSController):
    """
    RackSpace specific overrides.
    """

    def _connect(self):
        if self.cloud.region in ('us', 'uk'):
            driver = get_driver(Provider.RACKSPACE_FIRST_GEN)
        else:
            driver = get_driver(Provider.RACKSPACE)
        return driver(self.cloud.username, self.cloud.apikey,
                      region=self.cloud.region)


class SoftLayerDNSController(BaseDNSController):
    """
    SoftLayer specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.SOFTLAYER)(self.cloud.username,
                                              self.cloud.apikey)

    def _create_zone__prepare_args(self, kwargs):
        if kwargs['type']:
            kwargs.pop('type', None)

    def _list_records__postparse_data(self, pr_record, record):
        """Get the provider specific information into the Mongo model"""
        if pr_record.data not in record.rdata:
            record.rdata.append(pr_record.data)


class VultrDNSController(BaseDNSController):
    """
    Vultr specific overrides.
    """

    def _connect(self):
        return get_driver(Provider.VULTR)(self.cloud.apikey)

    def _create_zone__prepare_args(self, kwargs):
        if 'ip' in kwargs:
            kwargs['extra'] = {'serverip': kwargs.pop('ip', None)}

    def _list_records__postparse_data(self, pr_record, record):
        """Get the provider specific information into the Mongo model"""
        if pr_record.type == "CNAME" and not pr_record.data.endswith('.'):
            pr_record.data += '.'
        if pr_record.data not in record.rdata:
            record.rdata.append(pr_record.data)
