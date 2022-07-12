import os
import json

# Python 2 and 3 support
from future.standard_library import install_aliases
install_aliases()
import urllib.request
import urllib.parse
import urllib.error

import logging

from chameleon import PageTemplateFile

from mist.api import config

from mist.api.helpers import encrypt
from mist.api.helpers import mac_sign
from mist.api.methods import notify_admin

from mist.api.rules.models import Rule
from mist.api.rules.models import NoDataRule
from mist.api.users.models import User

from mist.api.portal.models import Portal

from mist.api.notifications.models import EmailAlert
from mist.api.notifications.models import NoDataRuleTracker
from mist.api.notifications.models import InAppRecommendation

from mist.api.notifications.helpers import _get_alert_details


log = logging.getLogger(__name__)


def send_alert_email(rule, resource, incident_id, value, triggered, timestamp,
                     emails, action='', level='', description=''):
    """Send an alert e-mail to notify users that a rule was triggered.

    Arguments:

        rule:        The mist.api.rules.models.Rule instance that got
                     triggered.
        resource:    The resource for which the rule got triggered.
                     For a subclass of `ResourceRule` his has to be a
                     `me.Document` subclass. If the rule is arbitrary,
                     then this argument must be set to None.
        incident_id: The UUID of the incident. Each new incident gets
                     assigned a UUID.
        value:       The value yielded by the rule's evaluation. This
                     is the value that's exceeded the given threshold.
        triggered:   True, if the rule has been triggered. Otherwise,
                     False.
        timestamp:   The UNIX timestamp at which the state of the rule
                     changed, went from triggered to un-triggered or
                     vice versa.
        emails:      A list of e-mails to push notifications to.
        action:      An optional action to replace the default "alert".
        description: An optional description to be added in the alert
                     email body.

    Note that alerts aren't sent out every time a rule gets triggered,
    rather they obey the `EmailAlert.reminder_schedule` schedule that
    denotes how often an e-mail may be sent.

    """
    assert isinstance(rule, Rule), type(rule)
    assert resource or rule.is_arbitrary(), type(resource)

    # Get dict with alert details.
    info = _get_alert_details(resource, rule, incident_id, value,
                              triggered, timestamp, action, level, description)

    # Create a new EmailAlert if the alert has just been triggered.
    try:
        alert = EmailAlert.objects.get(owner=rule.org,
                                       incident_id=incident_id)
    except EmailAlert.DoesNotExist:
        if not triggered:
            return
        alert = EmailAlert(owner=rule.org, incident_id=incident_id)
        # Allows unsubscription from alerts on a per-rule basis.
        alert.rid = rule.id
        alert.rtype = 'rule'
        # Allows reminder alerts to be sent.
        alert.reminder_enabled = True
        # Suppress alert.
        alert.suppressed = suppress_nodata_alert(rule)
        alert.save()
        # Allows to log newly triggered incidents.
    else:
        reminder = ' - Reminder %d' % alert.reminder_count if triggered else ''
        info['action'] += reminder

    if alert.suppressed:
        log.warning('Alert for %s suppressed since %s', rule, alert.created)
        return

    # Check whether an alert has to be sent in case of a (re)triggered rule.
    if triggered and not alert.is_due():
        log.info('Alert for %s is due in %s', rule, alert.due_in())
        return

    # Create the e-mail body.
    subject = \
        '[%(portal_name)s] *** %(state)s *** %(resource_type)s '\
        '`%(resource_name)s`: %(metric_name)s'
    alert.subject = subject % info

    info['condition'] = info['condition'].replace(
        '>', 'greater than').replace('<', 'less than').replace(
            '=', 'equals').replace('{}', '')
    pt = os.path.join(os.path.dirname(__file__), 'templates/text_alert.pt')
    alert.text_body = PageTemplateFile(pt)(inputs=info)

    pt = os.path.join(os.path.dirname(__file__), 'templates/html_alert.pt')
    alert.html_body = PageTemplateFile(pt)(inputs=info)

    # Send alert.
    alert.channel.send(list(emails))

    # We need to save the notification's state in order to look it up the next
    # time an alert will be re-triggered or untriggered for the given incident.
    # We also make sure to delete the notification in case the corresponding
    # alert has been untriggered, since (at least for now) there is no reason
    # to keep notifications via e-mail indefinetely.
    if triggered:
        alert.reminder_count += 1
        alert.save()
    else:
        alert.delete()


def suppress_nodata_alert(rule):

    if not (isinstance(rule, NoDataRule) and config.NO_DATA_ALERT_SUPPRESSION):
        return False

    if EmailAlert.objects(rtype='rule', suppressed=True).count():
        log.warning('Suppressed %s. Previous alerts suppressed, too', rule)
        return True

    # Get the number of no-data rules and of corresponding machines, which
    # have fired a trigger.
    freqs = NoDataRuleTracker.get_frequencies()
    nodata_rules_firing = len(freqs)
    mon_machines_firing = sum(freqs.values())

    # Get the total number of no-data rules and the number of machines
    # they're monitoring.
    total_nodata_rules = NoDataRule.objects.count()
    total_mon_machines = sum(r.get_resources().count() for
                             r in NoDataRule.objects())

    # If only a small number of no-data rules has been triggered, return.
    rules_ratio = round(nodata_rules_firing / (1. * total_nodata_rules), 2)
    if rules_ratio < config.NO_DATA_RULES_RATIO:
        return False

    # If a large enough number of no-data rules has been triggered, but
    # only for a small subset of all monitored machines, return.
    machines_ratio = round(mon_machines_firing / (1. * total_mon_machines), 2)
    if machines_ratio < config.NO_DATA_MACHINES_RATIO:
        return False

    def get_unsuppress_link(action):
        assert action in ('unsuppress', 'delete', )
        params = {'action': action,
                  'key': Portal.get_singleton().external_api_key}
        token = {'token': encrypt(json.dumps(params))}
        mac_sign(token)
        return '%s/suppressed-alerts?%s' % (config.PORTAL_URI,
                                            urllib.parse.urlencode(token))

    # Otherwise, suppress e-mail notification and notify the portal's admins.
    d = {
        'rule': rule,
        'total_num_monitored_machines': total_mon_machines,
        'total_number_of_nodata_rules': total_nodata_rules,
        'mon_machines_firing': mon_machines_firing,
        'nodata_rules_firing': nodata_rules_firing,
        'machines_percentage': machines_ratio * 100,
        'rules_percentage': rules_ratio * 100,
        'delete_alerts_link': get_unsuppress_link(action='delete'),
        'unsuppress_alerts_link': get_unsuppress_link(action='unsuppress'),
    }
    try:
        notify_admin(
            title=config.NO_DATA_ALERT_SUPPRESSION_SUBJECT.format(
                portal_name=config.PORTAL_NAME),
            message=config.NO_DATA_ALERT_SUPPRESSION_BODY % d
        )
    except Exception as exc:
        log.error('Suppressed %s. Failed to notify admins: %r', rule, exc)
    return True


def dismiss_scale_notifications(machine, feedback='NEUTRAL'):
    '''
    Convenience function to dismiss scale notifications from
    a machine.
    Calls dismiss on each notification's channel. May update
    the feedback field on each notification.
    '''
    recommendation = InAppRecommendation.objects(
        owner=machine.owner, model_id="autoscale_v1", rid=machine.id).first()
    # TODO Shouldn't we store which user executed the recommendations action?
    # Marking the recommendation as "dismissed by everyone" seems a bit wrong.
    # Perhaps recommendations' actions such as this one must be invoked by a
    # distinct API endpoint?
    if recommendation is not None:
        recommendation.applied = feedback == "POSITIVE"
        user_ids = set(user.id for user in machine.owner.members)
        user_ids ^= set(recommendation.dismissed_by)
        recommendation.channel.dismiss(
            users=[user for user in User.objects(id__in=user_ids).only('id')]
        )
