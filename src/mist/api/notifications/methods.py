import os
import json
import time
import urllib
import logging
import datetime

from chameleon import PageTemplateFile

from mist.api import config
from mist.api.helpers import encrypt
from mist.api.helpers import mac_sign

from mist.api.rules.models import Rule
from mist.api.users.models import User
from mist.api.users.models import Organization

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine

from mist.api.notifications.models import EmailAlert
from mist.api.notifications.models import InAppRecommendation

from mist.api.notifications.helpers import _log_alert
from mist.api.notifications.helpers import _alert_pretty_details


log = logging.getLogger(__name__)


# TODO: Shouldn't be specific to machines. Should pass in a (resource_type,
# resource_id) tuple in order to fetch the corresponding mongoengine object
# and the verify ownership.
def send_alert_email(owner, rule_id, value, triggered, timestamp, incident_id,
                     cloud_id, machine_id, action=''):
    """Notify owner that alert was triggered.

    params:
        owner: The owner object of the owner whose alert is being triggered.
        rule_id: The id of the rule triggered. None if it's a dummy rule.
        value: The current value of the rules metric. None if no data alert.
        cloud_id, machine_id: Required iff rule_id is None.
        action: Optional, will override the action string sent by email
        trigger: Not sure what this is, but it sure is required.
    """
    # Get rule.
    rule = Rule.objects.get(id=rule_id, owner_id=owner.id)

    # Get resource. FIXME: Shouldn't be specific to machines.
    machine = Machine.objects.get(owner=owner, machine_id=machine_id)

    # FIXME: This should be deprecated and replaced with a more generic one.
    info = _alert_pretty_details(owner, rule.title, value, triggered,
                                 timestamp, cloud_id, machine_id, action)

    # Create a new EmailAlert if the alert has just been triggered.
    try:
        alert = EmailAlert.objects.get(owner=owner, incident_id=incident_id)
    except EmailAlert.DoesNotExist:
        alert = EmailAlert(owner=owner, incident_id=incident_id)
        # Allows unsubscription from alerts on a per-rule basis.
        alert.rid = rule.id
        alert.rtype = 'rule'
        # Allows reminder alerts to be sent.
        alert.reminder_enabled = True
        # Allows to log newly triggered incidents.
        skip_log = False
    else:
        skip_log = False if not triggered else True
        reminder = ' - Reminder %d' % alert.reminder_count if triggered else ''
        info['action'] += reminder

    # Check whether an alert has to be sent in case of a (re)triggered rule.
    if triggered and not alert.is_due():
        log.info('Alert for %s is due in %s', rule, alert.due_in())
        return

    # Create the e-mail body.
    subject = '[mist.io] *** %(state)s *** from %(name)s: %(metric_name)s'
    alert.subject = subject % info

    pt = os.path.join(os.path.dirname(__file__), 'templates/text_alert.pt')
    alert.text_body = PageTemplateFile(pt)(inputs=info)

    pt = os.path.join(os.path.dirname(__file__), 'templates/html_alert.pt')
    alert.html_body = PageTemplateFile(pt)(inputs=info)

    # Concat all e-mail addresses. FIXME This shouldn't be here. It must be
    # returned by the mist.api.rules.actions.NotificationAction.
    emails = set(rule.emails)
    for email_list in (owner.get_emails(), owner.alerts_email or [], ):
        emails |= set(email_list)

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

    # Log (un)triggered alert. FIXME Needs to be able to log event for a
    # variety of resource, not just machines. Replace `title` with `rule.id`.
    if skip_log is False:
        _log_alert(machine.owner, rule.title, value, triggered, timestamp,
                   incident_id, cloud_id=machine.cloud.id,
                   machine_id=machine.machine_id)


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
    recommendation.applied = feedback == "POSITIVE"
    user_ids = set(user.id for user in machine.owner.members)
    user_ids ^= set(recommendation.dismissed_by)
    recommendation.channel.dismiss(
        users=[user for user in User.objects(id__in=user_ids).only('id')]
    )
