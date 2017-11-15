import json
import urllib2

import jsonpatch

from mist.api import config
from mist.api.helpers import send_email, amqp_publish_user

from mist.api.notifications.models import (Notification, NotificationOverride,
                                           EmailReport, InAppNotification)

import logging


class BaseChannel():
    '''
    Base notification channel class
    '''

    def send(self, notification):
        '''
        Accepts a notification and sends it using the
        current channel instance.
        '''
        pass

    def delete(self, notification):
        '''
        Accepts a notification and deletes it
        if it had been saved
        '''
        pass

    def dismiss(self, notification):
        '''
        Accepts a notification and marks it as
        dismissed by the user
        '''
        pass


class EmailNotificationsChannel(BaseChannel):
    '''
    Email channel for notifications.
    Tries to send using Sendgrid, if credentials are available
    in config, otherwise sends email using SMTP.
    '''

    def send(self, notification):
        '''
        Accepts a notification and sends an email using included data.
        If SENDGRID_EMAIL_NOTIFICATIONS_KEY is available
        in config, it uses Sendgrid to deliver the email. Otherwise, it
        uses plain SMTP through send_email()
        '''
        user = notification.user

        to = notification.email or user.email
        full_name = user.get_nice_name()
        first_name = user.first_name or user.get_nice_name()

        if (hasattr(config, "SENDGRID_EMAIL_NOTIFICATIONS_KEY")):
            from sendgrid.helpers.mail import (Email,
                                               Mail,
                                               Personalization,
                                               Content,
                                               Substitution)
            import sendgrid

            self.sg_instance = sendgrid.SendGridAPIClient(
                apikey=config.SENDGRID_EMAIL_NOTIFICATIONS_KEY)

            mail = Mail()
            mail.from_email = Email(notification.sender_email,
                                    notification.sender_title)
            personalization = Personalization()
            personalization.add_to(Email(to, full_name))
            personalization.subject = notification.subject
            sub1 = Substitution("%name%", first_name)
            personalization.add_substitution(sub1)
            if "unsub_link" in notification:
                sub2 = Substitution("%nsub%", notification.unsub_link)
                personalization.add_substitution(sub2)
            mail.add_personalization(personalization)

            mail.add_content(Content("text/plain", notification.body))
            if "html_body" in notification:
                mail.add_content(
                    Content(
                        "text/html",
                        notification.html_body))

            mdict = mail.get()
            try:
                return self.sg_instance.client.mail.send.post(
                    request_body=mdict)
            except urllib2.URLError as exc:
                logging.error(exc)
                exit()
            except Exception as exc:
                logging.error(str(exc.status_code) + ' - ' + exc.reason)
                logging.error(exc.to_dict)
                exit()
        else:
            send_email(notification.subject, notification.body,
                       [to], sender=notification.sender_email)


class InAppChannel(BaseChannel):
    '''
    In-app Notifications channel
    Manages notifications and triggers session updates
    '''

    def send(self, notification):

        def modify(notification):
            if notification.unique:
                similar = InAppNotification.objects(
                    user=notification.user,
                    organization=notification.organization,
                    machine=notification.machine,
                    tag=notification.tag,
                    cloud=notification.cloud,
                    model_id=notification.model_id)
                if similar:
                    # unfortunately, queryset does not support pop()
                    first = similar[0]
                    first.update_from(notification)
                    first.dismissed = False  # To display again
                    first.save()
                    for item in [item for item in similar if item != first]:
                        item.dismissed = True
                        item.save()
                else:
                    notification.save()
            else:
                notification.save()

        self._modify_and_notify(notification, modify)

    def delete(self, notification):

        def modify(notification):
            notification.delete()

        self._modify_and_notify(notification, modify)

    def dismiss(self, notification):

        def modify(notification):
            notification.dismissed = True
            notification.save()

        self._modify_and_notify(notification, modify)

    def _modify_and_notify(self, notification, modifier):
        user = notification.user

        old_notifications = [
            json.loads(obj.to_json()) for obj in InAppNotification.objects(
                user=user,
                dismissed=False)
        ]
        modifier(notification)
        new_notifications = [
            json.loads(obj.to_json()) for obj in InAppNotification.objects(
                user=user,
                dismissed=False)
        ]
        patch = jsonpatch.JsonPatch.from_diff(
            old_notifications, new_notifications).patch
        if patch:
            data = json.dumps({
                "user": user.id,
                "patch": patch
            }, cls=NotificationsEncoder)
            amqp_publish_user(notification.organization,
                              routing_key='patch_notifications',
                              data=data)


class NotificationsEncoder(json.JSONEncoder):
    '''
    JSON Encoder that properly handles Notification
    instances
    '''

    def default(self, o):
        if (isinstance(o, Notification) or
                isinstance(o, NotificationOverride)):
            # FIXME: this is kind of dumb, but it works
            return json.loads(o.to_json())
        else:
            return json.JSONEncoder.default(self, o)


def channel_instance_for_notification(notification):
    '''
    Accepts a notification instance and returns
    an instance of the corresponding channel
    '''
    if isinstance(notification, EmailNotification):
        return EmailNotificationsChannel()
    elif isinstance(notification, InAppNotification):
        return InAppChannel()
    return None
