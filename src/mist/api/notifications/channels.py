import json
import jsonpatch

from mist.api import config
from mist.api.helpers import send_email, amqp_publish_user

from models import Notification

import logging


class BaseChannel():
    '''
    Represents a notification channel
    '''

    def send(self, notification):
        '''
        Accepts a notification and sends it using the
        current channel instance.
        '''
        pass

    def delete(self, notification_id):
        '''
        Accepts a notification id and deletes the
        corresponding notification
        '''
        pass


class EmailReportsChannel(BaseChannel):
    '''
    Email channel for reports.
    Tries to send using Sendgrid, if credentials are available
    in config, otherwise sends email using SMTP.
    '''

    def send(self, notification):
        '''
        Accepts a notification and sends an email using included data.
        If SENDGRID_REPORTING_KEY and EMAIL_REPORT_SENDER are available
        in config, it uses Sendgrid to deliver the email. Otherwise, it
        uses plain SMTP through send_email()
        '''
        user = notification.user

        to = notification.email or user.email
        full_name = user.get_nice_name()
        first_name = user.first_name or user.get_nice_name()

        if (hasattr(config, "SENDGRID_REPORTING_KEY") and
                hasattr(config, "EMAIL_REPORT_SENDER")):
            from sendgrid.helpers.mail import (Email,
                                               Mail,
                                               Personalization,
                                               Content,
                                               Substitution)
            import sendgrid

            self.sg_instance = sendgrid.SendGridAPIClient(
                apikey=config.SENDGRID_REPORTING_KEY)

            mail = Mail()
            mail.from_email = Email(
                config.EMAIL_REPORT_SENDER,
                "Mist.io Reports")
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
            except Exception as exc:
                logging.error(str(exc.status_code) + ' - ' + exc.reason)
                logging.error(exc.to_dict)
                exit()
        else:
            send_email(notification.subject, notification.body,
                       [to], sender="config.EMAIL_REPORT_SENDER")


class InAppChannel(BaseChannel):
    '''
    In-app Notifications channel
    Manages notifications and triggers session updates
    '''

    def send(self, notification):

        def modify(notification):
            notification.save()

        self.modify_and_notify(notification, modify)

    def delete(self, notification):

        def modify(notification):
            notification.delete()

        self.modify_and_notify(notification, delete)

    def dismiss(self, notification):

        def modify(notification):
            notification.dismissed = True
            notification.save()

        self.modify_and_notify(notification, delete)

    def modify_and_notify(self, notification, modifier):
        user = notification.user
        old_notifications = Notification.objects(
            user=user, dismissed=False).to_json()
        modifier(notification)
        new_notifications = Notification.objects(
            user=user, dismissed=False).to_json()
        patch = jsonpatch.JsonPatch.from_diff(
            old_notifications, new_notifications).patch
        if patch:
            amqp_publish_user(notification.organization,
                              routing_key='notification',
                              data=json.dumps({
                                  "user": user,
                                  "patch": patch
                              }))


class StdoutChannel(BaseChannel):
    '''
    Stdout channel, mainly for testing/debugging
    '''

    def send(self, notification):
        print notification.subject
        if "summary" in notification:
            print notification.summary
        print notification.body


def channel_instance_with_name(name):
    '''
    Accepts a string and returns a channel instance with
    matching name or None
    '''
    if name == 'stdout':
        return StdoutChannel()
    elif name == 'email_reports':
        return EmailReportsChannel()
    elif name == 'in_app':
        return InAppChannel()
    return None
