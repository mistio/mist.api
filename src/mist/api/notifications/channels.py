
from chameleon import PageTemplateFile
from sendgrid.helpers.mail import (Email,
                                   Mail,
                                   Personalization,
                                   Content,
                                   Substitution)
import sendgrid

from mist.api.users.models import User
from mist.api import config


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


class WeeklyReportsChannel(BaseChannel):
    '''
    Sendgrid (email) channel for weekly reports
    '''

    sg_instance = sendgrid.SendGridAPIClient(
        apikey=config.SENDGRID_REPORTING_KEY)

    def send(self, notification):
        user = notification["user"]
        org = notification["org"]

        mail = Mail()
        mail.from_email = Email(config.EMAIL_REPORT_SENDER, "Mist.io Reports")
        personalization = Personalization()
        email = Email(notification.get("email", user.email),
                      notification.get("full_name", user.get_nice_name()))
        personalization.add_to(email)
        personalization.subject = notification["subject"]
        sub1 = Substitution("%name%", notification.get(
            "name", user.first_name or user.get_nice_name()))
        personalization.add_substitution(sub1)
        if "unsub_link" in notification:
            sub2 = Substitution("%nsub%", notification["unsub_link"])
            personalization.add_substitution(sub2)
        mail.add_personalization(personalization)

        mail.add_content(Content("text/plain", notification["body"]))
        if "html_body" in notification:
            mail.add_content(Content("text/html", notification["html_body"]))

        mdict = mail.get()
        try:
            return self.sg_instance.client.mail.send.post(request_body=mdict)
        except Exception as exc:
            print str(exc)
            print exc.read()


class StdoutChannel(BaseChannel):
    '''
    Stdout channel, mainly for testing/debugging
    '''

    def send(self, notification):
        print notification["subject"]
        if "summary" in notification:
            print notification["summary"]
        print notification["body"]


def channel_instance_with_name(name):
    '''
    Accepts a string and returns a channel instance with
    matching name or None
    '''
    if name == 'stdout':
        return StdoutChannel()
    elif name == 'weekly_reports':
        return WeeklyReportsChannel()
    return None
