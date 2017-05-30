
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


class SendgridChannel(BaseChannel):
    '''
    Sendgrid (email) channel
    '''
    sg_instance = sendgrid.SendGridAPIClient(
        apikey=config.SENDGRID_REPORTING_KEY)

    def send(self, notification):
        mail = Mail()
        mail.from_email = Email(config.EMAIL_REPORT_SENDER, "Mist.io Reports")
        personalization = Personalization()
        personalization.add_to(Email(notification["email"]))
        personalization.subject = notification["subject"]
        personalization.add_substitution(
            Substitution("%name%", notification["name"]))
        mail.add_personalization(personalization)

        if "html_body" in notification:
            mail.add_content(Content("text/html", notification["html_body"]))
        mail.add_content(Content("text/plain", notification["body"]))

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
    elif name == 'email':
        return SendgridChannel()
    return None
