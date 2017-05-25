import logging

import sendgrid

from mist.api.users.models import User, Organization, Owner
import models


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
        user = User.objects(id=notification.user_id)
        mail.from_email = Email(config.EMAIL_REPORT_SENDER, "Mist.io Reports")
        personalization = Personalization()
        personalization.add_to(Email(user.email))
        personalization.subject = notification.subject
        personalization.add_substitution(Substitution("%name%", owner["name"]))
        mail.add_personalization(personalization)

        mail.add_content(Content("text/plain", notification.summary))
        mail.add_content(Content("text/plain", notification.body))
        # TODO: add HTML formatting to notifications? Implement HTML sending somehow..
        #mail.add_content(Content("text/html", report_dict["html_template"]))

        mdict = mail.get()
        try:
            return sg_instance.client.mail.send.post(request_body=mdict)
        except Exception as exc:
            print str(exc)
            print exc.read()


class StdoutChannel(BaseChannel):
	'''
	Stdout channel, mainly for testing/debugging
	'''
	def send(self, notification):
		print notification.subject
		if notification.summary:
			print notification.summary
		print notification.body


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