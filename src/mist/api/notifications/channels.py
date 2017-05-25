import sendgrid

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
        personalization.add_to(Email(user.email))
        personalization.subject = notification.subject
        personalization.add_substitution(Substitution("%name%", owner["name"]))
        mail.add_personalization(personalization)

        mail.add_content(Content("text/plain", report_dict["text_template"]))
        mail.add_content(Content("text/html", report_dict["html_template"]))

        mdict = mail.get()
        try:
            return sg_instance.client.mail.send.post(request_body=mdict)
        except Exception as exc:
            print str(exc)
            print exc.read()
            sys.exit(1)


def channel_instance_with_name(name):
	'''
	Accepts a string and returns a channel instance with
	matching name or None
	'''
	if name == 'email':
		return SendgridChannel()
	return None