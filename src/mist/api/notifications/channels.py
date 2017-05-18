
from sendgrid.helpers.mail import (Email,
                                   Mail,
                                   Personalization,
                                   Content,
                                   Substitution)
import sendgrid

from mist.api import config

class BaseChannel():

	def send(self, notification, user):
		'''
		Accepts a Notification and a User instance and sends
		the notification to the user.
		This method should be subclassed for each concrete
		channel implementation.
		'''
		pass


 class SendgridChannel(BaseChannel):
 	sg_instance = sendgrid.SendGridAPIClient(
        	apikey=config.SENDGRID_REPORTING_KEY)

 	def send(self, notification, user):

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
