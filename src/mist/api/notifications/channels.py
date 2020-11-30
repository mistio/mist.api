# Python 2 and 3 support
from future.standard_library import install_aliases
install_aliases()
import urllib.request
import urllib.error
import urllib.parse

import logging
import jsonpatch

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from sendgrid.helpers.mail import Email
from sendgrid.helpers.mail import Content
from sendgrid.helpers.mail import Substitution
from sendgrid.helpers.mail import Personalization

from mist.api import config

from mist.api.helpers import send_email
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

from mist.api.users.models import User


log = logging.getLogger(__name__)


class BaseNotificationChannel(object):
    """Base class containing all common functionality amongst channels."""

    def __init__(self, notification):
        """Instantiate self given a mist.api.notifications.models.Notification
        instance."""
        self.ntf = notification  # TODO Accept a list of notifications?

    @property
    def ctype(self):
        """Return the channel's type."""
        return type(self.ntf).__name__

    def send(self, users=None):
        """The main method invoked in order to send a notification via
        a channel. This is where the core logic of each channel is defined."""
        raise NotImplementedError()

    def dismiss(self, users=None):
        """This method dismisses a notification in order to hide it from the
        end user. Certain notification channels may not have a need for such
        an action."""
        pass


class EmailNotificationChannel(BaseNotificationChannel):

    def send(self, users=None):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.notifications.models import UserNotificationPolicy

        if not users:
            users = self.ntf.owner.members
        elif not isinstance(users, list):
            users = [users]

        for user in users:
            # Prepare each user's information. Note that users may either be
            # instances of mist.api.users.models.User or e-mail addresses.
            if isinstance(user, User):
                to = user.email
                full_name = user.get_nice_name()
                first_name = user.first_name or full_name
                unsub_link = self.ntf.get_unsub_link(user.id)
                query_kwargs = {'owner': self.ntf.owner, 'user_id': user.id}
            else:
                to = user  # Just an e-mail.
                full_name = first_name = ""
                unsub_link = self.ntf.get_unsub_link(user_id=None, email=user)
                query_kwargs = {'owner': self.ntf.owner, 'email': user}

            # Check the user's notification policy.
            try:
                np = UserNotificationPolicy.objects.get(**query_kwargs)
                if np.has_blocked(self.ntf):
                    continue
            except UserNotificationPolicy.DoesNotExist:
                log.debug('No UserNotificationPolicy found for %s', user)

            if config.SENDGRID_EMAIL_NOTIFICATIONS_KEY:
                # Initialize SendGrid client.
                sg = SendGridAPIClient(config.SENDGRID_EMAIL_NOTIFICATIONS_KEY)
                mail = Mail()
                mail.from_email = Email(self.ntf.sender_email,
                                        self.ntf.sender_title)

                # Personalize e-mail.
                personalization = Personalization()
                personalization.subject = self.ntf.subject
                personalization.add_to(Email(to, full_name))
                sub = Substitution("%name%", first_name)
                personalization.add_substitution(sub)
                if unsub_link:
                    sub = Substitution("%nsub%", unsub_link)
                    personalization.add_substitution(sub)
                mail.add_personalization(personalization)

                # Add content.
                mail.add_content(Content("text/plain", self.ntf.text_body))
                if self.ntf.html_body:
                    mail.add_content(Content("text/html", self.ntf.html_body))

                # Attempt to send.
                try:
                    sg.client.mail.send.post(request_body=mail.get())
                except urllib.error.URLError as exc:
                    log.exception(repr(exc))
                except Exception as exc:
                    log.exception(repr(exc))
            else:
                body = self.ntf.text_body.replace("%nsub%", unsub_link)
                send_email(self.ntf.subject, body, [to],
                           sender=self.ntf.sender_email)


class InAppNotificationChannel(BaseNotificationChannel):

    def send(self, users=None, dismiss=False):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.notifications.models import InAppNotification
        from mist.api.notifications.models import UserNotificationPolicy

        # Get the list of `InAppNotifications`s in the current context before
        # any update takes place.
        owner_old_ntfs = list(InAppNotification.objects(owner=self.ntf.owner))

        if not users:
            users = self.ntf.owner.members
        elif not isinstance(users, list):
            users = [users]

        # Save/update/dismiss notifications.
        if dismiss:
            dismissed_by = set(self.ntf.dismissed_by)
            old_dismissed_by = list(dismissed_by)
            dismissed_by |= set(user.id for user in users)
            self.ntf.dismissed_by = list(dismissed_by)

        # Is anyone listening?
        if not amqp_owner_listening(self.ntf.owner.id):
            return

        # Re-fetch all notifications in order to calculate the diff between
        # the two lists.
        owner_new_ntfs = list(InAppNotification.objects(owner=self.ntf.owner))

        # Apply each user's notification policy on the above lists to get rid
        # of notifications users are not interested in.
        for user in users:
            user_old_ntfs, user_new_ntfs = [], []
            try:
                np = UserNotificationPolicy.objects.get(user_id=user.id)
            except UserNotificationPolicy.DoesNotExist:
                log.debug('No UserNotificationPolicy found for %s', user)
                user_old_ntfs = [ntf.as_dict() for ntf in owner_old_ntfs
                                 if not (self.ntf.id == ntf.id and
                                         user.id in old_dismissed_by)]
                user_new_ntfs = [ntf.as_dict() for ntf in owner_new_ntfs
                                 if not (self.ntf.id == ntf.id and
                                         user.id in dismissed_by)]
            else:
                user_old_ntfs = [ntf.as_dict() for ntf in owner_old_ntfs
                                 if not np.has_blocked(ntf) and not
                                 (self.ntf.id == ntf.id and
                                  user.id in old_dismissed_by)]
                user_new_ntfs = [ntf.as_dict() for ntf in owner_new_ntfs
                                 if not np.has_blocked(ntf) and not
                                 (self.ntf.id == ntf.id and
                                  user.id in dismissed_by)]
            # Now we can save the dismissed notification
            self.ntf.save()

            # Calculate diff.
            patch = jsonpatch.JsonPatch.from_diff(user_old_ntfs,
                                                  user_new_ntfs).patch

            if patch:
                amqp_publish_user(self.ntf.owner.id,
                                  routing_key='patch_notifications',
                                  data={'user': user.id,
                                        'patch': patch})

    def dismiss(self, users=None):
        self.send(users, dismiss=True)
