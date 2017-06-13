import uuid
import logging
import datetime

import mongoengine as me

from mist.api import config


log = logging.getLogger(__name__)


class AvailableUpgrade(me.EmbeddedDocument):
    name = me.StringField(required=True)
    sha = me.StringField(required=True)


class Portal(me.Document):
    """Holds metadata about the mist.io installation itself

    There's only ever supposed to be a single document in this collection.
    """

    # Metadata about the local mist.io portal
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    created_at = me.DateTimeField(default=datetime.datetime.now)

    # Newer available mist.io versions
    available_upgrades = me.EmbeddedDocumentListField(AvailableUpgrade)

    # This field has a uniqueness constraint and always has the same value.
    # This is an extra check to ensure that we'll not end up with multiple
    # Document instances.
    answer_to_life_the_universe_and_everything = me.IntField(default=42,
                                                             unique=True)

    def save(self, *args, **kwargs):
        return super(Portal, self).save(*args, **kwargs)

    @classmethod
    def get_singleton(cls):
        """Return (and create if missing) the single Portal document"""
        try:
            portal = cls.objects.get()
            log.debug("Loaded portal info from db.")
        except me.DoesNotExist:
            log.info("No portal info found in db, will try to initialize.")
            try:
                portal = cls()
                portal.save()
                log.info("Initialized portal info.")
            except me.NotUniqueError:
                log.warning("Probable race condition while initializing "
                            "portal info, will try to reload.")
                portal = cls.objects.get()
                log.debug("Loaded portal info from db.")
        except me.MultipleObjectsReturned:
            log.error("Multiple Portal info found in database.")
            portal = cls.objects.first()
        return portal

    def as_dict(self):
        return {
            'portal_id': self.id,
            'created_at': str(self.created_at),
            'version': config.VERSION,
            'available_upgrades': [{'name': upgrade.name, 'sha': upgrade.sha}
                                   for upgrade in self.available_upgrades]
        }
