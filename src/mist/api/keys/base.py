import logging
import mongoengine as me

from future.utils import string_types

from mist.api.exceptions import KeyExistsError
from mist.api.exceptions import BadRequestError
from mist.api.helpers import rename_kwargs
from mist.api.helpers import trigger_session_update

log = logging.getLogger(__name__)


class BaseKeyController(object):
    def __init__(self, key):
        """Initialize a key controller given a key

        Most times one is expected to access a controller from inside the
        key, like this:

          key = mist.api.keys.models.Key.objects.get(id=key.id)
          key.ctl.construct_public_from_private()
        """
        self.key = key

    def add(self, fail_on_invalid_params=True, **kwargs):
        """Add an entry to the database

        This is only to be called by `Key.add` classmethod to create
        a key. Fields `owner` and `name` are already populated in
        `self.key`. The `self.key` is not yet saved.

        """
        from mist.api.keys.models import Key

        rename_kwargs(kwargs, 'priv', 'private')
        # Check for invalid `kwargs` keys.
        errors = {}
        for key in kwargs:
            if key not in self.key._key_specific_fields:
                error = "Invalid parameter %s=%r." % (key, kwargs[key])
                if fail_on_invalid_params:
                    errors[key] = error
                else:
                    log.warning(error)
                    kwargs.pop(key)
        if errors:
            log.error("Error adding %s: %s", self.key, errors)
            raise BadRequestError({
                'msg': "Invalid parameters %s." % list(errors.keys()),
                'errors': errors,
            })

        for key, value in kwargs.items():
            setattr(self.key, key, value)

        if not Key.objects(owner=self.key.owner, default=True):
            self.key.default = True

        try:
            self.key.save()
        except me.ValidationError as exc:
            log.error("Error adding %s: %s", self.key.name, exc.to_dict())
            raise BadRequestError({'msg': str(exc),
                                   'errors': exc.to_dict()})
        except me.NotUniqueError as exc:
            log.error("Key %s not unique error: %s", self.key.name, exc)
            raise KeyExistsError()

        # SEC
        self.key.owner.mapper.update(self.key)

        log.info("Added key with name '%s'", self.key.name)
        trigger_session_update(self.key.owner, ['keys'])

    def generate(self):
        raise NotImplementedError()

    def rename(self, name):  # replace io.methods.edit_key
        """Edit name of an existing key"""
        log.info("Renaming key '%s' to '%s'.", self.key.name, name)

        if self.key.name == name:
            log.warning("Same name provided. No reason to edit this key")
            return
        self.key.name = name
        self.key.save()
        log.info("Renamed key '%s' to '%s'.", self.key.name, name)
        trigger_session_update(self.key.owner, ['keys'])

    def set_default(self):
        from mist.api.keys.models import Key
        """Set a new key as default key, given a key_id"""

        log.info("Setting key with id '%s' as default.", self.key.id)

        Key.objects(owner=self.key.owner, default=True).update(default=False)
        self.key.default = True
        self.key.save()

        log.info("Successfully set key with id '%s' as default.", self.key.id)
        trigger_session_update(self.key.owner, ['keys'])

    def associate(self, machine, username='', port=22, no_connect=False):
        """Associates a key with a machine."""

        from mist.api.machines.models import KeyMachineAssociation

        log.info("Associating key %s to machine %s", self.key.id,
                 machine.machine_id)

        if isinstance(port, string_types):
            if port.isdigit():
                port = int(port)
            elif not port:
                port = 22
            else:
                raise BadRequestError("Port is required")
        elif isinstance(port, int):
            port = port
        else:
            raise BadRequestError("Invalid port type: %r" % port)

        # check if key already associated, if not already associated,
        # create the association.This is only needed if association doesn't
        # exist. Associations will otherwise be
        # created by shell.autoconfigure upon successful connection
        key_assoc = KeyMachineAssociation.objects(key=self.key,
                                                  machine=machine,
                                                  ssh_user=username,
                                                  port=port)
        if key_assoc:
            log.warning("Key '%s' already associated with machine '%s' "
                        "in cloud '%s'", self.key.id,
                        machine.cloud.id, machine.machine_id)

            return key_assoc[0]

        key_assoc = KeyMachineAssociation(key=self.key, machine=machine,
                                          last_used=0, ssh_user=username,
                                          sudo=False, port=port)
        key_assoc.save()

        trigger_session_update(self.key.owner, ['keys'])
        return key_assoc

    def disassociate(self, machine):
        """Disassociates a key from a machine."""

        from mist.api.machines.models import KeyMachineAssociation

        log.info("Disassociating key of machine '%s' " % machine.machine_id)

        # removing key association
        KeyMachineAssociation.objects(key=self.key,
                                      machine=machine).delete()
        trigger_session_update(self.key.owner, ['keys'])
