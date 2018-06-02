import mongoengine as me

from mist.api.exceptions import UnauthorizedError


class OwnershipMixin(object):
    """A mixin class that adds reference to the owner/creator of a resource

    The creator of a resource is set once the resource is created and stays
    the same throughout the resource's lifetime. Initially, the owner of a
    resource is the same as its creator. However, transfer of ownership is
    possible.

    The idea of ownership may also be used to extend RBAC. The owner of a
    resource may be granted full access rights on it. For this functionality
    to be enabled, set Organization.ownership_enabled to True.

    This mixin can be used with any mist.io resource, which is a subclass of
    me.Document.

    """

    owned_by = me.ReferenceField('User', reverse_delete_rule=me.NULLIFY)
    created_by = me.ReferenceField('User', reverse_delete_rule=me.NULLIFY)

    def assign_to(self, user, assign_creator=True):
        """Assign the resource to `user`

        The specified user becomes the resource's owner. If assign_creator
        is True, then the user is declared as the resource's creator, too.

        """
        user.get_ownership_mapper(self.owner).update(self)
        self.owned_by = user
        if assign_creator is True:
            self.created_by = user
        self.save()

    def transfer_ownership(self, auth_context, user):
        """Transfer the resource's ownership to `user`

        If the requesting user is not the resource's owner, then an error
        will be thrown, unless the requesting user is a member of the Org's
        Owners team.

        """
        assert auth_context.owner == self.owner
        assert user in auth_context.owner.members
        if not self.owned_by or self.owned_by != auth_context.user:
            if not auth_context.is_owner():
                raise UnauthorizedError('You do not own this resource')
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.owner).remove(self)
        self.assign_to(user, assign_creator=False)
