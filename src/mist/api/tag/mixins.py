import mongoengine as me


class TagMixin(object):
    """A mixin class that adds the resource's tags

    This mixin can be used with any taggable mist.io resource.

    """
    tags = me.DictField(unique=True, required=False, sparse=True)
