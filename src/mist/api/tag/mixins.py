import mongoengine as me


class TagMixin(object):
    """A mixin class that adds the resource's tags

    This mixin can be used with any taggable mist.io resource.

    """
    tags = me.StringField(default='')

    def to_dict(self, tags):
        dikt = {}
        for pair in tags.split(',')[1:-1]:
            k, v = pair.split(':')
            dikt[k] = v or None

        return dikt

    def to_string(self, tag_dict):
        tags = ''
        for k, v in tag_dict.items():
            tags = tags.rstrip(',') + f',{k}:{v or ""},'

        return tags

    def update_tags(self, tags_to_update):
        tag_dict = self.to_dict(self.tags)
        tag_dict.update(tags_to_update)

        self.tags = self.to_string(tag_dict)
        self.save()

    def delete_tags(self, key_list):
        tag_dict = self.to_dict(self.tags)
        for k in key_list:
            tag_dict.pop(k, None)

        self.tags = self.to_string(tag_dict)
        self.save()
