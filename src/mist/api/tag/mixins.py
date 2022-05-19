import mongoengine as me


class TagMixin(object):
    """A mixin class that adds the resource's tags

    This mixin can be used with any taggable mist.io resource.

    """
    tags = me.StringField(default='')

    def tags_to_dict(self):
        dikt = {}
        for pair in self.tags.split(',')[1:-1]:
            k, v = pair.split(':')
            dikt[k] = None if v == 'None' else v

        return dikt

    def tags_to_string(self, tag_dict):
        tags = ''
        for k, v in tag_dict.items():
            tags = tags.rstrip(',') + f',{k}:{v},'

        return tags

    def update_tags(self, tags_to_update):
        tag_dict = self.tags_to_dict()
        tag_dict.update(tags_to_update)

        self.tags = self.tags_to_string(tag_dict)
        self.save()

    def delete_tags(self, key_list):
        tag_dict = self.tags_to_dict()
        for k in key_list:
            tag_dict.pop(k, None)

        self.tags = self.tags_to_string(tag_dict)
        self.save()
