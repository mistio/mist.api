import mongoengine as me
import re


class TagMixin(object):
    """A mixin class that adds the resource's tags

    This mixin can be used with any taggable mist.io resource.

    """
    tags = me.StringField(default='')

    def update_tags(self, tag_dict):
        # import ipdb; ipdb.set_trace()
        for k, v in tag_dict.items():
            if f',{k}:' not in self.tags:
                self.tags = self.tags.rstrip(',') + f',{k}:{v},'
            elif f',{k}:{v},' not in self.tags:
                self.tags = re.sub(f',{k}:.*?,', f',{k}:{v},', self.tags)
        self.save()

    def delete_tags(self, key_list):
        for k in key_list:
            self.tags = re.sub(f',{k}:.*?,', ',', self.tags)
            self.save()
