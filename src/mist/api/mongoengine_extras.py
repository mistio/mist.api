import mongoengine as me
from mist.api.tag.tasks import update_tags, delete_tags


class MistDictField(me.DictField):
    def validate(self, value):
        assert isinstance(value, dict), (type(value), value)
        value = sanitize_dict(value)
        super(MistDictField, self).validate(value)


class MistListField(me.ListField):
    def validate(self, value):
        assert isinstance(value, list), (type(value), value)
        value = sanitize_dict(value)
        super(MistListField, self).validate(value)


class TagQuerySet(me.QuerySet):
    def insert(self, doc_or_docs, load_bulk=True, write_concern=None,
               signal_kwargs=None):

        if doc_or_docs:
            update_tags.send(resource_type=doc_or_docs[0].resource_type,
                             resource_id=doc_or_docs[0].resource_id,
                             tag_dict={tag.key: tag.value
                                       for tag in doc_or_docs}
                             )
            return super().insert(doc_or_docs, load_bulk,
                                  write_concern, signal_kwargs)

    def delete(self, write_concern=None, _from_doc_delete=False,
               cascade_refs=None):
        if self:
            delete_tags.send(resource_type=self[0].resource_type,
                             resource_id=self[0].resource_id,
                             key_list=[tag.key for tag in self]
                             )
        return super().delete(write_concern, _from_doc_delete, cascade_refs)


def sanitize_dict(value):
    if isinstance(value, list):
        return [sanitize_dict(v) for v in value]
    elif not isinstance(value, dict):
        return value
    for key in list(value.keys()):
        if key == '_cls':
            del value[key]
            continue
        k = key.replace('.', '_').replace('$', '_')
        value[k] = sanitize_dict(value.pop(key))
    return value
