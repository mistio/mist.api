import mongoengine as me


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
