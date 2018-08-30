import mongoengine as me


class MistDictField(me.DictField):
    def validate(self, value):
        assert isinstance(value, dict), (type(value), value)
        escape_dots_and_dollars_from_dict(value)
        super(MistDictField, self).validate(value)


def escape_dots_and_dollars_from_dict(value):
    if not isinstance(value, dict):
        return value
    for key in list(value.keys()):
        k = key.replace('.', '_').replace('$', '_')
        value[k] = escape_dots_and_dollars_from_dict(value.pop(key))
    return value
