
import json
import mongoengine as me


class Cost(me.EmbeddedDocument):
    hourly = me.FloatField(default=0)
    monthly = me.FloatField(default=0)

    def as_dict(self):
        return json.loads(self.to_json())
