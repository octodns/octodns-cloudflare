from octodns.record import Record


class CloudflareZoneRecord(Record):
    """
    Custom record type for Cloudflare zone.

    Supports updating the zone plan.
    """

    _type = 'CF_ZONE'
    _value_type = dict

    FREE_PLAN = 'free'

    def __init__(self, zone, name, data, *args, **kwargs):
        super().__init__(zone, name, data, *args, **kwargs)
        self.value = data['value']

    @classmethod
    def validate(cls, _name, fqdn, data):
        value = data['value']
        if not isinstance(value, dict):
            return [f'CF_ZONE value must be a dict, not {type(value)}']

        if 'plan' not in value:
            return ['CF_ZONE value must include "plan" key']

        if not all(isinstance(v, str) for v in value.values()):
            return ['CF_ZONE values must be strings']

        return []

    def _equality_tuple(self):
        return (self.zone.name, self._type, self.name, self.value['plan'])

    def changes(self, other, target):
        if not isinstance(other, CloudflareZoneRecord):
            return True
        return other.value != self.value

    def __repr__(self):
        return f'CloudflareZoneRecord<{self.value}>'


# Register the custom record type
Record.register_type(CloudflareZoneRecord)
