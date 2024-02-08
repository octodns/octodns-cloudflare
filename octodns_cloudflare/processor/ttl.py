#
#
#

from octodns.processor.base import BaseProcessor, ProcessorException

class TtlToProxy(BaseProcessor):
    '''
    Ensure Cloudflare's proxy status is setup depending on the TTL set for the record. This
    can be helpful for `octodns_bind.ZoneFileSource` or the like.

    Example usage:

    processors:
      ttl-to-proxy:
        class: octodns_cloudflare.processor.ttl.TtlToProxy
        ttl: 0

    zones:
      exxampled.com.:
        sources:
          - config
        processors:
          - ttl-to-proxy
        targets:
          - cloudflare
    '''

    def __init__(self, name, ttl=0):
        super().__init__(name)
        self.ttl = ttl

    def process_source_zone(self, zone, *args, **kwargs):
        for record in zone.records:
            if record.ttl == self.ttl:
                record = record.copy()
                record._octodns['cloudflare'] = {'proxied': True, 'auto-ttl': True}
                record.ttl = 1; # Ensure we set to valid TTL.
                desired.add_record(record, replace=True, lenient=True)

        return zone
