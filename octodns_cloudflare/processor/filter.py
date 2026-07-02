#
#
#

from octodns.processor.base import BaseProcessor
from octodns.processor.filter import AllowsMixin, RejectsMixin


class _FilterProcessor(BaseProcessor):
    def __init__(self, name, include_target=True, **kwargs):
        super().__init__(name, **kwargs)
        self.include_target = include_target

    def process_source_zone(self, *args, **kwargs):
        return self._process(*args, **kwargs)

    def process_target_zone(self, existing, *args, **kwargs):
        if self.include_target:
            return self._process(existing, *args, **kwargs)
        return existing


class _TagBaseFilter(_FilterProcessor):
    def __init__(self, name, tags, **kwargs):
        super().__init__(name, **kwargs)
        self._tags = set(tags)

    def _process(self, zone, *args, **kwargs):
        for record in zone.records:
            cloudflare = record.octodns.get('cloudflare', {})
            # A record's tags are the union of its record-level tags and any
            # per-value tags (octodns.cloudflare.values). Filtering is
            # record-granular, so a record is considered to carry a tag if any
            # of its values do. Malformed entries are tolerated here and left
            # for the provider to report at plan time.
            tags = set(cloudflare.get('tags') or [])
            for entry in cloudflare.get('values') or []:
                if isinstance(entry, dict):
                    tags.update(entry.get('tags') or [])
            if self._tags.issubset(tags):
                self.matches(zone, record)
            else:
                self.doesnt_match(zone, record)

        return zone


class TagAllowListFilter(_TagBaseFilter, AllowsMixin):
    '''
    Only manage records with the specified tag(s).

    Example usage:

    processors:
      filter-tags:
        class: octodns_cloudflare.processor.filter.TagAllowListFilter
        tags:
          - 'team:engineering'
        # Optional param that can be set to False to leave the target zone
        # alone, thus allowing deletion of existing records. (default: True)
        # include_target: True

    zones:
      example.com.:
        sources:
          - config
        processors:
          - filter-tags
        targets:
          - cloudflare
    '''

    def __init__(self, name, tags, **kwargs):
        super().__init__(name, tags, **kwargs)


class TagRejectListFilter(_TagBaseFilter, RejectsMixin):
    '''
    Ignore records with the specified tag(s).

    Example usage:

    processors:
      filter-tags:
        class: octodns_cloudflare.processor.filter.TagRejectListFilter
        tags:
          - 'managed-by:terraform'
        # Optional param that can be set to False to leave the target zone
        # alone, thus allowing deletion of existing records. (default: True)
        # include_target: True

    zones:
      example.com.:
        sources:
          - config
        processors:
          - filter-tags
        targets:
          - cloudflare
    '''

    def __init__(self, name, tags, **kwargs):
        super().__init__(name, tags, **kwargs)
