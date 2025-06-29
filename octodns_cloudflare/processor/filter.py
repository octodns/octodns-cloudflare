#
#
#

from abc import ABCMeta, abstractmethod

from octodns.processor.base import BaseProcessor
from octodns.processor.filter import AllowsMixin, RejectsMixin


# TODO: Use octodns.processor.filter._FilterProcessor?
class _FilterProcessor(BaseProcessor, metaclass=ABCMeta):
    def __init__(self, name, include_target=True, **kwargs):
        super().__init__(name, **kwargs)
        self.include_target = include_target

    def process_source_zone(self, *args, **kwargs):
        return self._process(*args, **kwargs)

    def process_target_zone(self, existing, *args, **kwargs):
        if self.include_target:
            return self._process(existing, *args, **kwargs)
        return existing

    @abstractmethod
    def _process(self, zone, *args, **kwargs):
        pass  # pragma: no cover


class _TagBaseFilter(_FilterProcessor):
    def __init__(self, name, tags, **kwargs):
        super().__init__(name, **kwargs)
        self._tags = set(tags)

    def _process(self, zone, *args, **kwargs):
        for record in zone.records:
            tags = set(record.octodns.get('cloudflare', {}).get('tags', []))
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
