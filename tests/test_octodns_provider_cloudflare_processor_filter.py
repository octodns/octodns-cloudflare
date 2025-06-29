#
#
#

from unittest import TestCase

from octodns.record import Record
from octodns.zone import Zone

from octodns_cloudflare.processor.filter import (
    TagAllowListFilter,
    TagRejectListFilter,
)

zone = Zone('unit.tests.', [])
for record in [
    Record.new(
        zone,
        'foo',
        {
            'ttl': 300,
            'type': 'CNAME',
            'value': 'foo.example.com.',
            'octodns': {'cloudflare': {'tags': ['managed-by:terraform']}},
        },
    ),
    Record.new(
        zone,
        'bar',
        {
            'ttl': 300,
            'type': 'CNAME',
            'value': 'bar.example.com.',
            'octodns': {
                'cloudflare': {
                    'tags': ['managed-by:terraform', 'team:engineering']
                }
            },
        },
    ),
    Record.new(
        zone,
        'baz',
        {
            'ttl': 300,
            'type': 'CNAME',
            'value': 'baz.example.com.',
            'octodns': {'cloudflare': {'tags': ['team:engineering']}},
        },
    ),
    Record.new(
        zone,
        'qux',
        {
            'ttl': 300,
            'type': 'CNAME',
            'value': 'qux.example.com.',
            'octodns': {'cloudflare': {'tags': []}},
        },
    ),
]:
    zone.add_record(record)


class TestTagAllowListFilter(TestCase):
    def test_process_source_zone(self):
        processor = TagAllowListFilter('allow-tags', ['team:engineering'])

        want = {'bar', 'baz'}
        got = processor.process_source_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})

    def test_process_target_zone(self):
        processor = TagAllowListFilter('allow-tags', ['team:engineering'])

        want = {'bar', 'baz'}
        got = processor.process_target_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})

    def test_process_source_zone_include_target(self):
        processor = TagAllowListFilter(
            'allow-tags', ['team:engineering'], include_target=False
        )

        want = {'bar', 'baz'}
        got = processor.process_source_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})

    def test_process_target_zone_include_target(self):
        processor = TagAllowListFilter(
            'allow-tags', ['team:engineering'], include_target=False
        )

        want = {'foo', 'bar', 'baz', 'qux'}
        got = processor.process_target_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})


class TestTagRejectListFilter(TestCase):
    def test_process_source_zone(self):
        processor = TagRejectListFilter('reject-tags', ['managed-by:terraform'])

        want = {'baz', 'qux'}
        got = processor.process_source_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})

    def test_process_target_zone(self):
        processor = TagRejectListFilter('reject-tags', ['managed-by:terraform'])

        want = {'baz', 'qux'}
        got = processor.process_target_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})

    def test_process_source_zone_include_target(self):
        processor = TagRejectListFilter(
            'reject-tags', ['managed-by:terraform'], include_target=False
        )

        want = {'baz', 'qux'}
        got = processor.process_source_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})

    def test_process_target_zone_include_target(self):
        processor = TagRejectListFilter(
            'reject-tags', ['managed-by:terraform'], include_target=False
        )

        want = {'foo', 'bar', 'baz', 'qux'}
        got = processor.process_target_zone(zone.copy())
        self.assertEqual(want, {r.name for r in got.records})
