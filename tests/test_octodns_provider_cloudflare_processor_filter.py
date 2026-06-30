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


class TestTagFilterPerValue(TestCase):
    # a record's tags are the union of record-level and per-value tags
    def _zone(self):
        z = Zone('unit.tests.', [])
        # per-value tags only, no record-level tags
        z.add_record(
            Record.new(
                z,
                'pv',
                {
                    'ttl': 300,
                    'type': 'A',
                    'values': ['1.2.3.4', '1.2.3.5'],
                    'octodns': {
                        'cloudflare': {
                            'values': [
                                {
                                    'value': '1.2.3.4',
                                    'tags': ['team:engineering'],
                                },
                                {'value': '1.2.3.5', 'tags': ['other']},
                            ]
                        }
                    },
                },
            )
        )
        # record-level tag unioned with a per-value tag
        z.add_record(
            Record.new(
                z,
                'mix',
                {
                    'ttl': 300,
                    'type': 'A',
                    'value': '1.2.3.6',
                    'octodns': {
                        'cloudflare': {
                            'tags': ['managed-by:terraform'],
                            'values': [
                                {
                                    'value': '1.2.3.6',
                                    'tags': ['team:engineering'],
                                }
                            ],
                        }
                    },
                },
            )
        )
        # malformed per-value entries are tolerated (no crash); the record
        # ends up with no usable tags
        z.add_record(
            Record.new(
                z,
                'bad',
                {
                    'ttl': 300,
                    'type': 'A',
                    'value': '1.2.3.7',
                    'octodns': {
                        'cloudflare': {'values': ['oops', {'value': '1.2.3.7'}]}
                    },
                },
            )
        )
        return z

    def test_allow_matches_per_value_tags(self):
        processor = TagAllowListFilter('allow', ['team:engineering'])
        got = processor.process_source_zone(self._zone().copy())
        self.assertEqual({'pv', 'mix'}, {r.name for r in got.records})

    def test_reject_matches_per_value_tags(self):
        processor = TagRejectListFilter('reject', ['team:engineering'])
        got = processor.process_source_zone(self._zone().copy())
        self.assertEqual({'bad'}, {r.name for r in got.records})
