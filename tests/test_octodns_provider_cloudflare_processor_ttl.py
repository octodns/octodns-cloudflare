from unittest import TestCase

from octodns.record import Record
from octodns.zone import Zone

from octodns_cloudflare.processor.ttl import TtlToProxy


class TestTtlToProxy(TestCase):
    def test_ttl_to_proxy(self):
        processor = TtlToProxy('test', ttl=0)

        zone = Zone('unit.tests.', [])
        zone_expected = Zone('unit.tests.', [])

        with_ttl = Record.new(
            zone, 'good', {'type': 'A', 'ttl': 0, 'value': '1.2.3.4'}
        )
        with_ttl_type_other = Record.new(
            zone, 'ttl-only', {'type': 'TXT', 'ttl': 0, 'value': 'acme'}
        )
        without_ttl = Record.new(
            zone, 'bad', {'type': 'A', 'ttl': 10, 'value': '1.2.3.4'}
        )
        zone.add_record(with_ttl)
        zone.add_record(with_ttl_type_other)
        zone.add_record(without_ttl)

        expected_with = Record.new(
            zone,
            'good',
            {
                'type': 'A',
                'ttl': 0,
                'value': '1.2.3.4',
                '_octodns': {'cloudflare': {'proxied': True, 'auto-ttl': True}},
            },
        )
        expected_with_ttl_only = Record.new(
            zone,
            'ttl-only',
            {
                'type': 'TXT',
                'ttl': 0,
                'value': '1.2.3.4',
                '_octodns': {'cloudflare': {'auto-ttl': True}},
            },
        )
        expected_without = Record.new(
            zone, 'bad', {'type': 'A', 'ttl': 10, 'value': '1.2.3.4'}
        )
        zone_expected.add_record(expected_with)
        zone_expected.add_record(expected_with_ttl_only)
        zone_expected.add_record(expected_without)

        added_proxy = processor.process_source_zone(zone)
        self.assertEqual(zone_expected.records, added_proxy.records)
        good = next(r for r in added_proxy.records if r.name == 'good')
        self.assertEqual(1, good.ttl)
        self.assertEqual(
            {'cloudflare': {'proxied': True, 'auto-ttl': True}}, good.octodns
        )
        ttl_only = next(r for r in added_proxy.records if r.name == 'ttl-only')
        self.assertEqual(1, good.ttl)
        self.assertEqual({'cloudflare': {'auto-ttl': True}}, ttl_only.octodns)
        bad = next(r for r in added_proxy.records if r.name == 'bad')
        self.assertEqual(10, bad.ttl)
        self.assertFalse('cloudflare' in bad.octodns)
