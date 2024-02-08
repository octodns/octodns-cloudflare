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
        without_ttl = Record.new(
            zone, 'bad', {'type': 'A', 'ttl': 10, 'value': '1.2.3.4'}
        )
        zone.add_record(with_ttl)
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
        expected_without = Record.new(
            zone, 'bad', {'type': 'A', 'ttl': 10, 'value': '1.2.3.4'}
        )
        zone_expected.add_record(expected_with)
        zone_expected.add_record(expected_without)

        added_proxy = processor.process_source_zone(zone)
        self.assertEqual(zone_expected.records, added_proxy.records)
