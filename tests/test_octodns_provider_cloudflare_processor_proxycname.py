from unittest import TestCase

from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_cloudflare import CloudflareProvider
from octodns_cloudflare.processor.proxycname import ProxyCNAME


class TestProxyCNAME(TestCase):
    def test_proxy_cname(self):
        processor = ProxyCNAME('test')

        zone = Zone('unit.tests.', [])  # Simulate what we want
        zone_empty = Zone(
            'unit.tests.', []
        )  # Simulate there being nothing existing
        zone_expected_cf = Zone(
            'unit.tests.', []
        )  # What the processor should produce based off what we want for Cloudflare provider
        zone_expected_other = Zone(
            'unit.tests.', []
        )  # What the processor should produce based off what we want for other providers

        # Zone of what we want
        proxyable = Record.new(
            zone,
            'good',
            {
                'type': 'A',
                'ttl': 300,
                'value': '1.2.3.4',
                'octodns': {'cloudflare': {'proxied': True}},
            },
        )
        proxyable_root = Record.new(
            zone,
            '',
            {
                'type': 'A',
                'ttl': 300,
                'value': '1.2.3.4',
                'octodns': {'cloudflare': {'proxied': True}},
            },
        )
        non_proxyable = Record.new(
            zone,
            'bad',
            {
                'type': 'TXT',
                'ttl': 300,
                'value': 'test',
                'octodns': {'cloudflare': {'proxied': True}},
            },
        )
        zone.add_record(proxyable)
        zone.add_record(proxyable_root)
        zone.add_record(non_proxyable)

        # Expected result in Cloudflare provider
        expected_cf_proxyable = Record.new(
            zone,
            'good',
            {
                'type': 'A',
                'ttl': 300,
                'value': "1.2.3.4",
                '_octodns': {'cloudflare': {'proxied': True}},
            },
        )
        expected_cf_proxyable_root = Record.new(
            zone,
            '',
            {
                'type': 'A',
                'ttl': 300,
                'value': "1.2.3.4",
                '_octodns': {'cloudflare': {'proxied': True}},
            },
        )
        expected_cf_non_proxyable = Record.new(
            zone,
            'bad',
            {
                'type': 'TXT',
                'ttl': 300,
                'value': 'test',
                '_octodns': {'cloudflare': {'proxied': True}},
            },
        )
        zone_expected_cf.add_record(expected_cf_proxyable)
        zone_expected_cf.add_record(expected_cf_proxyable_root)
        zone_expected_cf.add_record(expected_cf_non_proxyable)

        # Expected result in other providers
        expected_other_proxyable = Record.new(
            zone,
            'good',
            {
                'type': 'CNAME',
                'ttl': 300,
                'value': "good.unit.tests.cdn.cloudflare.net.",
                '_octodns': {'cloudflare': {'proxied': True}},
            },
        )
        expected_other_proxyable_root = Record.new(
            zone,
            '',
            {
                'type': 'ALIAS',
                'ttl': 300,
                'value': "unit.tests.cdn.cloudflare.net.",
                '_octodns': {'cloudflare': {'proxied': True}},
            },
        )
        expected_other_non_proxyable = Record.new(
            zone,
            'bad',
            {
                'type': 'TXT',
                'ttl': 300,
                'value': 'test',
                '_octodns': {'cloudflare': {'proxied': True}},
            },
        )
        zone_expected_other.add_record(expected_other_proxyable)
        zone_expected_other.add_record(expected_other_proxyable_root)
        zone_expected_other.add_record(expected_other_non_proxyable)

        # Process / check Cloudflare provider destined records
        processed_cf_desired, processed_cf_existing = (
            processor.process_source_and_target_zones(
                zone, zone_empty, CloudflareProvider
            )
        )
        self.assertEqual(zone_expected_cf.records, processed_cf_desired.records)

        # Process / check other provider destined records
        processed_other_desired, processed_other_existing = (
            processor.process_source_and_target_zones(
                zone, zone_empty, YamlProvider
            )
        )
        self.assertEqual(
            zone_expected_other.records, processed_other_desired.records
        )
