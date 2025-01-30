from unittest import TestCase

from octodns.record import Record, ValidationError
from octodns.zone import Zone

from octodns_cloudflare.record import CloudflareZoneRecord


class TestCloudflareZoneRecord(TestCase):
    def test_cloudflare_zone_record(self):
        # Test valid plan record creation
        zone = Zone('unit.tests.', [])

        record = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )

        self.assertIsInstance(record, CloudflareZoneRecord)
        self.assertEqual('CF_ZONE', record._type)
        self.assertEqual({'plan': 'enterprise'}, record.value)

        # Test validation errors
        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                zone,
                '_plan_update',
                {
                    'type': 'CF_ZONE',
                    'ttl': 300,
                    'value': 'invalid',  # Should be dict
                },
            )
        self.assertTrue('_plan_update.unit.tests.' in str(ctx.exception))
        self.assertTrue('must be a dict' in str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                zone,
                '_plan_update',
                {'type': 'CF_ZONE', 'ttl': 300, 'value': {}},  # Missing 'plan'
            )
        self.assertTrue('_plan_update.unit.tests.' in str(ctx.exception))
        self.assertTrue('must include "plan" key' in str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                zone,
                '_plan_update',
                {
                    'type': 'CF_ZONE',
                    'ttl': 300,
                    'value': {'plan': 123},  # Invalid value type
                },
            )
        self.assertTrue('_plan_update.unit.tests.' in str(ctx.exception))
        self.assertTrue('must be strings' in str(ctx.exception))

        # Test equality comparison
        record1 = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )

        record2 = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )

        record3 = Record.new(
            zone,
            '_plan_update',
            {
                'type': 'CF_ZONE',
                'ttl': 300,
                'value': {'plan': 'business'},  # Different target plan
            },
        )

        self.assertEqual(record1, record2)
        self.assertNotEqual(record1, record3)

        # Test comparison with non-CloudflareZoneRecord
        other_record = Record.new(
            zone, '_plan_update', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
        )
        self.assertTrue(record1.changes(other_record, None))

    def test_cloudflare_zone_record_repr(self):
        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )
        self.assertEqual(
            "CloudflareZoneRecord<{'plan': 'enterprise'}>", repr(record)
        )

    def test_cloudflare_zone_record_changes(self):
        zone = Zone('unit.tests.', [])

        # Test changes with non-CloudflareZoneRecord
        record = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )
        other = Record.new(
            zone, '_plan_update', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
        )
        self.assertTrue(record.changes(other, None))

        # Test changes with same type but different values
        other = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'pro'}},
        )
        self.assertTrue(record.changes(other, None))

        # Test no changes with identical records
        other = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )
        self.assertFalse(record.changes(other, None))

    def test_cloudflare_zone_record_equality(self):
        zone = Zone('unit.tests.', [])
        record1 = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )

        # Same record
        record2 = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )
        self.assertEqual(record1, record2)

        # Different plan
        record3 = Record.new(
            zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'pro'}},
        )
        self.assertNotEqual(record1, record3)

        # Different name
        record4 = Record.new(
            zone,
            'other_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )
        self.assertNotEqual(record1, record4)

        # Different zone
        other_zone = Zone('other.tests.', [])
        record5 = Record.new(
            other_zone,
            '_plan_update',
            {'type': 'CF_ZONE', 'ttl': 300, 'value': {'plan': 'enterprise'}},
        )
        self.assertNotEqual(record1, record5)
