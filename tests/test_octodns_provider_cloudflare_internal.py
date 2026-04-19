#
#
#

from os.path import dirname, join
from unittest import TestCase

from requests_mock import mock as requests_mock

from octodns.provider import ProviderException
from octodns.provider.plan import Plan
from octodns.record import Create, Record
from octodns.zone import Zone

from octodns_cloudflare import CloudflareInternalProvider

ACCOUNT_ID = 'acct0000000000000000000000000001'
VIEW_ID = 'view11111111111111111111111111aa'
ZONE_ID = 'bb000000000000000000000000000001'
ORPHAN_ID = 'cc000000000000000000000000000002'


def fixture(name):
    with open(join(dirname(__file__), 'fixtures', name)) as fh:
        return fh.read()


class TestCloudflareInternalProvider(TestCase):

    def _provider(self, view_id=None):
        return CloudflareInternalProvider(
            'test',
            token='token',
            account_id=ACCOUNT_ID,
            view_id=view_id,
            retry_period=0,
        )

    # 1. init validation
    def test_init_requires_account_id(self):
        with self.assertRaises(ProviderException) as ctx:
            CloudflareInternalProvider('test', token='token')
        self.assertIn('account_id is required', str(ctx.exception))

    def test_init_rejects_public_only_params(self):
        for forbidden in ('cdn', 'pagerules', 'plan_type'):
            with self.assertRaises(ProviderException) as ctx:
                CloudflareInternalProvider(
                    'test',
                    token='token',
                    account_id=ACCOUNT_ID,
                    **{forbidden: 'anything'},
                )
            self.assertIn(forbidden, str(ctx.exception))

    def test_init_no_urlfwd_and_no_pagerules(self):
        provider = self._provider()
        self.assertNotIn('URLFWD', provider.SUPPORTS)
        self.assertFalse(provider.pagerules)
        self.assertIsNone(provider.plan_type)
        self.assertFalse(provider.cdn)

    # 3. hybrid enumeration union
    def test_zones_hybrid_union(self):
        provider = self._provider()
        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones'
                f'?page=1&per_page=50&account.id={ACCOUNT_ID}',
                text=fixture('cloudflare-internal-zones-mixed.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views?page=1&per_page=50',
                text=fixture('cloudflare-views-list.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ORPHAN_ID}',
                text=fixture('cloudflare-internal-zone-hydrate-cc.json'),
            )
            zones = provider.zones

        # public full-type zone must not appear; both internals must
        self.assertIn('corp.internal.tests.', zones)
        self.assertIn('orphan.internal.tests.', zones)
        self.assertNotIn('public.example.com.', zones)
        self.assertEqual(ZONE_ID, zones['corp.internal.tests.']['id'])
        self.assertEqual(ORPHAN_ID, zones['orphan.internal.tests.']['id'])
        self.assertIsNone(zones['corp.internal.tests.']['cloudflare_plan'])
        self.assertEqual([], zones['corp.internal.tests.']['name_servers'])

    # 4. view_id narrowing
    def test_zones_view_id_narrows_enumeration(self):
        provider = self._provider(view_id=VIEW_ID)
        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views/{VIEW_ID}',
                text=fixture('cloudflare-views-single.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}',
                text=fixture('cloudflare-internal-zone-hydrate-bb.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ORPHAN_ID}',
                text=fixture('cloudflare-internal-zone-hydrate-cc.json'),
            )

            # Fail if anything hits the /zones list or the /views list
            def _forbidden(request, context):
                raise AssertionError(
                    f'Unexpected call to {request.url} with view_id set'
                )

            mock.get(
                'https://api.cloudflare.com/client/v4/zones', json=_forbidden
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views',
                json=_forbidden,
            )

            zones = provider.zones

        self.assertEqual(
            {'corp.internal.tests.', 'orphan.internal.tests.'},
            set(zones.keys()),
        )

    # 5. duplicate-name raises
    def test_zones_duplicate_name_raises(self):
        provider = self._provider()
        empty_views = {
            'result': [],
            'result_info': {
                'page': 1,
                'per_page': 50,
                'total_pages': 1,
                'count': 0,
                'total_count': 0,
            },
            'success': True,
            'errors': [],
            'messages': [],
        }
        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones'
                f'?page=1&per_page=50&account.id={ACCOUNT_ID}',
                text=fixture('cloudflare-internal-zones-duplicate-name.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views?page=1&per_page=50',
                json=empty_views,
            )

            with self.assertRaises(ProviderException) as ctx:
                provider.zones

        msg = str(ctx.exception)
        self.assertIn('shared.internal.tests', msg)
        self.assertIn('dupa0000000000000000000000000001', msg)
        self.assertIn('dupb0000000000000000000000000002', msg)
        self.assertIn('view_id', msg)

    # 6. duplicate-name disambiguated by view_id
    def test_zones_duplicate_name_disambiguated_by_view_id(self):
        provider = self._provider(view_id=VIEW_ID)
        # view contains exactly one of the two duplicate-named zones
        one_view = {
            'result': {
                'id': VIEW_ID,
                'name': 'disambiguating-view',
                'zones': ['dupa0000000000000000000000000001'],
                'created_time': '2026-03-01T00:00:00Z',
                'modified_time': '2026-03-01T00:00:00Z',
            },
            'success': True,
            'errors': [],
            'messages': [],
        }
        one_zone = {
            'result': {
                'id': 'dupa0000000000000000000000000001',
                'name': 'shared.internal.tests',
                'status': 'active',
                'type': 'internal',
                'name_servers': [],
                'plan': None,
            },
            'success': True,
            'errors': [],
            'messages': [],
        }
        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views/{VIEW_ID}',
                json=one_view,
            )
            mock.get(
                'https://api.cloudflare.com/client/v4/zones/'
                'dupa0000000000000000000000000001',
                json=one_zone,
            )

            zones = provider.zones

        self.assertEqual({'shared.internal.tests.'}, set(zones.keys()))
        self.assertEqual(
            'dupa0000000000000000000000000001',
            zones['shared.internal.tests.']['id'],
        )

    # 7. populate reads internal records via inherited /dns_records path
    def test_populate_reads_internal_records(self):
        provider = self._provider(view_id=VIEW_ID)

        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views/{VIEW_ID}',
                text=fixture('cloudflare-views-single.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}',
                text=fixture('cloudflare-internal-zone-hydrate-bb.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ORPHAN_ID}',
                text=fixture('cloudflare-internal-zone-hydrate-cc.json'),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}'
                '/dns_records?page=1&per_page=100',
                text=fixture('cloudflare-internal-dns_records.json'),
            )

            zone = Zone('corp.internal.tests.', [])
            exists = provider.populate(zone)

        self.assertTrue(exists)
        records_by_type = {r._type for r in zone.records}
        self.assertEqual({'A', 'CNAME', 'MX'}, records_by_type)

    # 8. apply refuses to create missing zone
    def test_apply_refuses_to_create_missing_zone(self):
        provider = self._provider()
        provider._zones = {}  # prevent lazy fetch

        desired = Zone('never-exists.internal.tests.', [])
        desired.add_record(
            Record.new(
                desired, '', {'ttl': 300, 'type': 'A', 'values': ['10.0.0.42']}
            )
        )

        plan = Plan(
            existing=None,
            desired=desired,
            changes=[Create(r) for r in desired.records],
            exists=False,
        )

        with requests_mock() as mock:
            # If provider tries to POST /zones, fail loudly
            def _forbidden(request, context):
                raise AssertionError('provider must not create internal zones')

            mock.post(
                'https://api.cloudflare.com/client/v4/zones', json=_forbidden
            )

            with self.assertRaises(ProviderException) as ctx:
                provider._apply(plan)

        msg = str(ctx.exception)
        self.assertIn('never-exists.internal.tests.', msg)
        self.assertIn(ACCOUNT_ID, msg)
        self.assertIn('does not auto-create', msg)

    # 9. apply creates records in an existing internal zone
    def test_apply_creates_records_in_existing_zone(self):
        provider = self._provider()
        provider._zones = {
            'corp.internal.tests.': {
                'id': ZONE_ID,
                'cloudflare_plan': None,
                'name_servers': [],
            }
        }
        provider._zone_records = {}

        desired = Zone('corp.internal.tests.', [])
        new_record = Record.new(
            desired, 'app', {'ttl': 300, 'type': 'A', 'values': ['10.0.0.99']}
        )
        desired.add_record(new_record)

        plan = Plan(
            existing=Zone('corp.internal.tests.', []),
            desired=desired,
            changes=[Create(new_record)],
            exists=True,
        )

        with requests_mock() as mock:
            mock.post(
                f'https://api.cloudflare.com/client/v4/zones/'
                f'{ZONE_ID}/dns_records',
                json={'result': {}, 'success': True, 'errors': []},
            )
            # Any POST to /zones (for zone creation) must not happen.
            mock.post(
                'https://api.cloudflare.com/client/v4/zones',
                json=lambda r, c: (_ for _ in ()).throw(
                    AssertionError('internal provider must not create zones')
                ),
            )

            provider._apply(plan)

            # Verify a single record-create POST fired
            record_posts = [
                req
                for req in mock.request_history
                if req.method == 'POST'
                and req.path == f'/client/v4/zones/{ZONE_ID}/dns_records'
            ]
            self.assertEqual(1, len(record_posts))
            self.assertEqual('10.0.0.99', record_posts[0].json()['content'])

    # 10. apply does not issue plan-type calls
    def test_apply_skips_plan_type_handling(self):
        provider = self._provider()
        provider._zones = {
            'corp.internal.tests.': {
                'id': ZONE_ID,
                'cloudflare_plan': None,
                'name_servers': [],
            }
        }
        provider._zone_records = {}

        desired = Zone('corp.internal.tests.', [])
        # Empty changes list — apply should be a no-op past the guards.
        plan = Plan(
            existing=Zone('corp.internal.tests.', []),
            desired=desired,
            changes=[],
            exists=True,
        )

        with requests_mock() as mock:
            # Any call to /available_plans or PATCH /zones/{id} for plan
            # updates must not happen.
            def _forbidden(request, context):
                raise AssertionError(
                    f'plan-type path must not run; saw {request.method} '
                    f'{request.url}'
                )

            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}'
                '/available_plans',
                json=_forbidden,
            )
            mock.patch(
                f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}',
                json=_forbidden,
            )

            provider._apply(plan)

    # Pagination for both enumeration paths (covers the page += 1 branches)
    def test_zones_pagination_both_endpoints(self):
        provider = CloudflareInternalProvider(
            'test',
            token='token',
            account_id=ACCOUNT_ID,
            zones_per_page=1,
            retry_period=0,
        )

        def _paged_zones(page, zone):
            return {
                'result': [zone] if zone else [],
                'result_info': {
                    'page': page,
                    'per_page': 1,
                    'total_pages': 2,
                    'count': 1 if zone else 0,
                    'total_count': 1,
                },
                'success': True,
                'errors': [],
                'messages': [],
            }

        z1 = {
            'id': 'page0000000000000000000000000001',
            'name': 'p1.internal.tests',
            'status': 'active',
            'type': 'internal',
            'name_servers': [],
            'plan': None,
        }
        v1 = {
            'id': 'viewpage111111111111111111111111',
            'name': 'v1',
            'zones': [],
            'created_time': '',
            'modified_time': '',
        }

        def _paged_views(page, view):
            return {
                'result': [view] if view else [],
                'result_info': {
                    'page': page,
                    'per_page': 1,
                    'total_pages': 2,
                    'count': 1 if view else 0,
                    'total_count': 1,
                },
                'success': True,
                'errors': [],
                'messages': [],
            }

        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones'
                f'?page=1&per_page=1&account.id={ACCOUNT_ID}',
                json=_paged_zones(1, z1),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones'
                f'?page=2&per_page=1&account.id={ACCOUNT_ID}',
                json=_paged_zones(2, None),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views?page=1&per_page=1',
                json=_paged_views(1, v1),
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views?page=2&per_page=1',
                json=_paged_views(2, None),
            )

            zones = provider.zones

        self.assertEqual({'p1.internal.tests.'}, set(zones.keys()))

    # A view may name a non-internal zone (defensively filtered)
    def test_zones_skips_non_internal_from_view_hydrate(self):
        provider = self._provider(view_id=VIEW_ID)
        stray_id = 'stray00000000000000000000000full'
        one_view = {
            'result': {
                'id': VIEW_ID,
                'name': 'v',
                'zones': [stray_id],
                'created_time': '',
                'modified_time': '',
            },
            'success': True,
            'errors': [],
            'messages': [],
        }
        stray_zone = {
            'result': {
                'id': stray_id,
                'name': 'stray.example.com',
                'status': 'active',
                'type': 'full',
                'name_servers': ['ns1', 'ns2'],
                'plan': {'legacy_id': 'free'},
            },
            'success': True,
            'errors': [],
            'messages': [],
        }
        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/accounts/'
                f'{ACCOUNT_ID}/dns_settings/views/{VIEW_ID}',
                json=one_view,
            )
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{stray_id}',
                json=stray_zone,
            )

            zones = provider.zones

        # Non-internal zones returned via a view walk are dropped
        self.assertEqual({}, dict(zones))

    # Root NS records on an internal zone are stripped before the
    # BaseProvider SUPPORTS_ROOT_NS check can reject the plan.
    def test_process_desired_zone_strips_root_ns(self):
        provider = self._provider()
        # strict_supports defaults to True — this confirms the strip is
        # unconditional (not gated by strict mode).
        self.assertTrue(provider.strict_supports)

        desired = Zone('corp.internal.tests.', [])
        desired.add_record(
            Record.new(
                desired,
                '',
                {
                    'ttl': 3600,
                    'type': 'NS',
                    'values': ['ns1.example.com.', 'ns2.example.com.'],
                },
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'app',
                {'ttl': 300, 'type': 'A', 'values': ['10.0.0.5']},
            )
        )

        processed = provider._process_desired_zone(desired)

        types = {r._type for r in processed.records}
        self.assertNotIn('NS', types)
        self.assertIn('A', types)

    def test_process_desired_zone_no_root_ns_is_pass_through(self):
        provider = self._provider()
        desired = Zone('corp.internal.tests.', [])
        desired.add_record(
            Record.new(
                desired,
                'only',
                {'ttl': 300, 'type': 'A', 'values': ['10.0.0.9']},
            )
        )

        processed = provider._process_desired_zone(desired)

        self.assertEqual({'A'}, {r._type for r in processed.records})

    # 11. pagerules disabled — SUPPORTS lacks URLFWD, zone_records
    # does not hit /pagerules
    def test_pagerules_disabled(self):
        provider = self._provider()
        self.assertNotIn('URLFWD', provider.SUPPORTS)

        provider._zones = {
            'corp.internal.tests.': {
                'id': ZONE_ID,
                'cloudflare_plan': None,
                'name_servers': [],
            }
        }

        with requests_mock() as mock:
            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}'
                '/dns_records?page=1&per_page=100',
                text=fixture('cloudflare-internal-dns_records.json'),
            )

            def _forbidden(request, context):
                raise AssertionError(
                    f'pagerules must not be queried; saw {request.url}'
                )

            mock.get(
                f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}'
                '/pagerules',
                json=_forbidden,
            )

            zone = Zone('corp.internal.tests.', [])
            provider.zone_records(zone)
