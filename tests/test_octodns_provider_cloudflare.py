#
#
#

from os.path import dirname, join
from unittest import TestCase, skipIf
from unittest.mock import Mock, call, patch

from requests import HTTPError
from requests_mock import ANY
from requests_mock import mock as requests_mock

from octodns import __VERSION__ as octodns_version
from octodns.idna import idna_encode
from octodns.provider import SupportsException
from octodns.provider.base import Plan
from octodns.provider.yaml import YamlProvider
from octodns.record import Create, Delete, Record, Update
from octodns.zone import Zone

from octodns_cloudflare import (
    CloudflareAuthenticationError,
    CloudflareProvider,
    CloudflareRateLimitError,
)

octodns_supports_meta = tuple(int(p) for p in octodns_version.split('.')) >= (
    1,
    11,
    0,
)


def set_record_proxied_flag(record, proxied):
    try:
        record.octodns['cloudflare']['proxied'] = proxied
    except KeyError:
        record.octodns['cloudflare'] = {'proxied': proxied}

    return record


def set_record_auto_ttl_flag(record, auto_ttl):
    try:
        record.octodns['cloudflare']['auto-ttl'] = auto_ttl
    except KeyError:
        record.octodns['cloudflare'] = {'auto-ttl': auto_ttl}

    return record


def set_record_comment(record, comment):
    try:
        record.octodns['cloudflare']['comment'] = comment
    except KeyError:
        record.octodns['cloudflare'] = {'comment': comment}

    return record


def set_record_tags(record, tags):
    try:
        record.octodns['cloudflare']['tags'] = tags
    except KeyError:
        record.octodns['cloudflare'] = {'tags': tags}

    return record


class TestCloudflareProvider(TestCase):
    expected = Zone('unit.tests.', [])
    source = YamlProvider('test', join(dirname(__file__), 'config'))
    source.populate(expected)

    # Our test suite differs a bit, add our NS and remove the simple one
    expected.add_record(
        Record.new(
            expected,
            'under',
            {
                'ttl': 3600,
                'type': 'NS',
                'values': ['ns1.unit.tests.', 'ns2.unit.tests.'],
            },
        )
    )
    for record in list(expected.records):
        if record.name == 'sub' and record._type == 'NS':
            expected.remove_record(record)
            break

    empty = {'result': [], 'result_info': {'count': 0, 'per_page': 0}}

    def test_populate(self):
        provider = CloudflareProvider('test', 'email', 'token', retry_period=0)

        # Bad requests
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=400,
                text='{"success":false,"errors":[{"code":1101,'
                '"message":"request was invalid"}],'
                '"messages":[],"result":null}',
            )

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)

            self.assertEqual('CloudflareError', type(ctx.exception).__name__)
            self.assertEqual('request was invalid', str(ctx.exception))

        # Bad auth
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=403,
                text='{"success":false,"errors":[{"code":9103,'
                '"message":"Unknown X-Auth-Key or X-Auth-Email"}],'
                '"messages":[],"result":null}',
            )

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(
                'CloudflareAuthenticationError', type(ctx.exception).__name__
            )
            self.assertEqual(
                'Unknown X-Auth-Key or X-Auth-Email', str(ctx.exception)
            )

        # Bad auth, unknown resp
        with requests_mock() as mock:
            mock.get(ANY, status_code=403, text='{}')

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(
                'CloudflareAuthenticationError', type(ctx.exception).__name__
            )
            self.assertEqual('Cloudflare error', str(ctx.exception))

        # General error
        with requests_mock() as mock:
            mock.get(ANY, status_code=500, text='Things caught fire')

            with self.assertRaises(HTTPError) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(500, ctx.exception.response.status_code)

        # Rate Limit error
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=429,
                text='{"success":false,"errors":[{"code":10100,'
                '"message":"More than 1200 requests per 300 seconds '
                'reached. Please wait and consider throttling your '
                'request speed"}],"messages":[],"result":null}',
            )

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)

            self.assertEqual(
                'CloudflareRateLimitError', type(ctx.exception).__name__
            )
            self.assertEqual(
                'More than 1200 requests per 300 seconds '
                'reached. Please wait and consider throttling '
                'your request speed',
                str(ctx.exception),
            )

        # Rate Limit error, unknown resp
        with requests_mock() as mock:
            mock.get(ANY, status_code=429, text='{}')

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)

            self.assertEqual(
                'CloudflareRateLimitError', type(ctx.exception).__name__
            )
            self.assertEqual('Cloudflare error', str(ctx.exception))

        # 502/503 error, Cloudflare API issue
        with requests_mock() as mock:
            mock.get(ANY, status_code=502, text='bad gateway')

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)

            self.assertEqual('Cloudflare5xxError', type(ctx.exception).__name__)
            self.assertEqual('Cloudflare error', str(ctx.exception))

            mock.get(ANY, status_code=503, text='service unavailable')

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)

            self.assertEqual('Cloudflare5xxError', type(ctx.exception).__name__)
            self.assertEqual('Cloudflare error', str(ctx.exception))

        # Non-existent zone doesn't populate anything
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, json=self.empty)

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(set(), zone.records)

        # re-populating the same non-existent zone uses cache and makes no
        # calls
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(set(), again.records)

        # bust zone cache
        provider._zones = None

        # existing zone with data
        with requests_mock() as mock:
            base = 'https://api.cloudflare.com/client/v4/zones'

            # zones
            with open('tests/fixtures/cloudflare-zones-page-1.json') as fh:
                mock.get(f'{base}?page=1', status_code=200, text=fh.read())
            with open('tests/fixtures/cloudflare-zones-page-2.json') as fh:
                mock.get(f'{base}?page=2', status_code=200, text=fh.read())
            with open('tests/fixtures/cloudflare-zones-page-3.json') as fh:
                mock.get(f'{base}?page=3', status_code=200, text=fh.read())
            mock.get(
                f'{base}?page=4',
                status_code=200,
                json={'result': [], 'result_info': {'count': 0, 'per_page': 0}},
            )

            base = f'{base}/234234243423aaabb334342aaa343435'

            # pagerules/URLFWD
            with open('tests/fixtures/cloudflare-pagerules.json') as fh:
                mock.get(
                    f'{base}/pagerules?status=active',
                    status_code=200,
                    text=fh.read(),
                )

            # records
            base = f'{base}/dns_records'
            with open(
                'tests/fixtures/cloudflare-dns_records-page-1.json'
            ) as fh:
                mock.get(f'{base}?page=1', status_code=200, text=fh.read())
            with open(
                'tests/fixtures/cloudflare-dns_records-page-2.json'
            ) as fh:
                mock.get(f'{base}?page=2', status_code=200, text=fh.read())
            with open(
                'tests/fixtures/cloudflare-dns_records-page-3.json'
            ) as fh:
                mock.get(f'{base}?page=3', status_code=200, text=fh.read())

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(24, len(zone.records))

            changes = self.expected.changes(zone, provider)

            # delete a urlfwd, create 3 urlfwd, delete 1 NS
            self.assertEqual(9, len(changes))

        # re-populating the same zone/records comes out of cache, no calls
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(24, len(again.records))

    def test_apply(self):
        provider = CloudflareProvider(
            'test', 'email', 'token', retry_period=0, strict_supports=False
        )

        provider._request = Mock()

        provider._request.side_effect = [
            self.empty,  # no zones
            {'result': {'id': 42}},  # zone create
        ] + [
            None
        ] * 34  # individual record creates

        # non-existent zone, create everything
        plan = provider.plan(self.expected)
        self.assertEqual(22, len(plan.changes))
        self.assertEqual(22, provider.apply(plan))
        self.assertFalse(plan.exists)

        provider._request.assert_has_calls(
            [
                # created the domain
                call(
                    'POST',
                    '/zones',
                    data={'jump_start': False, 'name': 'unit.tests'},
                ),
                # created at least one of the record with expected data
                call(
                    'POST',
                    '/zones/42/dns_records',
                    data={
                        'content': 'ns1.unit.tests.',
                        'type': 'NS',
                        'name': 'under.unit.tests',
                        'ttl': 3600,
                    },
                ),
                # make sure semicolons are not escaped when sending data and the
                # correct double quotes escapes are used so it is accepted by CF
                call(
                    'POST',
                    '/zones/42/dns_records',
                    data={
                        "content": "\"v=DKIM1;k=rsa;s=email;h=sha256;"
                        "p=A/kinda+of/long/string+with+numb3rs\"",
                        "type": "TXT",
                        "name": "txt.unit.tests",
                        "ttl": 600,
                    },
                ),
                # create at least one pagerules
                call(
                    'POST',
                    '/zones/42/pagerules',
                    data={
                        'targets': [
                            {
                                'target': 'url',
                                'constraint': {
                                    'operator': 'matches',
                                    'value': 'urlfwd.unit.tests/',
                                },
                            }
                        ],
                        'actions': [
                            {
                                'id': 'forwarding_url',
                                'value': {
                                    'url': 'http://www.unit.tests',
                                    'status_code': 302,
                                },
                            }
                        ],
                        'status': 'active',
                    },
                ),
            ],
            True,
        )
        # expected number of total calls
        self.assertEqual(36, provider._request.call_count)

        provider._request.reset_mock()

        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997653",
                    "type": "A",
                    "name": "www.unit.tests",
                    "content": "1.2.3.4",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997654",
                    "type": "A",
                    "name": "www.unit.tests",
                    "content": "2.2.3.4",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:44.030044Z",
                    "created_on": "2017-03-11T18:01:44.030044Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997655",
                    "type": "A",
                    "name": "nc.unit.tests",
                    "content": "3.2.3.4",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 120,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:44.030044Z",
                    "created_on": "2017-03-11T18:01:44.030044Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997655",
                    "type": "A",
                    "name": "ttl.unit.tests",
                    "content": "4.2.3.4",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 600,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:44.030044Z",
                    "created_on": "2017-03-11T18:01:44.030044Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "2a9140b17ffb0e6aed826049eec970b7",
                    "targets": [
                        {
                            "target": "url",
                            "constraint": {
                                "operator": "matches",
                                "value": "urlfwd.unit.tests/",
                            },
                        }
                    ],
                    "actions": [
                        {
                            "id": "forwarding_url",
                            "value": {
                                "url": "https://www.unit.tests",
                                "status_code": 302,
                            },
                        }
                    ],
                    "priority": 1,
                    "status": "active",
                    "created_on": "2021-06-25T20:10:50.000000Z",
                    "modified_on": "2021-06-28T22:38:10.000000Z",
                },
                {
                    "id": "2a9141b18ffb0e6aed826050eec970b8",
                    "targets": [
                        {
                            "target": "url",
                            "constraint": {
                                "operator": "matches",
                                "value": "urlfwdother.unit.tests/target",
                            },
                        }
                    ],
                    "actions": [
                        {
                            "id": "forwarding_url",
                            "value": {
                                "url": "https://target.unit.tests",
                                "status_code": 301,
                            },
                        }
                    ],
                    "priority": 2,
                    "status": "active",
                    "created_on": "2021-06-25T20:10:50.000000Z",
                    "modified_on": "2021-06-28T22:38:10.000000Z",
                },
            ]
        )

        # we don't care about the POST/create return values
        provider._request.return_value = {}

        # Test out the create rate-limit handling, then 9 successes
        provider._request.side_effect = [CloudflareRateLimitError('{}')] + (
            [None] * 5
        )

        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted,
                'nc',
                {
                    'ttl': 60,  # TTL is below their min
                    'type': 'A',
                    'value': '3.2.3.4',
                },
            )
        )
        wanted.add_record(
            Record.new(
                wanted,
                'ttl',
                {'ttl': 300, 'type': 'A', 'value': '3.2.3.4'},  # TTL change
            )
        )
        wanted.add_record(
            Record.new(
                wanted,
                'urlfwd',
                {
                    'ttl': 300,
                    'type': 'URLFWD',
                    'value': {
                        'path': '/*',  # path change
                        'target': 'https://www.unit.tests/',  # target change
                        'code': 301,  # status_code change
                        'masking': '2',
                        'query': 0,
                    },
                },
            )
        )

        plan = provider.plan(wanted)
        # only see the delete & ttl update, below min-ttl is filtered out
        self.assertEqual(4, len(plan.changes))
        self.assertEqual(4, provider.apply(plan))
        self.assertTrue(plan.exists)
        # creates a the new value and then deletes all the old
        provider._request.assert_has_calls(
            [
                call(
                    'DELETE',
                    '/zones/42/pagerules/2a9141b18ffb0e6aed826050eec970b8',
                ),
                # this one used the zone_id lookup fallback, thus 42
                call(
                    'DELETE',
                    '/zones/42/dns_records/fc12ab34cd5611334422ab3322997653',
                ),
                call(
                    'DELETE',
                    '/zones/ff12ab34cd5611334422ab3322997650/'
                    'dns_records/fc12ab34cd5611334422ab3322997654',
                ),
                call(
                    'PUT',
                    '/zones/42/dns_records/fc12ab34cd5611334422ab3322997655',
                    data={
                        'content': '3.2.3.4',
                        'type': 'A',
                        'name': 'ttl.unit.tests',
                        'proxied': False,
                        'ttl': 300,
                    },
                ),
                call(
                    'PUT',
                    '/zones/42/pagerules/2a9140b17ffb0e6aed826049eec970b7',
                    data={
                        'targets': [
                            {
                                'target': 'url',
                                'constraint': {
                                    'operator': 'matches',
                                    'value': 'urlfwd.unit.tests/*',
                                },
                            }
                        ],
                        'actions': [
                            {
                                'id': 'forwarding_url',
                                'value': {
                                    'url': 'https://www.unit.tests/',
                                    'status_code': 301,
                                },
                            }
                        ],
                        'status': 'active',
                    },
                ),
            ]
        )

        # Run the basic apply tests but with an account_id
        provider = CloudflareProvider(
            'test',
            'email',
            'token',
            account_id='334234243423aaabb334342aaa343433',
            retry_period=0,
            strict_supports=False,
        )

        provider._request = Mock()

        provider._request.side_effect = [
            self.empty,  # no zones
            {'result': {'id': 42, 'name_servers': ['foo']}},  # zone create
        ] + [
            None
        ] * 34  # individual record creates

        # non-existent zone, create everything
        plan = provider.plan(self.expected)
        self.assertEqual(22, len(plan.changes))
        self.assertEqual(22, provider.apply(plan))
        self.assertFalse(plan.exists)

        provider._request.assert_has_calls(
            [
                # created the domain
                call(
                    'POST',
                    '/zones',
                    data={
                        'jump_start': False,
                        'name': 'unit.tests',
                        'account': {'id': '334234243423aaabb334342aaa343433'},
                    },
                ),
                # created at least one of the record with expected data
                call(
                    'POST',
                    '/zones/42/dns_records',
                    data={
                        'content': 'ns1.unit.tests.',
                        'type': 'NS',
                        'name': 'under.unit.tests',
                        'ttl': 3600,
                    },
                ),
                # make sure semicolons are not escaped when sending data
                call(
                    'POST',
                    '/zones/42/dns_records',
                    data={
                        "content": "\"v=DKIM1;k=rsa;s=email;h=sha256;"
                        "p=A/kinda+of/long/string+with+numb3rs\"",
                        "type": "TXT",
                        "name": "txt.unit.tests",
                        "ttl": 600,
                    },
                ),
                # create at least one pagerules
                call(
                    'POST',
                    '/zones/42/pagerules',
                    data={
                        'targets': [
                            {
                                'target': 'url',
                                'constraint': {
                                    'operator': 'matches',
                                    'value': 'urlfwd.unit.tests/',
                                },
                            }
                        ],
                        'actions': [
                            {
                                'id': 'forwarding_url',
                                'value': {
                                    'url': 'http://www.unit.tests',
                                    'status_code': 302,
                                },
                            }
                        ],
                        'status': 'active',
                    },
                ),
            ],
            True,
        )
        # expected number of total calls
        self.assertEqual(36, provider._request.call_count)

        # Creating new zone with plan_type
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )

        provider._request = Mock()
        provider._request.side_effect = [
            self.empty,  # no zones
            {'result': {'id': 42, 'name_servers': ['foo']}},  # zone create
            {
                'result': [
                    {'legacy_id': 'free', 'id': 'plan-1'},
                    {'legacy_id': 'enterprise', 'id': 'plan-2'},
                ]
            },  # available plans
            {'result': {'plan': {'legacy_id': 'enterprise'}}},  # plan update
        ] + [
            self.empty
        ] * 34  # individual record creates

        # non-existent zone, create everything
        plan = provider.plan(self.expected)
        self.assertEqual(22, len(plan.changes))
        self.assertEqual(22, provider.apply(plan))
        self.assertFalse(plan.exists)

        expected = [
            # created the domain
            call(
                'POST',
                '/zones',
                data={
                    'jump_start': False,
                    'name': 'unit.tests',
                    'account': {'id': 'account_id'},
                },
            )
        ]
        request_call_count = 36
        if octodns_supports_meta:
            request_call_count += 2
            expected.extend(
                [
                    # get available plans
                    call('GET', '/zones/42/available_plans'),
                    # update plan
                    call('PATCH', '/zones/42', data={'plan': {'id': 'plan-2'}}),
                ]
            )
        expected.append(
            call(
                'POST',
                '/zones/42/dns_records',
                data={
                    'content': '1.2.3.4',
                    'name': 'unit.tests',
                    'type': 'A',
                    'ttl': 300,
                    'proxied': False,
                },
            )
        )
        provider._request.assert_has_calls(expected, False)
        # expected number of total calls
        self.assertEqual(request_call_count, provider._request.call_count)

        # Creating new zone without plan_type
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type=None
        )

        provider._request = Mock()
        provider._request.side_effect = [
            self.empty,  # no zones
            {'result': {'id': 42, 'name_servers': ['foo']}},  # zone create
        ] + [
            self.empty
        ] * 34  # individual record creates

        # non-existent zone, create everything
        plan = provider.plan(self.expected)
        self.assertEqual(22, len(plan.changes))
        self.assertEqual(22, provider.apply(plan))
        self.assertFalse(plan.exists)

        provider._request.assert_has_calls(
            [
                # created the domain
                call(
                    'POST',
                    '/zones',
                    data={
                        'jump_start': False,
                        'name': 'unit.tests',
                        'account': {'id': 'account_id'},
                    },
                ),
                # no call to get available plans or update plan here
                call(
                    'POST',
                    '/zones/42/dns_records',
                    data={
                        'content': '1.2.3.4',
                        'name': 'unit.tests',
                        'type': 'A',
                        'ttl': 300,
                        'proxied': False,
                    },
                ),
            ],
            False,
        )
        # expected number of total calls
        self.assertEqual(36, provider._request.call_count)

        # Plan update when current plan differs
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {
            'unit.tests.': {
                'id': '42',
                'cloudflare_plan': 'pro',
                'name_servers': [],
            }
        }

        provider._request = Mock()
        provider._request.side_effect = [
            self.empty,
            self.empty,
            # Get available plans
            {
                'result': [
                    {'legacy_id': 'pro', 'id': 'plan-1'},
                    {'legacy_id': 'enterprise', 'id': 'plan-2'},
                ]
            },
            # Update plan
            {'result': {'plan': {'legacy_id': 'enterprise'}}},
        ] + [
            self.empty
        ] * 34  # Create new records

        plan = provider.plan(self.expected)
        self.assertEqual(22, len(plan.changes))
        self.assertEqual(22, provider.apply(plan))

        request_call_count = 36
        expected = [
            # Get existing records
            call(
                'GET',
                '/zones/42/dns_records',
                params={'page': 1, 'per_page': 100},
            ),
            # Get existing pagerules
            call('GET', '/zones/42/pagerules', params={'status': 'active'}),
        ]
        if octodns_supports_meta:
            request_call_count += 2
            expected.extend(
                [
                    # Get available plans
                    call('GET', '/zones/42/available_plans'),
                    # Update plan
                    call('PATCH', '/zones/42', data={'plan': {'id': 'plan-2'}}),
                ]
            )
        provider._request.assert_has_calls(expected, False)
        self.assertEqual(request_call_count, provider._request.call_count)

        # No plan update when current plan matches
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {
            'unit.tests.': {'id': '42', 'cloudflare_plan': 'enterprise'}
        }
        provider._request = Mock()
        provider._request.side_effect = [self.empty] * 2
        provider._update_plan = Mock()
        plan = provider.plan(self.expected)
        if octodns_supports_meta:
            self.assertEqual(
                None, plan.meta
            )  # No meta changes when plans match
        self.assertEqual(2, provider._request.call_count)
        provider._update_plan.assert_not_called()

        # No plan meta when plan_type is None
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type=None
        )
        provider._zones = {
            'unit.tests.': {'id': '42', 'cloudflare_plan': 'pro'}
        }
        provider._request = Mock()
        provider._request.side_effect = [self.empty] * 2
        provider._update_plan = Mock()
        plan = provider.plan(self.expected)
        if octodns_supports_meta:
            self.assertEqual(None, plan.meta)  # No meta when plan_type is None
        self.assertEqual(2, provider._request.call_count)
        provider._update_plan.assert_not_called()

    def test_update_add_swap(self):
        provider = CloudflareProvider('test', 'email', 'token', retry_period=0)

        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997653",
                    "type": "A",
                    "name": "a.unit.tests",
                    "content": "1.1.1.1",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997654",
                    "type": "A",
                    "name": "a.unit.tests",
                    "content": "2.2.2.2",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
            ]
        )

        provider._request = Mock()
        provider._request.side_effect = [
            CloudflareRateLimitError('{}'),
            self.empty,  # no zones
            {'result': {'id': 42, 'name_servers': ['foo']}},  # zone create
            None,
            None,
            None,
            None,
        ]

        # Add something and delete something
        zone = Zone('unit.tests.', [])
        existing = Record.new(
            zone,
            'a',
            {
                'ttl': 300,
                'type': 'A',
                # This matches the zone data above, one to swap, one to leave
                'values': ['1.1.1.1', '2.2.2.2'],
            },
        )
        new = Record.new(
            zone,
            'a',
            {
                'ttl': 300,
                'type': 'A',
                # This leaves one, swaps ones, and adds one
                'values': ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
            },
        )
        change = Update(existing, new)
        plan = Plan(zone, zone, [change], True)
        provider._apply(plan)

        # get the list of zones, create a zone, add some records, update
        # something, and delete something
        provider._request.assert_has_calls(
            [
                call('GET', '/zones', params={'page': 1, 'per_page': 50}),
                call(
                    'POST',
                    '/zones',
                    data={'jump_start': False, 'name': 'unit.tests'},
                ),
                call(
                    'POST',
                    '/zones/42/dns_records',
                    data={
                        'content': '4.4.4.4',
                        'type': 'A',
                        'name': 'a.unit.tests',
                        'proxied': False,
                        'ttl': 300,
                    },
                ),
                call(
                    'PUT',
                    '/zones/42/dns_records/fc12ab34cd5611334422ab3322997654',
                    data={
                        'content': '2.2.2.2',
                        'type': 'A',
                        'name': 'a.unit.tests',
                        'proxied': False,
                        'ttl': 300,
                    },
                ),
                call(
                    'PUT',
                    '/zones/42/dns_records/fc12ab34cd5611334422ab3322997653',
                    data={
                        'content': '3.3.3.3',
                        'type': 'A',
                        'name': 'a.unit.tests',
                        'proxied': False,
                        'ttl': 300,
                    },
                ),
            ]
        )

    def test_update_delete(self):
        # We need another run so that we can delete, we can't both add and
        # delete in one go b/c of swaps
        provider = CloudflareProvider('test', 'email', 'token', retry_period=0)

        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997653",
                    "type": "NS",
                    "name": "unit.tests",
                    "content": "ns1.foo.bar",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997654",
                    "type": "NS",
                    "name": "unit.tests",
                    "content": "ns2.foo.bar",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "2a9140b17ffb0e6aed826049eec974b7",
                    "targets": [
                        {
                            "target": "url",
                            "constraint": {
                                "operator": "matches",
                                "value": "urlfwd1.unit.tests/",
                            },
                        }
                    ],
                    "actions": [
                        {
                            "id": "forwarding_url",
                            "value": {
                                "url": "https://www.unit.tests",
                                "status_code": 302,
                            },
                        }
                    ],
                    "priority": 1,
                    "status": "active",
                    "created_on": "2021-06-25T20:10:50.000000Z",
                    "modified_on": "2021-06-28T22:38:10.000000Z",
                },
                {
                    "id": "2a9141b18ffb0e6aed826054eec970b8",
                    "targets": [
                        {
                            "target": "url",
                            "constraint": {
                                "operator": "matches",
                                "value": "urlfwd1.unit.tests/target",
                            },
                        }
                    ],
                    "actions": [
                        {
                            "id": "forwarding_url",
                            "value": {
                                "url": "https://target.unit.tests",
                                "status_code": 301,
                            },
                        }
                    ],
                    "priority": 2,
                    "status": "active",
                    "created_on": "2021-06-25T20:10:50.000000Z",
                    "modified_on": "2021-06-28T22:38:10.000000Z",
                },
            ]
        )

        provider._request = Mock()
        provider._request.side_effect = [
            CloudflareRateLimitError('{}'),
            self.empty,  # no zones
            {'result': {'id': 42, 'name_servers': ['foo']}},  # zone create
            None,
            None,
            None,
            None,
        ]

        # Add something and delete something
        zone = Zone('unit.tests.', [])
        existing = Record.new(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'NS',
                # This matches the zone data above, one to delete, one to leave
                'values': ['ns1.foo.bar.', 'ns2.foo.bar.'],
            },
        )
        exstingurlfwd = Record.new(
            zone,
            'urlfwd1',
            {
                'ttl': 300,
                'type': 'URLFWD',
                'values': [
                    {
                        'path': '/',
                        'target': 'https://www.unit.tests',
                        'code': 302,
                        'masking': '2',
                        'query': 0,
                    },
                    {
                        'path': '/target',
                        'target': 'https://target.unit.tests',
                        'code': 301,
                        'masking': '2',
                        'query': 0,
                    },
                ],
            },
        )
        new = Record.new(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'NS',
                # This leaves one and deletes one
                'value': 'ns2.foo.bar.',
            },
        )
        newurlfwd = Record.new(
            zone,
            'urlfwd1',
            {
                'ttl': 300,
                'type': 'URLFWD',
                'value': {
                    'path': '/',
                    'target': 'https://www.unit.tests',
                    'code': 302,
                    'masking': '2',
                    'query': 0,
                },
            },
        )
        change = Update(existing, new)
        changeurlfwd = Update(exstingurlfwd, newurlfwd)
        plan = Plan(zone, zone, [change, changeurlfwd], True)
        provider._apply(plan)

        # Get zones, create zone, create a record, delete a record
        provider._request.assert_has_calls(
            [
                call('GET', '/zones', params={'page': 1, 'per_page': 50}),
                call(
                    'POST',
                    '/zones',
                    data={'jump_start': False, 'name': 'unit.tests'},
                ),
                call(
                    'PUT',
                    '/zones/42/dns_records/fc12ab34cd5611334422ab3322997654',
                    data={
                        'content': 'ns2.foo.bar.',
                        'type': 'NS',
                        'name': 'unit.tests',
                        'ttl': 300,
                    },
                ),
                call(
                    'DELETE',
                    '/zones/42/dns_records/fc12ab34cd5611334422ab3322997653',
                ),
                call(
                    'PUT',
                    '/zones/42/pagerules/2a9140b17ffb0e6aed826049eec974b7',
                    data={
                        'targets': [
                            {
                                'target': 'url',
                                'constraint': {
                                    'operator': 'matches',
                                    'value': 'urlfwd1.unit.tests/',
                                },
                            }
                        ],
                        'actions': [
                            {
                                'id': 'forwarding_url',
                                'value': {
                                    'url': 'https://www.unit.tests',
                                    'status_code': 302,
                                },
                            }
                        ],
                        'status': 'active',
                    },
                ),
                call(
                    'DELETE',
                    '/zones/42/pagerules/2a9141b18ffb0e6aed826054eec970b8',
                ),
            ]
        )

    def test_pagerules(self):
        provider = CloudflareProvider(
            'test', 'email', 'token', retry_period=0, pagerules=False
        )

        # Set things up to preexist/mock as necessary
        zone = Zone('unit.tests.', [])
        # Stuff a fake zone id in place
        provider._zones = {zone.name: {'id': '42', 'name_servers': ['foo']}}
        provider._request = Mock()
        side_effect = [
            {
                'result': [],
                'result_info': {'count': 0, 'per_page': 50},
                # /zones/42/dns_records
            },
            {
                'result': [
                    {
                        "id": "2a9140b17ffb0e6aed826049eec974b7",
                        "targets": [
                            {
                                "target": "url",
                                "constraint": {
                                    "operator": "matches",
                                    "value": "urlfwd1.unit.tests/",
                                },
                            }
                        ],
                        "actions": [
                            {
                                "id": "forwarding_url",
                                "value": {
                                    "url": "https://www.unit.tests",
                                    "status_code": 302,
                                },
                            }
                        ],
                        "priority": 1,
                        "status": "active",
                        "created_on": "2021-06-25T20:10:50.000000Z",
                        "modified_on": "2021-06-28T22:38:10.000000Z",
                    }
                ],
                'result_info': {'count': 1, 'per_page': 50},
                # /zones/42/pagerules
            },
        ]
        provider._request.side_effect = side_effect

        # Now we populate, and expect to see nothing
        self.assertFalse(provider.plan(zone))
        # We should have had only a single call to get the dns_records, no
        # calls to pagerules
        provider._request.assert_called_once()

        # reset things
        provider._zone_records = {}
        provider.SUPPORTS.add('URLFWD')
        provider._request.side_effect = side_effect
        # enable pagerules
        provider.pagerules = True
        # plan again, this time we expect both calls and a record
        plan = provider.plan(zone)
        self.assertEqual(1, len(plan.changes))
        change = list(plan.changes)[0]
        self.assertEqual('URLFWD', change.record._type)
        provider._request.assert_has_calls(
            [
                call(
                    'GET',
                    '/zones/42/dns_records',
                    params={'page': 1, 'per_page': 100},
                ),
                call('GET', '/zones/42/pagerules', params={'status': 'active'}),
            ]
        )

    def test_ptr(self):
        provider = CloudflareProvider('test', 'email', 'token')

        zone = Zone('unit.tests.', [])
        # PTR record
        ptr_record = Record.new(
            zone, 'ptr', {'ttl': 300, 'type': 'PTR', 'value': 'foo.bar.com.'}
        )

        ptr_record_contents = provider._gen_data(ptr_record)
        self.assertEqual(
            {
                'name': 'ptr.unit.tests',
                'ttl': 300,
                'type': 'PTR',
                'content': 'foo.bar.com.',
            },
            list(ptr_record_contents)[0],
        )

    def test_loc(self):
        self.maxDiff = None
        provider = CloudflareProvider('test', 'email', 'token')

        zone = Zone('unit.tests.', [])
        # LOC record
        loc_record = Record.new(
            zone,
            'example',
            {
                'ttl': 300,
                'type': 'LOC',
                'value': {
                    'lat_degrees': 31,
                    'lat_minutes': 58,
                    'lat_seconds': 52.1,
                    'lat_direction': 'S',
                    'long_degrees': 115,
                    'long_minutes': 49,
                    'long_seconds': 11.7,
                    'long_direction': 'E',
                    'altitude': 20,
                    'size': 10,
                    'precision_horz': 10,
                    'precision_vert': 2,
                },
            },
        )

        loc_record_contents = provider._gen_data(loc_record)
        self.assertEqual(
            {
                'name': 'example.unit.tests',
                'ttl': 300,
                'type': 'LOC',
                'data': {
                    'lat_degrees': 31,
                    'lat_minutes': 58,
                    'lat_seconds': 52.1,
                    'lat_direction': 'S',
                    'long_degrees': 115,
                    'long_minutes': 49,
                    'long_seconds': 11.7,
                    'long_direction': 'E',
                    'altitude': 20,
                    'size': 10,
                    'precision_horz': 10,
                    'precision_vert': 2,
                },
            },
            list(loc_record_contents)[0],
        )

    def test_naptr(self):
        self.maxDiff = None
        provider = CloudflareProvider('test', 'email', 'token')

        cf_data = {
            'comment': None,
            'content': '20 100 "S" "SIP+D2U" "" _sip._udp.unit.tests.',
            'created_on': '2023-01-08T01:02:34.567985Z',
            'data': {
                'flags': 'S',
                'order': 20,
                'preference': 100,
                'regex': '',
                'replacement': '_sip._udp.unit.tests.',
                'service': 'SIP+D2U',
            },
            'id': '8b60c8518d09465ffc7741b7a4a431f98',
            'locked': False,
            'meta': {
                'auto_added': False,
                'managed_by_apps': False,
                'managed_by_argo_tunnel': False,
                'source': 'primary',
            },
            'modified_on': '2023-01-08T01:02:34.567985Z',
            'name': 'naptr.unit.tests',
            'proxiable': False,
            'proxied': False,
            'tags': [],
            'ttl': 1,
            'type': 'NAPTR',
            'zone_id': 'd515defe41b173bee9488d9a4b5f5de9f',
            'zone_name': 'unit.tests',
        }
        data = provider._data_for_NAPTR('NAPTR', [cf_data])
        self.assertEqual(
            {
                'ttl': 300,
                'type': 'NAPTR',
                'values': [
                    {
                        'flags': 'S',
                        'order': 20,
                        'preference': 100,
                        'regexp': '',
                        'replacement': '_sip._udp.unit.tests.',
                        'service': 'SIP+D2U',
                    }
                ],
            },
            data,
        )

        zone = Zone('unit.tests.', [])
        record = Record.new(zone, 'naptr', data)
        contents = list(provider._contents_for_NAPTR(record))
        self.assertEqual([{'data': cf_data['data']}], contents)

        key = provider._gen_key(cf_data)
        self.assertEqual('20 100 "S" "SIP+D2U" "" _sip._udp.unit.tests.', key)

    def test_srv(self):
        provider = CloudflareProvider('test', 'email', 'token')

        zone = Zone('unit.tests.', [])
        # SRV record not under a sub-domain
        srv_record = Record.new(
            zone,
            '_example._tcp',
            {
                'ttl': 300,
                'type': 'SRV',
                'value': {
                    'port': 1234,
                    'priority': 0,
                    'target': 'nc.unit.tests.',
                    'weight': 5,
                },
            },
        )
        # SRV record under a sub-domain
        srv_record_with_sub = Record.new(
            zone,
            '_example._tcp.sub',
            {
                'ttl': 300,
                'type': 'SRV',
                'value': {
                    'port': 1234,
                    'priority': 0,
                    'target': 'nc.unit.tests.',
                    'weight': 5,
                },
            },
        )

        srv_record_contents = provider._gen_data(srv_record)
        srv_record_with_sub_contents = provider._gen_data(srv_record_with_sub)
        self.assertEqual(
            {
                'name': '_example._tcp.unit.tests',
                'ttl': 300,
                'type': 'SRV',
                'data': {
                    'service': '_example',
                    'proto': '_tcp',
                    'name': 'unit.tests.',
                    'priority': 0,
                    'weight': 5,
                    'port': 1234,
                    'target': 'nc.unit.tests',
                },
            },
            list(srv_record_contents)[0],
        )
        self.assertEqual(
            {
                'name': '_example._tcp.sub.unit.tests',
                'ttl': 300,
                'type': 'SRV',
                'data': {
                    'service': '_example',
                    'proto': '_tcp',
                    'name': 'sub',
                    'priority': 0,
                    'weight': 5,
                    'port': 1234,
                    'target': 'nc.unit.tests',
                },
            },
            list(srv_record_with_sub_contents)[0],
        )

    def test_svcb(self):
        provider = CloudflareProvider('test', 'email', 'token')

        value = {
            'svcpriority': 42,
            'targetname': 'www.unit.tests.',
            'svcparams': {
                'alpn': ['h3', 'h2'],
                'ipv4hint': '127.0.0.1',
                'no-default-alpn': None,
            },
        }
        data = {'type': 'SVCB', 'ttl': 93, 'value': value}
        zone = Zone('unit.tests.', [])
        record = Record.new(zone, 'svcb', data, lenient=True)
        contents = list(provider._contents_for_SVCB(record))
        self.assertEqual(
            {
                'priority': value['svcpriority'],
                'target': value['targetname'],
                'value': ' alpn="h3,h2" ipv4hint="127.0.0.1" no-default-alpn',
            },
            contents[0]['data'],
        )

    def test_txt(self):
        provider = CloudflareProvider('test', 'email', 'token')

        # single record w/content
        data = provider._data_for_TXT(
            'TXT', [{'ttl': 42, 'content': 'hello world'}]
        )

        self.assertEqual(
            {'ttl': 42, 'type': 'TXT', 'values': ['hello world']}, data
        )

        # missing content, equivilent to empty from CF
        data = provider._data_for_TXT('TXT', [{'ttl': 42}])
        self.assertEqual({'ttl': 42, 'type': 'TXT', 'values': ['']}, data)

        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone,
            '',
            {'type': 'TXT', 'ttl': 300, 'value': 'test-value-without-quotes'},
        )
        data = list(provider._contents_for_TXT(record))
        self.assertEqual([{'content': '"test-value-without-quotes"'}], data)

        # really long txt value
        txt = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.'
        zone = Zone('unit.tests.', [])
        record = Record.new(zone, '', {'type': 'TXT', 'ttl': 300, 'value': txt})
        chunked = record.chunked_values[0]
        data = next(provider._contents_for_TXT(record))
        self.assertEqual({'content': chunked}, data)

    def test_alias(self):
        provider = CloudflareProvider('test', 'email', 'token')

        # A CNAME for us to transform to ALIAS
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )

        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('', record.name)
        self.assertEqual('unit.tests.', record.fqdn)
        self.assertEqual('ALIAS', record._type)
        self.assertEqual('www.unit.tests.', record.value)

        # Make sure we transform back to CNAME going the other way
        contents = provider._gen_data(record)
        self.assertEqual(
            {
                'content': 'www.unit.tests.',
                'name': 'unit.tests',
                'proxied': False,
                'ttl': 300,
                'type': 'CNAME',
            },
            list(contents)[0],
        )

    def test_gen_key(self):
        provider = CloudflareProvider('test', 'email', 'token')

        for expected, data in (
            ('foo.bar.com.', {'content': 'foo.bar.com.', 'type': 'CNAME'}),
            (
                '10 foo.bar.com.',
                {'content': 'foo.bar.com.', 'priority': 10, 'type': 'MX'},
            ),
            (
                '0 tag some-value',
                {
                    'data': {'flags': 0, 'tag': 'tag', 'value': 'some-value'},
                    'type': 'CAA',
                },
            ),
            (
                '42 100 thing-were-pointed.at 101',
                {
                    'data': {
                        'port': 42,
                        'priority': 100,
                        'target': 'thing-were-pointed.at',
                        'weight': 101,
                    },
                    'type': 'SRV',
                },
            ),
            (
                '31 58 52.1 S 115 49 11.7 E 20 10 10 2',
                {
                    'data': {
                        'lat_degrees': 31,
                        'lat_minutes': 58,
                        'lat_seconds': 52.1,
                        'lat_direction': 'S',
                        'long_degrees': 115,
                        'long_minutes': 49,
                        'long_seconds': 11.7,
                        'long_direction': 'E',
                        'altitude': 20,
                        'size': 10,
                        'precision_horz': 10,
                        'precision_vert': 2,
                    },
                    'type': 'LOC',
                },
            ),
            (
                '99 www.unit.tests. alpn="h3,h2"',
                {
                    'data': {
                        'priority': 99,
                        'target': 'www.unit.tests.',
                        'value': 'alpn="h3,h2"',
                    },
                    'type': 'SVCB',
                },
            ),
        ):
            self.assertEqual(expected, provider._gen_key(data))

    def test_cdn(self):
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', True
        )

        # A CNAME for us to transform to ALIAS
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "cname.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "A",
                    "name": "a.unit.tests",
                    "content": "1.1.1.1",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "A",
                    "name": "a.unit.tests",
                    "content": "1.1.1.2",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "A",
                    "name": "multi.unit.tests",
                    "content": "1.1.1.3",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "AAAA",
                    "name": "multi.unit.tests",
                    "content": "::1",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                },
            ]
        )

        zone = Zone('unit.tests.', [])
        provider.populate(zone)

        # the two A records get merged into one CNAME record pointing to
        # the CDN.
        self.assertEqual(3, len(zone.records))

        ordered = sorted(zone.records, key=lambda r: r.name)

        record = ordered[0]
        self.assertEqual('a', record.name)
        self.assertEqual('a.unit.tests.', record.fqdn)
        self.assertEqual('CNAME', record._type)
        self.assertEqual('a.unit.tests.cdn.cloudflare.net.', record.value)

        record = ordered[1]
        self.assertEqual('cname', record.name)
        self.assertEqual('cname.unit.tests.', record.fqdn)
        self.assertEqual('CNAME', record._type)
        self.assertEqual('cname.unit.tests.cdn.cloudflare.net.', record.value)

        record = ordered[2]
        self.assertEqual('multi', record.name)
        self.assertEqual('multi.unit.tests.', record.fqdn)
        self.assertEqual('CNAME', record._type)
        self.assertEqual('multi.unit.tests.cdn.cloudflare.net.', record.value)

        # CDN enabled records can't be updated, we don't know the real values
        # never point a Cloudflare record to itself.
        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted,
                'cname',
                {
                    'ttl': 300,
                    'type': 'CNAME',
                    'value': 'change.unit.tests.cdn.cloudflare.net.',
                },
            )
        )
        wanted.add_record(
            Record.new(
                wanted,
                'new',
                {
                    'ttl': 300,
                    'type': 'CNAME',
                    'value': 'new.unit.tests.cdn.cloudflare.net.',
                },
            )
        )
        wanted.add_record(
            Record.new(
                wanted,
                'created',
                {'ttl': 300, 'type': 'CNAME', 'value': 'www.unit.tests.'},
            )
        )

        plan = provider.plan(wanted)
        self.assertEqual(1, len(plan.changes))

    def test_cdn_alias(self):
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', True
        )

        # A CNAME for us to transform to ALIAS
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )

        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('', record.name)
        self.assertEqual('unit.tests.', record.fqdn)
        self.assertEqual('ALIAS', record._type)
        self.assertEqual('unit.tests.cdn.cloudflare.net.', record.value)

        # CDN enabled records can't be updated, we don't know the real values
        # never point a Cloudflare record to itself.
        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted,
                '',
                {
                    'ttl': 300,
                    'type': 'ALIAS',
                    'value': 'change.unit.tests.cdn.cloudflare.net.',
                },
            )
        )

        plan = provider.plan(wanted)
        self.assertEqual(False, hasattr(plan, 'changes'))

    def test_unproxiabletype_recordfor_returnsrecordwithnocloudflare(self):
        provider = CloudflareProvider('test', 'email', 'token')
        name = "unit.tests"
        _type = "NS"
        zone_records = [
            {
                "id": "fc12ab34cd5611334422ab3322997654",
                "type": _type,
                "name": name,
                "content": "ns2.foo.bar",
                "proxiable": True,
                "proxied": False,
                "ttl": 300,
                "locked": False,
                "zone_id": "ff12ab34cd5611334422ab3322997650",
                "zone_name": "unit.tests",
                "modified_on": "2017-03-11T18:01:43.420689Z",
                "created_on": "2017-03-11T18:01:43.420689Z",
                "meta": {"auto_added": False},
            }
        ]
        provider.zone_records = Mock(return_value=zone_records)
        zone = Zone('unit.tests.', [])
        provider.populate(zone)

        record = provider._record_for(zone, name, _type, zone_records, False)

        self.assertFalse(record.octodns.get('auto-ttl', False))
        self.assertFalse(record.octodns.get('proxied', False))

    def test_proxiabletype_recordfor_retrecordwithcloudflareunproxied(self):
        provider = CloudflareProvider('test', 'email', 'token')
        name = "multi.unit.tests"
        _type = "AAAA"
        zone_records = [
            {
                "id": "fc12ab34cd5611334422ab3322997642",
                "type": _type,
                "name": name,
                "content": "::1",
                "proxiable": True,
                "proxied": False,
                "ttl": 300,
                "locked": False,
                "zone_id": "ff12ab34cd5611334422ab3322997650",
                "zone_name": "unit.tests",
                "modified_on": "2017-03-11T18:01:43.420689Z",
                "created_on": "2017-03-11T18:01:43.420689Z",
                "meta": {"auto_added": False},
            }
        ]
        provider.zone_records = Mock(return_value=zone_records)
        zone = Zone('unit.tests.', [])
        provider.populate(zone)

        record = provider._record_for(zone, name, _type, zone_records, False)

        self.assertFalse(
            record.octodns.get('cloudflare', {}).get('proxied', False)
        )

    def test_proxiabletype_recordfor_returnsrecordwithcloudflareproxied(self):
        provider = CloudflareProvider('test', 'email', 'token')
        name = "multi.unit.tests"
        _type = "AAAA"
        zone_records = [
            {
                "id": "fc12ab34cd5611334422ab3322997642",
                "type": _type,
                "name": name,
                "content": "::1",
                "proxiable": True,
                "proxied": True,
                "ttl": 1,
                "locked": False,
                "zone_id": "ff12ab34cd5611334422ab3322997650",
                "zone_name": "unit.tests",
                "modified_on": "2017-03-11T18:01:43.420689Z",
                "created_on": "2017-03-11T18:01:43.420689Z",
                "meta": {"auto_added": False},
            }
        ]
        provider.zone_records = Mock(return_value=zone_records)
        zone = Zone('unit.tests.', [])
        provider.populate(zone)

        record = provider._record_for(zone, name, _type, zone_records, False)

        self.assertTrue(record.octodns['cloudflare']['auto-ttl'])
        self.assertTrue(record.octodns['cloudflare']['proxied'])

    def test_record_for_auto_ttl_no_proxied(self):
        provider = CloudflareProvider('test', 'email', 'token')
        name = "proxied.unit.tests"
        _type = "A"
        zone_records = [
            {
                "id": "fc12ab34cd5611334422ab3322997642",
                "type": _type,
                "name": name,
                "content": "4.3.2.1",
                "proxiable": True,
                "proxied": False,
                "ttl": 1,
                "locked": False,
                "zone_id": "ff12ab34cd5611334422ab3322997650",
                "zone_name": "unit.tests",
                "modified_on": "2017-03-11T18:01:43.420689Z",
                "created_on": "2017-03-11T18:01:43.420689Z",
                "meta": {"auto_added": False},
            }
        ]

        zone = Zone('unit.tests.', [])
        record = provider._record_for(zone, name, _type, zone_records, False)

        self.assertTrue(record.octodns['cloudflare']['auto-ttl'])
        self.assertFalse(record.octodns['cloudflare'].get('proxied', False))

    def test_proxiedrecordandnewttl_includechange_returnsfalse(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        existing = set_record_proxied_flag(
            Record.new(
                zone,
                'a',
                {'ttl': 1, 'type': 'A', 'values': ['1.1.1.1', '2.2.2.2']},
            ),
            True,
        )
        new = set_record_proxied_flag(
            Record.new(
                zone,
                'a',
                {'ttl': 300, 'type': 'A', 'values': ['1.1.1.1', '2.2.2.2']},
            ),
            True,
        )
        change = Update(existing, new)

        include_change = provider._include_change(change)

        self.assertFalse(include_change)

    def test_auto_ttl_ignores_ttl_change(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        existing = set_record_auto_ttl_flag(
            Record.new(
                zone,
                'a',
                {'ttl': 1, 'type': 'A', 'values': ['1.1.1.1', '2.2.2.2']},
            ),
            True,
        )
        new = set_record_auto_ttl_flag(
            Record.new(
                zone,
                'a',
                {'ttl': 300, 'type': 'A', 'values': ['1.1.1.1', '2.2.2.2']},
            ),
            True,
        )
        change = Update(existing, new)

        include_change = provider._include_change(change)

        self.assertFalse(include_change)

        # if flag is false, would return the change
        existing = set_record_auto_ttl_flag(existing, False)
        include_change = provider._include_change(change)
        self.assertTrue(include_change)

    def test_include_change_special_flags(self):
        provider = CloudflareProvider('test', 'email', 'token')

        zone = Zone('unit.tests.', [])
        a1_plain = Record.new(
            zone, 'www', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
        )
        a1_proxied = set_record_proxied_flag(
            Record.new(
                zone, 'www', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
            ),
            True,
        )
        a1_auto_ttl = set_record_auto_ttl_flag(
            Record.new(
                zone, 'www', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
            ),
            True,
        )

        # plain <-> proxied
        self.assertTrue(provider._include_change(Update(a1_plain, a1_proxied)))
        self.assertTrue(provider._include_change(Update(a1_proxied, a1_plain)))
        # plain <-> auto-ttl
        self.assertTrue(provider._include_change(Update(a1_plain, a1_auto_ttl)))
        self.assertTrue(provider._include_change(Update(a1_auto_ttl, a1_plain)))
        # proxied <-> auto-ttl
        self.assertTrue(
            provider._include_change(Update(a1_proxied, a1_auto_ttl))
        )
        self.assertTrue(
            provider._include_change(Update(a1_auto_ttl, a1_proxied))
        )

        # no special flag changes
        self.assertFalse(provider._include_change(Update(a1_plain, a1_plain)))
        self.assertFalse(
            provider._include_change(Update(a1_proxied, a1_proxied))
        )
        self.assertFalse(
            provider._include_change(Update(a1_auto_ttl, a1_auto_ttl))
        )

    def test_include_change_min_ttl(self):
        provider = CloudflareProvider('test', 'email', 'token')

        zone = Zone('unit.tests.', [])
        below1 = Record.new(
            zone, 'www', {'ttl': 42, 'type': 'A', 'value': '1.2.3.4'}
        )
        below2 = Record.new(
            zone, 'www', {'ttl': 119, 'type': 'A', 'value': '1.2.3.4'}
        )
        edge = Record.new(
            zone, 'www', {'ttl': 120, 'type': 'A', 'value': '1.2.3.4'}
        )
        above1 = Record.new(
            zone, 'www', {'ttl': 121, 'type': 'A', 'value': '1.2.3.4'}
        )
        above2 = Record.new(
            zone, 'www', {'ttl': 500, 'type': 'A', 'value': '1.2.3.4'}
        )

        # both below
        self.assertFalse(provider._include_change(Update(below1, below1)))
        self.assertFalse(provider._include_change(Update(below1, below2)))
        self.assertFalse(provider._include_change(Update(below2, below1)))
        self.assertFalse(provider._include_change(Update(below2, below2)))

        # one below, other at
        self.assertFalse(provider._include_change(Update(below1, edge)))
        self.assertFalse(provider._include_change(Update(below2, edge)))
        self.assertFalse(provider._include_change(Update(edge, below1)))
        self.assertFalse(provider._include_change(Update(edge, below2)))

        # both at
        self.assertFalse(provider._include_change(Update(edge, edge)))

        # one at, other above
        self.assertTrue(provider._include_change(Update(edge, above1)))
        self.assertTrue(provider._include_change(Update(edge, above2)))
        self.assertTrue(provider._include_change(Update(above1, edge)))
        self.assertTrue(provider._include_change(Update(above2, edge)))

        # both above
        self.assertTrue(provider._include_change(Update(above1, above2)))
        self.assertTrue(provider._include_change(Update(above2, above1)))
        self.assertFalse(provider._include_change(Update(above1, above1)))
        self.assertFalse(provider._include_change(Update(above2, above2)))

        # one below, one above
        self.assertTrue(provider._include_change(Update(below2, above1)))
        self.assertTrue(provider._include_change(Update(above1, below2)))

    def test_unproxiabletype_gendata_returnsnoproxied(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone, 'a', {'ttl': 3600, 'type': 'NS', 'value': 'ns1.unit.tests.'}
        )

        data = next(provider._gen_data(record))

        self.assertFalse('proxied' in data)

    def test_proxiabletype_gendata_returnsunproxied(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = set_record_proxied_flag(
            Record.new(
                zone, 'a', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
            ),
            False,
        )

        data = next(provider._gen_data(record))

        self.assertFalse(data['proxied'])

    def test_proxiabletype_gendata_returnsproxied(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = set_record_proxied_flag(
            Record.new(
                zone, 'a', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
            ),
            True,
        )

        data = next(provider._gen_data(record))

        self.assertTrue(data['proxied'])

    def test_createrecord_extrachanges_returnsemptylist(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(return_value=[])
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertFalse(extra_changes)

    def test_updaterecord_extrachanges_returnsemptylist(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 120,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertFalse(extra_changes)

    def test_deleterecord_extrachanges_returnsemptylist(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(return_value=[])
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertFalse(extra_changes)

    def test_proxify_extrachanges_returnsupdatelist(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertEqual(1, len(extra_changes))
        self.assertFalse(
            extra_changes[0]
            .existing.octodns.get('cloudflare', {})
            .get('proxied', False)
        )
        self.assertTrue(extra_changes[0].new.octodns['cloudflare']['proxied'])

    def test_unproxify_extrachanges_returnsupdatelist(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": True,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "fc12ab34cd5611334422ab3322997642",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "proxiable": True,
                    "proxied": False,
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertEqual(1, len(extra_changes))
        self.assertTrue(
            extra_changes[0].existing.octodns['cloudflare']['proxied']
        )
        self.assertFalse(
            extra_changes[0]
            .new.octodns.get('cloudflare', {})
            .get('proxied', False)
        )

    def test_emailless_auth(self):
        provider = CloudflareProvider(
            'test', token='token 123', email='email 234'
        )
        headers = provider._sess.headers
        self.assertEqual('email 234', headers['X-Auth-Email'])
        self.assertEqual('token 123', headers['X-Auth-Key'])

        provider = CloudflareProvider('test', token='token 123')
        headers = provider._sess.headers
        self.assertEqual('Bearer token 123', headers['Authorization'])
        self.assertTrue(headers['user-agent'])

    def test_retry_behavior(self):
        provider = CloudflareProvider(
            'test',
            token='token 123',
            email='email 234',
            retry_period=0,
            auth_error_retry_count=2,  # Add auth retry config
        )
        result = {
            "success": True,
            "errors": [],
            "messages": [],
            "result": [],
            "result_info": {"count": 1, "per_page": 50},
        }
        zone = Zone('unit.tests.', [])
        provider._request = Mock()

        # No retry required, just calls and is returned
        provider._zones = None
        provider._request.reset_mock()
        provider._request.side_effect = [result]
        self.assertEqual([], provider.zone_records(zone))
        provider._request.assert_has_calls(
            [call('GET', '/zones', params={'page': 1, 'per_page': 50})]
        )

        # One rate limit retry required
        provider._zones = None
        provider._request.reset_mock()
        provider._request.side_effect = [CloudflareRateLimitError('{}'), result]
        self.assertEqual([], provider.zone_records(zone))
        provider._request.assert_has_calls(
            [call('GET', '/zones', params={'page': 1, 'per_page': 50})]
        )

        # One auth retry required
        provider._zones = None
        provider._request.reset_mock()
        provider._request.side_effect = [
            CloudflareAuthenticationError('{}'),
            result,
        ]
        self.assertEqual([], provider.zone_records(zone))
        provider._request.assert_has_calls(
            [call('GET', '/zones', params={'page': 1, 'per_page': 50})]
        )

        # Two retries required - mixed rate limit and auth errors
        provider._zones = None
        provider._request.reset_mock()
        provider._request.side_effect = [
            CloudflareRateLimitError('{}'),
            CloudflareAuthenticationError('{}'),
            result,
        ]
        self.assertEqual([], provider.zone_records(zone))
        provider._request.assert_has_calls(
            [call('GET', '/zones', params={'page': 1, 'per_page': 50})]
        )

        # Exhaust rate limit retries
        provider._zones = None
        provider._request.reset_mock()
        provider._request.side_effect = [
            CloudflareRateLimitError({"errors": [{"message": "first"}]}),
            CloudflareRateLimitError({"errors": [{"message": "boo"}]}),
            CloudflareRateLimitError({"errors": [{"message": "boo"}]}),
            CloudflareRateLimitError({"errors": [{"message": "boo"}]}),
            CloudflareRateLimitError({"errors": [{"message": "last"}]}),
        ]
        with self.assertRaises(CloudflareRateLimitError) as ctx:
            provider.zone_records(zone)
            self.assertEqual('last', str(ctx.exception))

        # Exhaust auth retries
        provider._zones = None
        provider._request.reset_mock()
        provider._request.side_effect = [
            CloudflareAuthenticationError({"errors": [{"message": "first"}]}),
            CloudflareAuthenticationError({"errors": [{"message": "second"}]}),
            CloudflareAuthenticationError({"errors": [{"message": "last"}]}),
        ]
        with self.assertRaises(CloudflareAuthenticationError) as ctx:
            provider.zone_records(zone)
            self.assertEqual('last', str(ctx.exception))

        # Test with auth retries disabled (default behavior)
        provider = CloudflareProvider(
            'test', token='token 123', email='email 234', retry_period=0
        )
        provider._request = Mock()
        provider._zones = None
        provider._request.side_effect = [CloudflareAuthenticationError('{}')]
        with self.assertRaises(CloudflareAuthenticationError):
            provider.zone_records(zone)
        self.assertEqual(1, provider._request.call_count)

    def test_ttl_mapping(self):
        provider = CloudflareProvider('test', 'email', 'token')

        self.assertEqual(120, provider._ttl_data(120))
        self.assertEqual(120, provider._ttl_data(120))
        self.assertEqual(3600, provider._ttl_data(3600))
        self.assertEqual(300, provider._ttl_data(1))

    def test_tlsa(self):
        provider = CloudflareProvider('test', 'email', 'token')

        cf_data = {
            'comment': None,
            'content': '1 1 1 aa424242424242424242424242424242',
            'created_on': '2022-12-23T01:57:14.567985Z',
            'data': {
                'certificate': 'aa424242424242424242424242424242',
                'matching_type': 1,
                'selector': 1,
                'usage': 1,
            },
            'id': '42998ac69fc4a95cc5c85be9bef2dfbe',
            'locked': False,
            'meta': {
                'auto_added': False,
                'managed_by_apps': False,
                'managed_by_argo_tunnel': False,
                'source': 'primary',
            },
            'modified_on': '2022-12-23T01:57:14.567985Z',
            'name': 'tlsa.unit.tests',
            'proxiable': False,
            'proxied': False,
            'tags': [],
            'ttl': 1,
            'type': 'TLSA',
            'zone_id': 'caf91197cc7930c33b741ec30d29d909',
            'zone_name': 'unit.tests',
        }
        data = provider._data_for_TLSA('TLSA', [cf_data])
        self.assertEqual(
            {
                'ttl': 300,
                'type': 'TLSA',
                'values': [
                    {
                        'certificate_association_data': 'aa424242424242424242424242424242',
                        'certificate_usage': 1,
                        'matching_type': 1,
                        'selector': 1,
                    }
                ],
            },
            data,
        )

        zone = Zone('unit.tests.', [])
        record = Record.new(zone, 'tlsa', data)
        contents = list(provider._contents_for_TLSA(record))
        self.assertEqual([{'data': cf_data['data']}], contents)

        key = provider._gen_key(cf_data)
        self.assertEqual('1 1 1 aa424242424242424242424242424242', key)

    def test_sshfp(self):
        self.maxDiff = None
        provider = CloudflareProvider('test', 'email', 'token')

        cf_data = {
            'comment': None,
            'content': '1 2 859be6ed04643db411f067b6c1da1d75fe08b672',
            'created_on': '2023-03-02T01:02:44.567985Z',
            'data': {
                'algorithm': 1,
                'type': 2,
                'fingerprint': '859be6ed04643db411f067b6c1da1d75fe08b672',
            },
            'id': 'ggozrtnzb11nrr9qs4ko6y3j19qkehux9',
            'locked': False,
            'meta': {
                'auto_added': False,
                'managed_by_apps': False,
                'managed_by_argo_tunnel': False,
                'source': 'primary',
            },
            'modified_on': '2023-03-02T01:02:44.567985Z',
            'name': 'naptr.unit.tests',
            'proxiable': False,
            'proxied': False,
            'tags': [],
            'ttl': 300,
            'type': 'SSHFP',
            'zone_id': 'ff12ab34cd5611334422ab3322997650',
            'zone_name': 'unit.tests',
        }
        data = provider._data_for_SSHFP('SSHFP', [cf_data])
        self.assertEqual(
            {
                'ttl': 300,
                'type': 'SSHFP',
                'values': [
                    {
                        'algorithm': 1,
                        'fingerprint_type': 2,
                        'fingerprint': '859be6ed04643db411f067b6c1da1d75fe08b672',
                    }
                ],
            },
            data,
        )

        zone = Zone('unit.tests.', [])
        record = Record.new(zone, 'sshfp', data)
        contents = list(provider._contents_for_SSHFP(record))
        self.assertEqual([{'data': cf_data['data']}], contents)

        key = provider._gen_key(cf_data)
        self.assertEqual('1 2 859be6ed04643db411f067b6c1da1d75fe08b672', key)

    def test_idna_domain(self):
        self.maxDiff = None
        provider = CloudflareProvider('test', 'email', 'token')
        # existing zone with data
        with requests_mock() as mock:
            base = 'https://api.cloudflare.com/client/v4/zones'
            idna_zone_id = '234234243423aaabb334342bbb343433'
            # zone for idna zone is in page 3
            with open('tests/fixtures/cloudflare-zones-page-3.json') as fh:
                mock.get(f'{base}?page=1', status_code=200, text=fh.read())
            # records for idna zone is in page 3
            base = f'{base}/{idna_zone_id}'
            with open(
                'tests/fixtures/cloudflare-dns_records-page-3.json'
            ) as fh:
                mock.get(
                    f'{base}/dns_records?page=1',
                    status_code=200,
                    text=fh.read(),
                )
            # load page rules for idna zone
            with open('tests/fixtures/cloudflare-pagerules.json') as fh:
                mock.get(
                    f'{base}/pagerules?status=active',
                    status_code=200,
                    text=fh.read(),
                )

            # notice the i is a utf-8 character which becomes `xn--gthub-zsa.com.`
            zone = Zone('gíthub.com.', [])
            provider.populate(zone)
        self.assertEqual(11, len(zone.records))
        self.assertEqual(zone.name, idna_encode('gíthub.com.'))

    def test_account_id_filter(self):
        provider = CloudflareProvider(
            'test',
            'email',
            'token',
            account_id='334234243423aaabb334342aaa343433',
            strict_supports=False,
        )

        provider._request = Mock(status_code=200)
        provider._request.side_effect = [
            self.empty,
            None,
            None,
            None,
            None,
            None,
        ]

        provider.plan(self.expected)
        provider._request.assert_called_with(
            'GET',
            '/zones',
            params={
                'page': 1,
                'per_page': 50,
                'account.id': '334234243423aaabb334342aaa343433',
            },
        )

    def test_list_zones(self):
        provider = CloudflareProvider(
            'test',
            'email',
            'token',
            account_id='334234243423aaabb334342aaa343433',
        )

        # existing zone with data
        with requests_mock() as mock:
            base = 'https://api.cloudflare.com/client/v4/zones'

            # zones
            with open('tests/fixtures/cloudflare-zones-page-1.json') as fh:
                mock.get(f'{base}?page=1', status_code=200, text=fh.read())
            with open('tests/fixtures/cloudflare-zones-page-2.json') as fh:
                mock.get(f'{base}?page=2', status_code=200, text=fh.read())
            with open('tests/fixtures/cloudflare-zones-page-3.json') as fh:
                mock.get(f'{base}?page=3', status_code=200, text=fh.read())
            mock.get(
                f'{base}?page=4',
                status_code=200,
                json={'result': [], 'result_info': {'count': 0, 'per_page': 0}},
            )

            self.assertEqual(
                [
                    'github.com.',
                    'github.io.',
                    'githubusercontent.com.',
                    'unit.tests.',
                    'xn--gthub-zsa.com.',
                ],
                provider.list_zones(),
            )

    def test_record_contains_no_tags(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = set_record_tags(
            Record.new(
                zone, 'a', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
            ),
            [],
        )

        data = next(provider._gen_data(record))

        self.assertEqual('tags' in data, False)

    def test_record_contains_tags(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = set_record_tags(
            Record.new(
                zone, 'a', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
            ),
            ['testing:abc', 'abc:testing'],
        )

        data = next(provider._gen_data(record))

        self.assertCountEqual(data['tags'], ['testing:abc', 'abc:testing'])

    def test_add_tags(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "dd530a1c839d674c437144d2c2ea2861",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "tags": [],
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "dd530a1c839d674c437144d2c2ea2861",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "tags": ["testing:abc", "abc:testing"],
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertEqual(1, len(extra_changes))
        self.assertEqual(
            extra_changes[0]
            .existing.octodns.get('cloudflare', {})
            .get('tags', []),
            [],
        )
        self.assertEqual(
            extra_changes[0].new.octodns['cloudflare']['tags'],
            ['testing:abc', 'abc:testing'],
        )

    def test_update_tags(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "2b31564e42fd095d9fdd7abaf2fc86f8",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "tags": ["testing:abc", "abc:testing"],
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "2b31564e42fd095d9fdd7abaf2fc86f8",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "tags": ["one:abc", "abc:testing"],
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertEqual(1, len(extra_changes))
        self.assertEqual(
            extra_changes[0]
            .existing.octodns.get('cloudflare', {})
            .get('tags', []),
            ["testing:abc", "abc:testing"],
        )
        self.assertEqual(
            sorted(extra_changes[0].new.octodns['cloudflare']['tags']),
            sorted(["one:abc", "abc:testing"]),
        )

    def test_record_contains_comment(self):
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = set_record_comment(
            Record.new(
                zone, 'a', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
            ),
            'an example comment',
        )

        data = next(provider._gen_data(record))

        self.assertEqual(data['comment'], 'an example comment')

    def test_add_comment(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "dd530a1c839d674c437144d2c2ea2861",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "dd530a1c839d674c437144d2c2ea2861",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "comment": "a new comment",
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertEqual(1, len(extra_changes))
        self.assertEqual(
            extra_changes[0]
            .existing.octodns.get('cloudflare', {})
            .get('comment', ''),
            '',
        )
        self.assertEqual(
            extra_changes[0].new.octodns['cloudflare']['comment'],
            'a new comment',
        )

    def test_update_comment(self):
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "2b31564e42fd095d9fdd7abaf2fc86f8",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "comment": "an existing comment",
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        existing = Zone('unit.tests.', [])
        provider.populate(existing)
        provider.zone_records = Mock(
            return_value=[
                {
                    "id": "2b31564e42fd095d9fdd7abaf2fc86f8",
                    "type": "CNAME",
                    "name": "a.unit.tests",
                    "content": "www.unit.tests",
                    "comment": "a new comment",
                    "ttl": 300,
                    "locked": False,
                    "zone_id": "ff12ab34cd5611334422ab3322997650",
                    "zone_name": "unit.tests",
                    "modified_on": "2017-03-11T18:01:43.420689Z",
                    "created_on": "2017-03-11T18:01:43.420689Z",
                    "meta": {"auto_added": False},
                }
            ]
        )
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)

        extra_changes = provider._extra_changes(existing, desired, changes)

        self.assertEqual(1, len(extra_changes))
        self.assertEqual(
            extra_changes[0]
            .existing.octodns.get('cloudflare', {})
            .get('comment', ''),
            'an existing comment',
        )
        self.assertEqual(
            extra_changes[0].new.octodns['cloudflare']['comment'],
            'a new comment',
        )

    def test_change_keyer(self):
        provider = CloudflareProvider('test', 'email', 'token')

        zone = Zone('unit.tests.', [])

        ds = Record.new(
            zone,
            'subber',
            {
                'ttl': 300,
                'type': 'DS',
                'value': {
                    'key_tag': 23,
                    'algorithm': 2,
                    'digest_type': 3,
                    'digest': 'abcdefg',
                },
            },
        )
        self.assertEqual(
            (1, 'subber', 'ZDS'), provider._change_keyer(Create(ds))
        )
        self.assertEqual(
            (0, 'subber', 'DS'), provider._change_keyer(Delete(ds))
        )

        ns = Record.new(
            zone,
            'subber',
            {'ttl': 300, 'type': 'NS', 'value': 'ns1.unit.tests.'},
        )
        self.assertEqual(
            (1, 'subber', 'NS'), provider._change_keyer(Create(ns))
        )
        self.assertEqual(
            (0, 'subber', 'NS'), provider._change_keyer(Delete(ns))
        )

    @patch('octodns_cloudflare.BaseProvider._process_desired_zone')
    def test_process_desired_zone(self, mock_base_process_desired_zone):
        def mock_base_process_desired_zone_impl(desired):
            desired._base_process_desired_zone = True
            return desired

        mock_base_process_desired_zone.side_effect = (
            mock_base_process_desired_zone_impl
        )

        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=False
        )

        zone = Zone('unit.tests.', [])

        ds = Record.new(
            zone,
            'subber',
            {
                'ttl': 300,
                'type': 'DS',
                'value': {
                    'key_tag': 23,
                    'algorithm': 2,
                    'digest_type': 3,
                    'digest': 'abcdefg',
                },
            },
        )
        ns = Record.new(
            zone,
            'subber',
            {'ttl': 300, 'type': 'NS', 'value': 'ns1.unit.tests.'},
        )

        # has both
        desired = zone.copy()
        desired.add_record(ds)
        desired.add_record(ns)
        result = provider._process_desired_zone(desired)
        mock_base_process_desired_zone.assert_called_once_with(desired)
        mock_base_process_desired_zone.reset_mock()
        self.assertTrue(result._base_process_desired_zone)
        self.assertEqual({ds, ns}, result.records)

        # just NS
        desired = zone.copy()
        desired.add_record(ns)
        result = provider._process_desired_zone(desired)
        mock_base_process_desired_zone.assert_called_once_with(desired)
        mock_base_process_desired_zone.reset_mock()
        self.assertTrue(result._base_process_desired_zone)
        self.assertEqual({ns}, result.records)

        # just DS, will be removed
        desired = zone.copy()
        desired.add_record(ds)
        result = provider._process_desired_zone(desired)
        mock_base_process_desired_zone.assert_called_once_with(desired)
        mock_base_process_desired_zone.reset_mock()
        self.assertTrue(result._base_process_desired_zone)
        self.assertEqual(set(), result.records)

        # when in strict mode will error
        provider.strict_supports = True
        desired = zone.copy()
        desired.add_record(ds)
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(desired)
        msg = str(ctx.exception)
        mock_base_process_desired_zone.assert_not_called()
        self.assertTrue('subber.unit.tests.' in msg)
        self.assertTrue('coresponding NS record' in msg)

    @skipIf(
        not octodns_supports_meta,
        'octodns >= 1.11.0 required to test meta support',
    )
    def test_meta(self):
        """Test Cloudflare plan management functionality"""

        # New zone defaults to None in meta
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {}  # Zone doesn't exist yet

        plan = provider.plan(self.expected)
        self.assertEqual(
            {'cloudflare_plan': {'current': None, 'desired': 'enterprise'}},
            plan.meta,
        )

        # Zone not found when getting available plans
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {}  # Empty zones to simulate zone not found

        with self.assertRaises(SupportsException) as ctx:
            provider._available_plans('unit.tests.')

        self.assertEqual(str(ctx.exception), 'test: zone unit.tests. not found')

        # Non-list response when getting available plans
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {'unit.tests.': {'id': '42'}}
        provider._try_request = Mock()
        provider._try_request.return_value = {
            'result': {'error': 'not authorized'}  # Non-list response
        }

        with self.assertRaises(SupportsException) as ctx:
            provider._available_plans('unit.tests.')

        self.assertEqual(
            str(ctx.exception),
            'test: unable to determine supported plans, do you have an Enterprise account?',
        )

        # Unsupported plan type
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='unsupported_plan'
        )
        provider._zones = {'unit.tests.': {'id': '42'}}
        provider._try_request = Mock()
        provider._try_request.return_value = {
            'result': [
                {'legacy_id': 'pro', 'id': 'plan-1'},
                {'legacy_id': 'enterprise', 'id': 'plan-2'},
            ]
        }

        with self.assertRaises(SupportsException) as ctx:
            provider._resolve_plan_legacy_id('unit.tests.', 'unsupported_plan')

        self.assertEqual(
            str(ctx.exception),
            'test: unsupported_plan is not supported for unit.tests.',
        )

        # Older octodns version without meta support
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {
            'unit.tests.': {
                'id': '42',
                'cloudflare_plan': 'pro',
                'name_servers': ['foo'],
            }
        }
        provider._update_plan = Mock()
        provider._request = Mock()
        provider._request.side_effect = [self.empty] * 36  # Create new records
        provider.log = Mock()

        plan = provider.plan(self.expected)
        delattr(plan, 'meta')  # Remove meta attribute to simulate older octodns
        provider.apply(plan)
        self.assertEqual(36, provider._request.call_count)
        provider._update_plan.assert_not_called()

        provider.log.warning.assert_called_once_with(
            'plan_type is set but meta is not supported by octodns %s, plan changes will not be applied',
            octodns_version,
        )

        # Empty meta
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {
            'unit.tests.': {
                'id': '42',
                'cloudflare_plan': 'pro',
                'name_servers': ['foo'],
            }
        }
        provider._update_plan = Mock()
        provider._request = Mock()
        provider._request.side_effect = [self.empty] * 36

        plan = provider.plan(self.expected)
        plan.meta = {}  # Override meta to be empty
        provider.apply(plan)
        self.assertEqual(36, provider._request.call_count)
        provider._update_plan.assert_not_called()

        # Meta without cloudflare_plan
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {
            'unit.tests.': {
                'id': '42',
                'cloudflare_plan': 'pro',
                'name_servers': ['foo'],
            }
        }
        provider._update_plan = Mock()
        provider._request = Mock()
        provider._request.side_effect = [self.empty] * 36

        plan = provider.plan(self.expected)
        plan.meta = {'other_key': 'value'}  # Override meta with unrelated data
        provider.apply(plan)
        self.assertEqual(36, provider._request.call_count)
        provider._update_plan.assert_not_called()

        # Meta with cloudflare_plan but no desired plan
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', plan_type='enterprise'
        )
        provider._zones = {
            'unit.tests.': {
                'id': '42',
                'cloudflare_plan': 'pro',
                'name_servers': ['foo'],
            }
        }
        provider._update_plan = Mock()
        provider._request = Mock()
        provider._request.side_effect = [self.empty] * 36

        plan = provider.plan(self.expected)
        plan.meta = {'cloudflare_plan': {'current': 'pro'}}  # No desired plan
        provider.apply(plan)
        self.assertEqual(36, provider._request.call_count)
        provider._update_plan.assert_not_called()
