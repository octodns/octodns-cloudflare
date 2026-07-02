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
    source = YamlProvider(
        'test', join(dirname(__file__), 'config'), escaped_semicolons=False
    )
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
        provider = CloudflareProvider(
            'test', 'email', 'token', retry_period=0, regional_services=True
        )

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

            # regional hostnames (Cloudflare Regional Services); base above is
            # `.../dns_records`, this endpoint hangs off the zone root
            with open(
                'tests/fixtures/cloudflare-regional_hostnames.json'
            ) as fh:
                mock.get(
                    'https://api.cloudflare.com/client/v4/zones/'
                    '234234243423aaabb334342aaa343435/addressing/'
                    'regional_hostnames',
                    status_code=200,
                    text=fh.read(),
                )

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(24, len(zone.records))

            # the www A record picked up its region from regional services
            www = next(
                r for r in zone.records if r.name == 'www' and r._type == 'A'
            )
            self.assertEqual('eu', www.octodns['cloudflare']['region'])

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
            (
                '2371 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C',
                {
                    'data': {
                        'algorithm': 13,
                        'digest': 'BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C',
                        'digest_type': 2,
                        'key_tag': 2371,
                    },
                    'type': 'DS',
                },
            ),
            (
                '2371 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C',
                {
                    'content': '2371 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C',
                    'type': 'DS',
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

    def test_regional_hostname_recordfor_sets_region(self):
        # _record_for reads the per-zone mapping captured by zone_records and
        # annotates the matching proxiable record with its region_key
        provider = CloudflareProvider(
            'test', 'email', 'token', regional_services=True
        )
        zone = Zone('unit.tests.', [])
        a_records = [
            {
                "id": "fc12ab34cd5611334422ab3322997654",
                "type": "A",
                "name": "www.unit.tests",
                "content": "1.2.3.4",
                "proxiable": True,
                "proxied": True,
                "ttl": 1,
                "zone_id": "ff12ab34cd5611334422ab3322997650",
                "zone_name": "unit.tests",
                "meta": {"auto_added": False},
            }
        ]
        provider._zone_regional_hostnames = {
            'unit.tests.': {'www.unit.tests': 'eu'}
        }
        record = provider._record_for(zone, 'www', 'A', a_records, False)
        self.assertEqual('eu', record.octodns['cloudflare']['region'])

        # a non-proxiable record sharing the hostname must NOT pick up the
        # region — the mapping is hostname-keyed but region only applies to
        # proxiable types; otherwise it would generate a phantom Update every
        # sync (a co-located TXT/MX never converges)
        txt_records = [
            {
                "id": "fc12ab34cd5611334422ab3322997699",
                "type": "TXT",
                "name": "www.unit.tests",
                "content": "hello",
                "ttl": 300,
                "zone_id": "ff12ab34cd5611334422ab3322997650",
                "zone_name": "unit.tests",
                "meta": {"auto_added": False},
            }
        ]
        txt = provider._record_for(zone, 'www', 'TXT', txt_records, False)
        self.assertNotIn('region', txt.octodns.get('cloudflare', {}))

    def test_regional_hostname_recordfor_no_mapping(self):
        # when zone_records is stubbed (no mapping captured) no region is set
        # and no extra request is made
        provider = CloudflareProvider(
            'test', 'email', 'token', regional_services=True
        )
        zone = Zone('unit.tests.', [])
        zone_records = [
            {
                "id": "fc12ab34cd5611334422ab3322997654",
                "type": "A",
                "name": "www.unit.tests",
                "content": "1.2.3.4",
                "proxiable": True,
                "proxied": False,
                "ttl": 300,
                "zone_id": "ff12ab34cd5611334422ab3322997650",
                "zone_name": "unit.tests",
                "meta": {"auto_added": False},
            }
        ]
        record = provider._record_for(zone, 'www', 'A', zone_records, False)
        self.assertNotIn('region', record.octodns.get('cloudflare', {}))

    def test_regional_hostnames_fetch(self):
        provider = CloudflareProvider(
            'test', 'email', 'token', regional_services=True
        )
        provider._try_request = Mock()

        # no proxiable records -> no request, empty mapping (regions only
        # apply to proxiable hostnames)
        self.assertEqual(
            {}, provider._regional_hostnames('42', [{'type': 'TXT'}])
        )
        provider._try_request.assert_not_called()

        # a proxiable record present -> single GET, mapping keyed by hostname
        provider._try_request.return_value = {
            'result': [
                {"hostname": "www.unit.tests", "region_key": "eu"},
                {"hostname": "api.unit.tests", "region_key": "us"},
            ]
        }
        self.assertEqual(
            {'www.unit.tests': 'eu', 'api.unit.tests': 'us'},
            provider._regional_hostnames('42', [{'type': 'A'}]),
        )
        provider._try_request.assert_called_once_with(
            'GET', '/zones/42/addressing/regional_hostnames'
        )

        # a zone with no regional hostnames returns result=null -> empty
        # mapping (observed against live zones)
        provider._try_request.return_value = {'result': None}
        self.assertEqual(
            {}, provider._regional_hostnames('42', [{'type': 'A'}])
        )

    def test_regional_services_disabled(self):
        # default (regional_services=False): every region code path is a no-op
        # and the addressing API is never touched — zero behaviour change for
        # existing users and safe on non-entitled accounts
        provider = CloudflareProvider('test', 'email', 'token')
        self.assertFalse(provider.regional_services)
        provider._zones = {'unit.tests.': {'id': '42', 'name_servers': []}}
        provider._try_request = Mock()

        # the fetch is skipped entirely (no GET) even with proxiable records
        self.assertEqual(
            {}, provider._regional_hostnames('42', [{'type': 'A'}])
        )

        # _reconcile_regions short-circuits (no addressing write) even when a
        # desired record carries a region
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        provider._reconcile_regions(Mock(desired=desired, existing=desired))

        # _extra_changes ignores region diffs when disabled
        existing_zone = Zone('unit.tests.', [])
        existing_zone.add_record(
            self._region_record(existing_zone, region='eu')
        )
        desired_zone = Zone('unit.tests.', [])
        desired_zone.add_record(self._region_record(desired_zone, region='us'))
        self.assertFalse(
            provider._extra_changes(existing_zone, desired_zone, [])
        )

        provider._try_request.assert_not_called()

    def _region_record(self, zone, name='www', region='eu', proxied=True):
        record = Record.new(
            zone, name, {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
        )
        cloudflare = {}
        if proxied:
            cloudflare['proxied'] = True
        if region is not None:
            cloudflare['region'] = region
        if cloudflare:
            record.octodns['cloudflare'] = cloudflare
        return record

    def _region_provider(self, current=None):
        provider = CloudflareProvider(
            'test', 'email', 'token', regional_services=True
        )
        provider._zones = {'unit.tests.': {'id': '42', 'name_servers': []}}
        provider._try_request = Mock(return_value={})
        provider._zone_regional_hostnames = {'unit.tests.': dict(current or {})}
        return provider

    def _region_calls(self, provider):
        # the addressing/region requests issued, as (method, path, data)
        return [
            (c.args[0], c.args[1], c.kwargs.get('data'))
            for c in provider._try_request.call_args_list
            if len(c.args) > 1 and 'addressing/regional_hostnames' in c.args[1]
        ]

    def test_reconcile_regions_add(self):
        # a desired region with none currently set -> POST
        provider = self._region_provider()
        existing = Zone('unit.tests.', [])
        existing.add_record(self._region_record(existing, region=None))
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual(
            [
                (
                    'POST',
                    '/zones/42/addressing/regional_hostnames',
                    {'hostname': 'www.unit.tests', 'region_key': 'eu'},
                )
            ],
            self._region_calls(provider),
        )

    def test_reconcile_regions_change(self):
        # an existing region with a different desired value -> PATCH
        provider = self._region_provider({'www.unit.tests': 'eu'})
        existing = Zone('unit.tests.', [])
        existing.add_record(self._region_record(existing, region='eu'))
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='us'))
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual(
            [
                (
                    'PATCH',
                    '/zones/42/addressing/regional_hostnames/www.unit.tests',
                    {'region_key': 'us'},
                )
            ],
            self._region_calls(provider),
        )

    def test_reconcile_regions_remove(self):
        # a managed hostname that no longer wants a region -> DELETE
        provider = self._region_provider({'www.unit.tests': 'eu'})
        existing = Zone('unit.tests.', [])
        existing.add_record(self._region_record(existing, region='eu'))
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region=None))
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual(
            [
                (
                    'DELETE',
                    '/zones/42/addressing/regional_hostnames/www.unit.tests',
                    None,
                )
            ],
            self._region_calls(provider),
        )

    def test_reconcile_regions_noop(self):
        # desired matches current -> no request
        provider = self._region_provider({'www.unit.tests': 'eu'})
        existing = Zone('unit.tests.', [])
        existing.add_record(self._region_record(existing, region='eu'))
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual([], self._region_calls(provider))

    def test_reconcile_regions_shared_hostname_single_call(self):
        # an A and AAAA sharing a name + region -> exactly one POST
        provider = self._region_provider()
        existing = Zone('unit.tests.', [])
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        aaaa = Record.new(
            desired, 'www', {'ttl': 300, 'type': 'AAAA', 'value': '::1'}
        )
        aaaa.octodns['cloudflare'] = {'proxied': True, 'region': 'eu'}
        desired.add_record(aaaa)
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual(
            [
                (
                    'POST',
                    '/zones/42/addressing/regional_hostnames',
                    {'hostname': 'www.unit.tests', 'region_key': 'eu'},
                )
            ],
            self._region_calls(provider),
        )

    def test_reconcile_regions_delete_one_keeps_sibling_region(self):
        # removing the AAAA but keeping the A (still region=eu) must NOT strip
        # the shared hostname's region — the key shared-hostname safety property
        provider = self._region_provider({'www.unit.tests': 'eu'})
        existing = Zone('unit.tests.', [])
        existing.add_record(self._region_record(existing, region='eu'))
        aaaa = Record.new(
            existing, 'www', {'ttl': 300, 'type': 'AAAA', 'value': '::1'}
        )
        aaaa.octodns['cloudflare'] = {'proxied': True, 'region': 'eu'}
        existing.add_record(aaaa)
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual([], self._region_calls(provider))

    def test_reconcile_regions_leaves_unmanaged_untouched(self):
        # a regional hostname octoDNS doesn't manage (no record in existing or
        # desired) is never deleted
        provider = self._region_provider({'orphan.unit.tests': 'eu'})
        existing = Zone('unit.tests.', [])
        existing.add_record(self._region_record(existing, region=None))
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region=None))
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual([], self._region_calls(provider))

    def test_reconcile_regions_ignores_non_proxiable_and_no_existing(self):
        # non-proxiable desired records are skipped, and a missing existing
        # zone (plan.existing is None, e.g. a brand-new zone) is handled
        provider = self._region_provider()
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        desired.add_record(
            Record.new(
                desired, 'txt', {'ttl': 300, 'type': 'TXT', 'value': 'v'}
            )
        )
        provider._reconcile_regions(Mock(existing=None, desired=desired))
        # only the proxiable www gets a regional POST; the TXT is ignored
        self.assertEqual(
            [
                (
                    'POST',
                    '/zones/42/addressing/regional_hostnames',
                    {'hostname': 'www.unit.tests', 'region_key': 'eu'},
                )
            ],
            self._region_calls(provider),
        )

    def test_validate_regions_skips_non_region_records(self):
        # a non-proxiable record with no region is skipped — no warn, no raise
        # (strict mode would raise on any region issue)
        provider = CloudflareProvider(
            'test',
            'email',
            'token',
            regional_services=True,
            strict_supports=True,
        )
        zone = Zone('unit.tests.', [])
        zone.add_record(
            Record.new(zone, 'txt', {'ttl': 300, 'type': 'TXT', 'value': 'v'})
        )
        provider._validate_regions(zone)

    def test_reconcile_regions_conflicting_last_wins_deterministic(self):
        # conflicting regions at one hostname (validation flags this on its own)
        # — apply is deterministic: records are processed in sorted (name, type)
        # order, so AAAA wins over A regardless of set iteration order
        provider = self._region_provider()
        existing = Zone('unit.tests.', [])
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))  # A eu
        aaaa = Record.new(
            desired, 'www', {'ttl': 300, 'type': 'AAAA', 'value': '::1'}
        )
        aaaa.octodns['cloudflare'] = {'proxied': True, 'region': 'us'}
        desired.add_record(aaaa)
        provider._reconcile_regions(Mock(existing=existing, desired=desired))
        self.assertEqual(
            [
                (
                    'POST',
                    '/zones/42/addressing/regional_hostnames',
                    {'hostname': 'www.unit.tests', 'region_key': 'us'},
                )
            ],
            self._region_calls(provider),
        )

    def test_populate_disabled_skips_addressing(self):
        # with regional_services off (default), populate must NOT call the
        # addressing API even for a zone full of proxiable records — the
        # backwards-compat / non-entitled-safety guarantee, proven end-to-end
        provider = CloudflareProvider(
            'test', 'email', 'token', retry_period=0, pagerules=False
        )
        self.assertFalse(provider.regional_services)
        provider._zones = {'unit.tests.': {'id': '42', 'name_servers': []}}

        with requests_mock() as mock:
            mock.get(
                'https://api.cloudflare.com/client/v4/zones/42/dns_records',
                json={
                    'result': [
                        {
                            'id': '1',
                            'type': 'A',
                            'name': 'www.unit.tests',
                            'content': '1.2.3.4',
                            'proxiable': True,
                            'proxied': True,
                            'ttl': 1,
                        }
                    ],
                    'result_info': {'count': 1, 'per_page': 100},
                },
            )

            def _forbidden(request, context):
                raise AssertionError(
                    f'addressing must not be queried; saw {request.url}'
                )

            mock.get(
                'https://api.cloudflare.com/client/v4/zones/42'
                '/addressing/regional_hostnames',
                json=_forbidden,
            )

            zone = Zone('unit.tests.', [])
            provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = next(iter(zone.records))
        self.assertNotIn('region', record.octodns.get('cloudflare', {}))

    def test_apply_disabled_skips_addressing(self):
        # with regional_services off, apply never writes to the addressing API
        # even when a desired record carries a region
        provider = CloudflareProvider('test', 'email', 'token')
        self.assertFalse(provider.regional_services)
        provider._zones = {'unit.tests.': {'id': '42', 'name_servers': []}}
        provider._try_request = Mock(return_value={})

        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        existing = Zone('unit.tests.', [])
        plan = Mock(desired=desired, existing=existing, changes=[], meta=None)
        provider._apply(plan)

        for call_obj in provider._try_request.call_args_list:
            self.assertNotIn('addressing', str(call_obj))

    def test_apply_reconciles_regions(self):
        # region reconciliation is wired into _apply (end-to-end via the apply
        # entrypoint, not just the helper)
        provider = self._region_provider()
        desired = Zone('unit.tests.', [])
        desired.add_record(self._region_record(desired, region='eu'))
        existing = Zone('unit.tests.', [])
        existing.add_record(self._region_record(existing, region=None))
        plan = Mock(desired=desired, existing=existing, changes=[], meta=None)
        provider._apply(plan)
        self.assertEqual(
            [
                (
                    'POST',
                    '/zones/42/addressing/regional_hostnames',
                    {'hostname': 'www.unit.tests', 'region_key': 'eu'},
                )
            ],
            self._region_calls(provider),
        )

    def test_region_extrachanges(self):
        provider = CloudflareProvider(
            'test', 'email', 'token', regional_services=True
        )
        existing_zone = Zone('unit.tests.', [])
        desired_zone = Zone('unit.tests.', [])

        existing = self._region_record(existing_zone, region='eu')
        existing_zone.add_record(existing)
        desired = self._region_record(desired_zone, region='us')
        desired_zone.add_record(desired)

        # region differs -> an Update is added
        extra = provider._extra_changes(existing_zone, desired_zone, [])
        self.assertEqual(1, len(extra))
        self.assertIsInstance(extra[0], Update)

        # region matches -> nothing extra
        desired.octodns['cloudflare']['region'] = 'eu'
        self.assertFalse(
            provider._extra_changes(existing_zone, desired_zone, [])
        )

    @patch('octodns_cloudflare.BaseProvider._process_desired_zone')
    def test_process_desired_zone_region(self, mock_base):
        mock_base.side_effect = lambda desired: desired
        provider = CloudflareProvider(
            'test',
            'email',
            'token',
            strict_supports=False,
            regional_services=True,
        )
        zone = Zone('unit.tests.', [])

        # region on a non-proxied record is allowed but warned (non-strict)
        desired = zone.copy()
        desired.add_record(
            self._region_record(zone, name='grey', region='eu', proxied=False)
        )
        result = provider._process_desired_zone(desired)
        self.assertEqual(1, len(result.records))
        # the region is preserved (warned, not stripped) so it still applies
        kept = next(iter(result.records))
        self.assertEqual('eu', kept.octodns['cloudflare']['region'])

        # in strict mode each unsupported case raises with a clear message
        provider.strict_supports = True

        # region on a non-proxied record
        desired = zone.copy()
        desired.add_record(
            self._region_record(zone, name='grey', region='eu', proxied=False)
        )
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(desired)
        self.assertIn('non-proxied', str(ctx.exception))

        # region on a non-proxiable record type
        desired = zone.copy()
        txt = Record.new(zone, 'txt', {'ttl': 300, 'type': 'TXT', 'value': 'v'})
        txt.octodns['cloudflare'] = {'region': 'eu'}
        desired.add_record(txt)
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(desired)
        self.assertIn('only applies to', str(ctx.exception))

        # conflicting regions across record types sharing a name
        desired = zone.copy()
        desired.add_record(self._region_record(zone, name='www', region='eu'))
        aaaa = Record.new(
            zone, 'www', {'ttl': 300, 'type': 'AAAA', 'value': '::1'}
        )
        aaaa.octodns['cloudflare'] = {'proxied': True, 'region': 'us'}
        desired.add_record(aaaa)
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(desired)
        self.assertIn('conflicting regions', str(ctx.exception))
        self.assertIn('www.unit.tests.', str(ctx.exception))

        # conflicting regions at the apex (covers the fqdn formatting branch)
        desired = zone.copy()
        apex_a = Record.new(
            zone, '', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
        )
        apex_a.octodns['cloudflare'] = {'proxied': True, 'region': 'eu'}
        apex_aaaa = Record.new(
            zone, '', {'ttl': 300, 'type': 'AAAA', 'value': '::1'}
        )
        apex_aaaa.octodns['cloudflare'] = {'proxied': True, 'region': 'us'}
        desired.add_record(apex_a)
        desired.add_record(apex_aaaa)
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(desired)
        self.assertIn('conflicting regions', str(ctx.exception))
        self.assertIn('unit.tests.', str(ctx.exception))

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

    def test_api_url_default(self):
        provider = CloudflareProvider('test', 'email', 'token')
        self.assertEqual(
            'https://api.cloudflare.com/client/v4', provider.api_url
        )

    def test_api_url_custom(self):
        custom_url = 'https://api.fed.cloudflare.com/client/v4'
        provider = CloudflareProvider(
            'test', 'email', 'token', api_url=custom_url
        )
        self.assertEqual(custom_url, provider.api_url)

        # Verify the custom URL is used in actual requests
        with requests_mock() as mock:
            base = f'{custom_url}/zones'
            mock.get(f'{base}?page=1', status_code=200, json=self.empty)

            zone = Zone('unit.tests.', [])
            provider.populate(zone)

            # Confirm the request went to the custom endpoint
            self.assertEqual(
                f'{custom_url}/zones?page=1&per_page=50', mock.last_request.url
            )

    def test_api_url_trailing_slash(self):
        custom_url = 'https://api.fed.cloudflare.com/client/v4/'
        provider = CloudflareProvider(
            'test', 'email', 'token', api_url=custom_url
        )
        self.assertEqual(
            'https://api.fed.cloudflare.com/client/v4', provider.api_url
        )

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
            'content': '1 1 859be6ed04643db411f067b6c1da1d75fe08b672',
            'created_on': '2023-03-02T01:02:44.567985Z',
            'data': {
                'algorithm': 1,
                'type': 1,
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
                        'fingerprint_type': 1,
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
        self.assertEqual('1 1 859be6ed04643db411f067b6c1da1d75fe08b672', key)

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

    def test_per_value_metadata_populate_differing(self):
        # multiple values, each Cloudflare object with its own comment/tags ->
        # an explicit per-value list, no record-level shorthand
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 'a1',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.4',
                    'comment': 'primary',
                    'tags': ['cdn', 'tag1'],
                    'ttl': 300,
                },
                {
                    'id': 'a2',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.5',
                    'comment': 'failover',
                    'tags': ['cdn', 'tag2'],
                    'ttl': 300,
                },
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        record = next(iter(zone.records))
        cloudflare = record.octodns['cloudflare']
        # differing -> per-value list and no record-level comment/tags
        self.assertNotIn('comment', cloudflare)
        self.assertNotIn('tags', cloudflare)
        by_value = {e['value']: e for e in cloudflare['values']}
        self.assertEqual(by_value['1.2.3.4']['comment'], 'primary')
        self.assertEqual(by_value['1.2.3.4']['tags'], ['cdn', 'tag1'])
        self.assertEqual(by_value['1.2.3.5']['comment'], 'failover')
        self.assertEqual(by_value['1.2.3.5']['tags'], ['cdn', 'tag2'])

    def test_per_value_metadata_populate_uniform(self):
        # multiple values that all share the same metadata keep the
        # record-level shorthand (backwards compatible, no per-value list)
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 'a1',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.4',
                    'comment': 'same',
                    'tags': ['t'],
                    'ttl': 300,
                },
                {
                    'id': 'a2',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.5',
                    'comment': 'same',
                    'tags': ['t'],
                    'ttl': 300,
                },
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        cloudflare = next(iter(zone.records)).octodns['cloudflare']
        self.assertEqual('same', cloudflare['comment'])
        self.assertEqual(['t'], cloudflare['tags'])
        self.assertNotIn('values', cloudflare)

    def test_per_value_metadata_populate_partial(self):
        # one value has metadata, the other none -> list carries only the one
        # with metadata, no record-level default invented
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 'a1',
                    'type': 'A',
                    'name': 'p.unit.tests',
                    'content': '1.2.3.4',
                    'comment': 'only',
                    'ttl': 300,
                },
                {
                    'id': 'a2',
                    'type': 'A',
                    'name': 'p.unit.tests',
                    'content': '1.2.3.5',
                    'ttl': 300,
                },
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        record = next(iter(zone.records))
        cloudflare = record.octodns['cloudflare']
        self.assertNotIn('comment', cloudflare)
        self.assertEqual(
            ['1.2.3.4'], [e['value'] for e in cloudflare['values']]
        )
        self.assertEqual('only', cloudflare['values'][0]['comment'])
        # the value without metadata gets nothing on the way back out
        by_value = {d['content']: d for d in provider._gen_data(record)}
        self.assertNotIn('comment', by_value['1.2.3.5'])
        self.assertNotIn('tags', by_value['1.2.3.5'])
        self.assertEqual('only', by_value['1.2.3.4']['comment'])

    def test_per_value_metadata_gen_data_overrides(self):
        # record-level default + sparse per-value overrides, resolved per field
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone,
            'multi',
            {
                'ttl': 300,
                'type': 'A',
                'values': ['1.2.3.4', '1.2.3.5', '1.2.3.6'],
                'octodns': {
                    'cloudflare': {
                        'comment': 'default-c',
                        'tags': ['default-t'],
                        'values': [
                            {
                                'value': '1.2.3.4',
                                'comment': 'c4',
                                'tags': ['t4'],
                            },
                            # only tags -> comment falls back to record-level
                            {'value': '1.2.3.5', 'tags': ['t5']},
                        ],
                    }
                },
            },
        )
        by_value = {d['content']: d for d in provider._gen_data(record)}
        # fully overridden
        self.assertEqual('c4', by_value['1.2.3.4']['comment'])
        self.assertEqual(['t4'], by_value['1.2.3.4']['tags'])
        # tags overridden, comment inherits record-level default
        self.assertEqual('default-c', by_value['1.2.3.5']['comment'])
        self.assertEqual(['t5'], by_value['1.2.3.5']['tags'])
        # no entry -> record-level default for both
        self.assertEqual('default-c', by_value['1.2.3.6']['comment'])
        self.assertEqual(['default-t'], by_value['1.2.3.6']['tags'])

    def test_record_level_metadata_applies_to_all_values(self):
        # backwards compat: record-level comment/tags with no per-value list
        # apply to every value
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone,
            'multi',
            {
                'ttl': 300,
                'type': 'A',
                'values': ['1.2.3.4', '1.2.3.5'],
                'octodns': {'cloudflare': {'comment': 'shared', 'tags': ['t']}},
            },
        )
        for content in provider._gen_data(record):
            self.assertEqual('shared', content['comment'])
            self.assertEqual(['t'], content['tags'])

    def test_per_value_metadata_round_trip(self):
        # dump then re-emit reproduces each value's comment/tags
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 'a1',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.4',
                    'comment': 'primary',
                    'tags': ['tag1'],
                    'ttl': 300,
                },
                {
                    'id': 'a2',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.5',
                    'comment': 'failover',
                    'tags': ['tag2'],
                    'ttl': 300,
                },
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        record = next(iter(zone.records))
        by_value = {d['content']: d for d in provider._gen_data(record)}
        self.assertEqual('primary', by_value['1.2.3.4']['comment'])
        self.assertEqual(['tag1'], by_value['1.2.3.4']['tags'])
        self.assertEqual('failover', by_value['1.2.3.5']['comment'])
        self.assertEqual(['tag2'], by_value['1.2.3.5']['tags'])

    def test_per_value_metadata_extra_changes(self):
        # a metadata-only change on one value yields exactly one Update;
        # identical metadata yields none
        provider = CloudflareProvider('test', 'email', 'token')

        def records(comment_4):
            return [
                {
                    'id': 'a1',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.4',
                    'comment': comment_4,
                    'ttl': 300,
                },
                {
                    'id': 'a2',
                    'type': 'A',
                    'name': 'multi.unit.tests',
                    'content': '1.2.3.5',
                    'comment': 'failover',
                    'ttl': 300,
                },
            ]

        provider.zone_records = Mock(return_value=records('primary'))
        existing = Zone('unit.tests.', [])
        provider.populate(existing)

        provider.zone_records = Mock(return_value=records('primary-changed'))
        desired = Zone('unit.tests.', [])
        provider.populate(desired)
        changes = existing.changes(desired, provider)
        extra = provider._extra_changes(existing, desired, changes)
        self.assertEqual(1, len(extra))

        # no metadata change -> no extra change
        provider.zone_records = Mock(return_value=records('primary'))
        same = Zone('unit.tests.', [])
        provider.populate(same)
        self.assertEqual(
            0,
            len(
                provider._extra_changes(
                    existing, same, existing.changes(same, provider)
                )
            ),
        )

    @patch('octodns_cloudflare.BaseProvider._process_desired_zone')
    def test_per_value_metadata_validation(self, mock_base):
        mock_base.side_effect = lambda desired: desired
        zone = Zone('unit.tests.', [])

        def make_desired():
            desired = zone.copy()
            desired.add_record(
                Record.new(
                    zone,
                    'multi',
                    {
                        'ttl': 300,
                        'type': 'A',
                        'values': ['1.2.3.4', '1.2.3.5'],
                        'octodns': {
                            'cloudflare': {
                                'values': [
                                    {'value': '9.9.9.9', 'comment': 'orphan'}
                                ]
                            }
                        },
                    },
                )
            )
            return desired

        # strict -> a value not on the record is a plan-time error
        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=True
        )
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(make_desired())
        self.assertIn('not one of the', str(ctx.exception))
        self.assertIn('9.9.9.9', str(ctx.exception))

        # non-strict -> warn and pass through
        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=False
        )
        result = provider._process_desired_zone(make_desired())
        self.assertEqual(1, len(result.records))

        # an entry that references a real value passes validation cleanly,
        # even in strict mode
        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=True
        )
        valid = zone.copy()
        valid.add_record(
            Record.new(
                zone,
                'multi',
                {
                    'ttl': 300,
                    'type': 'A',
                    'values': ['1.2.3.4', '1.2.3.5'],
                    'octodns': {
                        'cloudflare': {
                            'values': [{'value': '1.2.3.4', 'comment': 'ok'}]
                        }
                    },
                },
            )
        )
        result = provider._process_desired_zone(valid)
        self.assertEqual(1, len(result.records))

    @patch('octodns_cloudflare.BaseProvider._process_desired_zone')
    def test_per_value_metadata_malformed(self, mock_base):
        mock_base.side_effect = lambda desired: desired
        zone = Zone('unit.tests.', [])

        def desired_with(values):
            desired = zone.copy()
            desired.add_record(
                Record.new(
                    zone,
                    'm',
                    {
                        'ttl': 300,
                        'type': 'A',
                        'values': ['1.2.3.4', '1.2.3.5'],
                        'octodns': {'cloudflare': {'values': values}},
                    },
                    lenient=True,
                )
            )
            return desired

        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=True
        )
        # values is not a list
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(
                desired_with({'1.2.3.4': {'comment': 'x'}})
            )
        self.assertIn('must be a list', str(ctx.exception))
        # an entry that is not a mapping
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(desired_with(['oops']))
        self.assertIn('must be a mapping', str(ctx.exception))
        # a mapping entry missing its 'value' key
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(
                desired_with([{'comment': 'no value'}])
            )
        self.assertIn('must be a mapping', str(ctx.exception))

        # non-strict: malformed config warns and degrades rather than crashing
        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=False
        )
        result = provider._process_desired_zone(
            desired_with(['oops', {'value': '1.2.3.4', 'comment': 'ok'}])
        )
        self.assertEqual(1, len(result.records))
        # the bad entry is skipped; the good one still applies
        rec = next(iter(result.records))
        by_value = {d['content']: d for d in provider._gen_data(rec)}
        self.assertEqual('ok', by_value['1.2.3.4']['comment'])
        self.assertNotIn('comment', by_value['1.2.3.5'])

        # non-strict + a non-list values warns and passes the record through
        result = provider._process_desired_zone(
            desired_with({'1.2.3.4': {'comment': 'x'}})
        )
        self.assertEqual(1, len(result.records))

        # a non-list values is ignored entirely by _gen_data, which falls back
        # to the record-level comment
        rec2 = Record.new(
            zone,
            'm2',
            {
                'ttl': 300,
                'type': 'A',
                'value': '9.9.9.9',
                'octodns': {
                    'cloudflare': {
                        'comment': 'record-level',
                        'values': {'9.9.9.9': {'comment': 'ignored'}},
                    }
                },
            },
            lenient=True,
        )
        self.assertEqual(
            'record-level', next(provider._gen_data(rec2))['comment']
        )

    def test_per_value_metadata_duplicate_value_warns(self):
        # two Cloudflare objects sharing a value but differing in metadata
        # can't be represented per-value -> keep the first and warn
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        records = [
            {
                'id': 'a1',
                'type': 'A',
                'name': 'dup.unit.tests',
                'content': '1.2.3.4',
                'comment': 'first',
                'ttl': 300,
            },
            {
                'id': 'a2',
                'type': 'A',
                'name': 'dup.unit.tests',
                'content': '1.2.3.4',
                'comment': 'second',
                'ttl': 300,
            },
        ]
        with self.assertLogs(provider.log, level='WARNING') as cm:
            record = provider._record_for(zone, 'dup', 'A', records, True)
        self.assertTrue(any('duplicate values' in line for line in cm.output))
        self.assertEqual('first', record.octodns['cloudflare']['comment'])

    def test_per_value_metadata_duplicate_value_identical(self):
        # duplicate value carrying identical metadata is deduped silently and
        # collapses to the record-level shorthand (no warning, no list)
        provider = CloudflareProvider('test', 'email', 'token')
        zone = Zone('unit.tests.', [])
        records = [
            {
                'id': 'a1',
                'type': 'A',
                'name': 'dup.unit.tests',
                'content': '1.2.3.4',
                'comment': 'same',
                'tags': ['t'],
                'ttl': 300,
            },
            {
                'id': 'a2',
                'type': 'A',
                'name': 'dup.unit.tests',
                'content': '1.2.3.4',
                'comment': 'same',
                'tags': ['t'],
                'ttl': 300,
            },
        ]
        record = provider._record_for(zone, 'dup', 'A', records, True)
        cloudflare = record.octodns['cloudflare']
        self.assertEqual('same', cloudflare['comment'])
        self.assertEqual(['t'], cloudflare['tags'])
        self.assertNotIn('values', cloudflare)

    def test_per_value_metadata_tags_only_entry(self):
        # differing values where one carries only tags and the other only a
        # comment -> each emitted entry omits the field it lacks
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 'a1',
                    'type': 'A',
                    'name': 'm.unit.tests',
                    'content': '1.2.3.4',
                    'tags': ['t4'],
                    'ttl': 300,
                },
                {
                    'id': 'a2',
                    'type': 'A',
                    'name': 'm.unit.tests',
                    'content': '1.2.3.5',
                    'comment': 'c5',
                    'ttl': 300,
                },
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        by_value = {
            e['value']: e
            for e in next(iter(zone.records)).octodns['cloudflare']['values']
        }
        self.assertEqual(['t4'], by_value['1.2.3.4']['tags'])
        self.assertNotIn('comment', by_value['1.2.3.4'])
        self.assertEqual('c5', by_value['1.2.3.5']['comment'])
        self.assertNotIn('tags', by_value['1.2.3.5'])

    def test_cdn_comment_tags(self):
        # CDN rewrites collapse to a single synthetic CNAME and keep the
        # record-level comment/tags shorthand (no per-value list)
        provider = CloudflareProvider(
            'test', 'email', 'token', 'account_id', True
        )
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 'c1',
                    'type': 'A',
                    'name': 'a.unit.tests',
                    'content': '1.1.1.1',
                    'proxiable': True,
                    'proxied': True,
                    'comment': 'cdn comment',
                    'tags': ['cdn-tag'],
                    'ttl': 300,
                }
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        cloudflare = next(iter(zone.records)).octodns['cloudflare']
        self.assertEqual('cdn comment', cloudflare['comment'])
        self.assertEqual(['cdn-tag'], cloudflare['tags'])
        self.assertNotIn('values', cloudflare)

    def test_per_value_metadata_mx(self):
        # structured-value type round-trips per-value metadata
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 'm1',
                    'type': 'MX',
                    'name': 'unit.tests',
                    'content': 'mx1.unit.tests',
                    'priority': 10,
                    'comment': 'primary',
                    'ttl': 300,
                },
                {
                    'id': 'm2',
                    'type': 'MX',
                    'name': 'unit.tests',
                    'content': 'mx2.unit.tests',
                    'priority': 20,
                    'comment': 'backup',
                    'ttl': 300,
                },
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        record = next(iter(zone.records))
        by_value = {
            (e['value']['preference'], e['value']['exchange']): e
            for e in record.octodns['cloudflare']['values']
        }
        self.assertEqual(
            'primary', by_value[(10, 'mx1.unit.tests.')]['comment']
        )
        self.assertEqual('backup', by_value[(20, 'mx2.unit.tests.')]['comment'])
        # and it survives the trip back out to Cloudflare contents
        contents = {
            (d['priority'], d['content']): d for d in provider._gen_data(record)
        }
        self.assertEqual(
            'primary', contents[(10, 'mx1.unit.tests.')]['comment']
        )
        self.assertEqual('backup', contents[(20, 'mx2.unit.tests.')]['comment'])

    def test_per_value_metadata_structured_round_trip(self):
        # every structured-value type ross called out (CAA/SRV/LOC/NAPTR) must
        # round-trip per-value metadata: the value-key stored on read has to
        # match the value-key looked up on write even though the value is a
        # multi-field dict rather than a scalar
        provider = CloudflareProvider('test', 'email', 'token')
        cases = {
            'CAA': (
                'ca',
                [
                    {
                        'type': 'CAA',
                        'name': 'ca.unit.tests',
                        'data': {'flags': 0, 'tag': 'issue', 'value': 'le.org'},
                        'ttl': 300,
                        'comment': 'A',
                    },
                    {
                        'type': 'CAA',
                        'name': 'ca.unit.tests',
                        'data': {
                            'flags': 0,
                            'tag': 'issuewild',
                            'value': 'ca2.org',
                        },
                        'ttl': 300,
                        'comment': 'B',
                    },
                ],
            ),
            'SRV': (
                '_sip._tcp',
                [
                    {
                        'type': 'SRV',
                        'name': '_sip._tcp.unit.tests',
                        'data': {
                            'priority': 10,
                            'weight': 20,
                            'port': 5060,
                            'target': 'sip1.unit.tests',
                        },
                        'ttl': 300,
                        'comment': 'A',
                    },
                    {
                        'type': 'SRV',
                        'name': '_sip._tcp.unit.tests',
                        'data': {
                            'priority': 20,
                            'weight': 20,
                            'port': 5061,
                            'target': 'sip2.unit.tests',
                        },
                        'ttl': 300,
                        'comment': 'B',
                    },
                ],
            ),
            'NAPTR': (
                'naptr',
                [
                    {
                        'type': 'NAPTR',
                        'name': 'naptr.unit.tests',
                        'data': {
                            'flags': 'U',
                            'order': 100,
                            'preference': 10,
                            'regex': '!^.*$!sip:a@b.example.com!',
                            'replacement': '.',
                            'service': 'SIP+D2U',
                        },
                        'ttl': 300,
                        'comment': 'A',
                    },
                    {
                        'type': 'NAPTR',
                        'name': 'naptr.unit.tests',
                        'data': {
                            'flags': 'U',
                            'order': 100,
                            'preference': 20,
                            'regex': '!^.*$!sip:c@d.example.com!',
                            'replacement': '.',
                            'service': 'SIP+D2T',
                        },
                        'ttl': 300,
                        'comment': 'B',
                    },
                ],
            ),
        }
        for _type, (name, records) in cases.items():
            zone = Zone('unit.tests.', [])
            record = provider._record_for(zone, name, _type, records, True)
            # differing per-value metadata -> an explicit per-value list
            self.assertIn('values', record.octodns['cloudflare'])
            # every value's comment survives the trip back out to Cloudflare
            comments = sorted(
                d.get('comment') for d in provider._gen_data(record)
            )
            self.assertEqual(
                ['A', 'B'], comments, f'{_type} per-value metadata lost'
            )

    @patch('octodns_cloudflare.BaseProvider._process_desired_zone')
    def test_per_value_metadata_non_canonical_values(self, mock_base):
        # a hand-authored entry value in an equivalent-but-different spelling
        # (mixed-case hostname, uncompressed IPv6) is normalized through the
        # record's value type, so it still matches its record value
        mock_base.side_effect = lambda desired: desired
        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=True
        )
        zone = Zone('unit.tests.', [])

        mx = Record.new(
            zone,
            'mx',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [
                    {'preference': 10, 'exchange': 'mx1.unit.tests.'},
                    {'preference': 20, 'exchange': 'mx2.unit.tests.'},
                ],
                'octodns': {
                    'cloudflare': {
                        'values': [
                            {
                                # mixed-case spelling of mx1.unit.tests.
                                'value': {
                                    'preference': 10,
                                    'exchange': 'MX1.Unit.Tests.',
                                },
                                'comment': 'primary',
                            }
                        ]
                    }
                },
            },
        )
        aaaa = Record.new(
            zone,
            'v6',
            {
                'ttl': 300,
                'type': 'AAAA',
                'values': ['2001:db8::1', '2001:db8::2'],
                'octodns': {
                    'cloudflare': {
                        'values': [
                            {
                                # uncompressed, uppercase spelling
                                'value': '2001:0DB8:0000:0000:0000:0000:0000:0001',
                                'comment': 'uncompressed',
                            }
                        ]
                    }
                },
            },
        )

        # matching works on the write path
        mx_contents = {
            d['priority']: d.get('comment') for d in provider._gen_data(mx)
        }
        self.assertEqual('primary', mx_contents[10])
        self.assertIsNone(mx_contents[20])
        aaaa_contents = {
            d['content']: d.get('comment') for d in provider._gen_data(aaaa)
        }
        self.assertEqual('uncompressed', aaaa_contents['2001:db8::1'])
        self.assertIsNone(aaaa_contents['2001:db8::2'])

        # and strict plan-time validation accepts the equivalent spellings
        desired = zone.copy()
        desired.add_record(mx)
        desired.add_record(aaaa)
        result = provider._process_desired_zone(desired)
        self.assertEqual(2, len(result.records))

    @patch('octodns_cloudflare.BaseProvider._process_desired_zone')
    def test_per_value_metadata_unparseable_value(self, mock_base):
        # an entry value the record's value type can't parse (here an MX
        # missing its exchange) must not crash; it falls back to its raw form,
        # matches nothing, and is reported at plan time
        mock_base.side_effect = lambda desired: desired
        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone,
            'mx',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 10, 'exchange': 'mx1.unit.tests.'}],
                'octodns': {
                    'cloudflare': {
                        'comment': 'record-level',
                        'values': [
                            {'value': {'preference': 10}, 'comment': 'nope'}
                        ],
                    }
                },
            },
            lenient=True,
        )

        # write path degrades to the record-level comment
        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=False
        )
        contents = list(provider._gen_data(record))
        self.assertEqual('record-level', contents[0]['comment'])

        # strict plan-time validation reports it as unmatched
        provider = CloudflareProvider(
            'test', 'email', 'token', strict_supports=True
        )
        desired = zone.copy()
        desired.add_record(record)
        with self.assertRaises(SupportsException) as ctx:
            provider._process_desired_zone(desired)
        self.assertIn('not one of the', str(ctx.exception))

    def test_per_value_metadata_txt(self):
        # TXT (chunked content path) round-trips per-value metadata
        provider = CloudflareProvider('test', 'email', 'token')
        provider.zone_records = Mock(
            return_value=[
                {
                    'id': 't1',
                    'type': 'TXT',
                    'name': 'txt.unit.tests',
                    'content': 'verification=abc',
                    'comment': 'search',
                    'ttl': 300,
                },
                {
                    'id': 't2',
                    'type': 'TXT',
                    'name': 'txt.unit.tests',
                    'content': 'v=spf1 ~all',
                    'comment': 'spf',
                    'ttl': 300,
                },
            ]
        )
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        record = next(iter(zone.records))
        by_value = {
            e['value']: e for e in record.octodns['cloudflare']['values']
        }
        self.assertEqual('search', by_value['verification=abc']['comment'])
        self.assertEqual('spf', by_value['v=spf1 ~all']['comment'])
        # Cloudflare TXT content is quoted; the per-value comment still lines
        # up with the right (chunked) content
        contents = {d['content']: d for d in provider._gen_data(record)}
        self.assertEqual('search', contents['"verification=abc"']['comment'])
        self.assertEqual('spf', contents['"v=spf1 ~all"']['comment'])

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
