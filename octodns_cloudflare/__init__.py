#
#
#

from collections import defaultdict
from io import StringIO
from logging import getLogger
from time import sleep
from urllib.parse import urlsplit

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.idna import IdnaDict
from octodns.provider import ProviderException, SupportsException
from octodns.provider.base import BaseProvider
from octodns.record import Create, Record, Update

try:  # pragma: no cover
    from octodns.record.https import HttpsValue
    from octodns.record.svcb import SvcbValue

    SUPPORTS_SVCB = True
except ImportError:  # pragma: no cover
    SUPPORTS_SVCB = False

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.9'


class CloudflareError(ProviderException):

    def __init__(self, data):
        try:
            message = data['errors'][0]['message']
        except (IndexError, KeyError, TypeError):
            message = 'Cloudflare error'
        super().__init__(message)


class CloudflareAuthenticationError(CloudflareError):

    def __init__(self, data):
        CloudflareError.__init__(self, data)


class CloudflareRateLimitError(CloudflareError):

    def __init__(self, data):
        CloudflareError.__init__(self, data)


class Cloudflare5xxError(CloudflareError):

    def __init__(self, data):
        CloudflareError.__init__(self, data)


_PROXIABLE_RECORD_TYPES = {'A', 'AAAA', 'ALIAS', 'CNAME'}


class CloudflareProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(
        (
            'ALIAS',
            'A',
            'AAAA',
            'CAA',
            'CNAME',
            'DS',
            'LOC',
            'MX',
            'NAPTR',
            'NS',
            'PTR',
            'SSHFP',
            'SRV',
            'SPF',
            'TLSA',
            'TXT',
        )
    )

    # These are only supported if we have a new enough octoDNS core
    if SUPPORTS_SVCB:  # pragma: no cover
        SUPPORTS.add('HTTPS')
        SUPPORTS.add('SVCB')

    TIMEOUT = 15

    def __init__(
        self,
        id,
        email=None,
        token=None,
        account_id=None,
        cdn=False,
        pagerules=True,
        plan_type=None,
        retry_count=4,
        retry_period=300,
        auth_error_retry_count=0,
        zones_per_page=50,
        records_per_page=100,
        min_ttl=120,
        *args,
        **kwargs,
    ):
        self.log = getLogger(f'CloudflareProvider[{id}]')
        self.log.debug(
            '__init__: id=%s, email=%s, token=***, account_id=%s, cdn=%s, plan=%s',
            id,
            email,
            account_id,
            cdn,
            plan_type,
        )
        super().__init__(id, *args, **kwargs)

        sess = Session()
        if email and token:
            sess.headers.update({'X-Auth-Email': email, 'X-Auth-Key': token})
        else:
            # https://api.cloudflare.com/#getting-started-requests
            # https://tools.ietf.org/html/rfc6750#section-2.1
            sess.headers.update({'Authorization': f'Bearer {token}'})
        sess.headers.update(
            {
                'User-Agent': f'octodns/{octodns_version} octodns-cloudflare/{__VERSION__}'
            }
        )
        self.account_id = account_id
        self.cdn = cdn
        self.pagerules = pagerules
        self.plan_type = plan_type
        self.retry_count = retry_count
        self.retry_period = retry_period
        self.auth_error_retry_count = auth_error_retry_count
        self.zones_per_page = zones_per_page
        self.records_per_page = records_per_page
        self.min_ttl = min_ttl
        self._sess = sess

        self._zones = None
        self._zone_records = {}
        if self.pagerules:
            # copy the class static/ever present list of supported types into
            # an instance property so that when we modify it we won't change
            # the shared version
            self.SUPPORTS = set(self.SUPPORTS)
            self.SUPPORTS.add('URLFWD')

    def _try_request(self, *args, **kwargs):
        tries = self.retry_count
        auth_tries = self.auth_error_retry_count
        while True:  # We'll raise to break after our tries expire
            try:
                return self._request(*args, **kwargs)
            except CloudflareRateLimitError:
                if tries <= 1:
                    raise
                tries -= 1
                self.log.warning(
                    'rate limit encountered, pausing '
                    'for %ds and trying again, %d remaining',
                    self.retry_period,
                    tries,
                )
                sleep(self.retry_period)
            except CloudflareAuthenticationError:
                if auth_tries <= 0:
                    raise
                auth_tries -= 1
                self.log.warning(
                    'authentication error encountered, pausing '
                    'for %ds and trying again, %d remaining',
                    self.retry_period,
                    auth_tries,
                )
                sleep(self.retry_period)
            except Cloudflare5xxError:
                if tries <= 0:
                    raise
                tries -= 1
                self.log.warning(
                    'http 502 error encountered, pausing '
                    'for %ds and trying again, %d remaining',
                    self.retry_period,
                    tries,
                )
                sleep(self.retry_period)

    def _request(self, method, path, params=None, data=None):
        self.log.debug('_request: method=%s, path=%s', method, path)

        url = f'https://api.cloudflare.com/client/v4{path}'
        resp = self._sess.request(
            method, url, params=params, json=data, timeout=self.TIMEOUT
        )
        self.log.debug('_request:   status=%d', resp.status_code)
        if resp.status_code == 400:
            self.log.debug('_request:   data=%s', data)
            raise CloudflareError(resp.json())
        if resp.status_code == 403:
            raise CloudflareAuthenticationError(resp.json())
        if resp.status_code == 429:
            raise CloudflareRateLimitError(resp.json())
        if resp.status_code in [502, 503]:
            raise Cloudflare5xxError("http 5xx")
        resp.raise_for_status()
        return resp.json()

    def _change_keyer(self, change):
        _type = change.record._type
        if _type == 'DS' and isinstance(change, Create):
            # when creating records in CF the NS for a node must come before the
            # DS so we need to flip their order. when deleting they'll already
            # be in the required order
            _type = 'ZDS'
        return (change.CLASS_ORDERING, change.record.name, _type)

    @property
    def zones(self):
        if self._zones is None:
            page = 1
            zones = []
            while page:
                params = {'page': page, 'per_page': self.zones_per_page}
                if self.account_id is not None:
                    params['account.id'] = self.account_id
                resp = self._try_request('GET', '/zones', params=params)
                zones += resp['result']
                info = resp['result_info']
                if info['count'] > 0 and info['count'] == info['per_page']:
                    page += 1
                else:
                    page = None

            self._zones = IdnaDict(
                {
                    f'{z["name"]}.': {
                        'id': z['id'],
                        'cloudflare_plan': z.get('plan', {}).get(
                            'legacy_id', None
                        ),
                        'name_servers': z.get('name_servers', []),
                    }
                    for z in zones
                }
            )

        return self._zones

    def _ttl_data(self, ttl):
        return 300 if ttl == 1 else ttl

    def _data_for_cdn(self, name, _type, records):
        self.log.info('CDN rewrite for %s', records[0]['name'])
        _type = "CNAME"
        if name == "":
            _type = "ALIAS"

        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'value': f'{records[0]["name"]}.cdn.cloudflare.net.',
        }

    def _data_for_multiple(self, _type, records):
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': [r['content'] for r in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_SPF = _data_for_multiple

    def _data_for_TXT(self, _type, records):
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': [
                r.get('content', '').replace(';', '\\;') for r in records
            ],
        }

    def _data_for_CAA(self, _type, records):
        values = []
        for r in records:
            data = r['data']
            values.append(data)
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': values,
        }

    def _data_for_CNAME(self, _type, records):
        only = records[0]
        return {
            'ttl': self._ttl_data(only['ttl']),
            'type': _type,
            'value': f'{only["content"]}.' if only['content'] != '.' else '.',
        }

    _data_for_ALIAS = _data_for_CNAME
    _data_for_PTR = _data_for_CNAME

    def _data_for_DS(self, _type, records):
        values = []
        for record in records:
            key_tag, algorithm, digest_type, digest = record['content'].split(
                ' ', 3
            )
            values.append(
                {
                    'algorithm': int(algorithm),
                    'digest': digest,
                    'digest_type': digest_type,
                    'key_tag': int(key_tag),
                }
            )
        return {
            'type': _type,
            'values': values,
            'ttl': self._ttl_data(records[0]['ttl']),
        }

    def _data_for_LOC(self, _type, records):
        values = []
        for record in records:
            r = record['data']
            values.append(
                {
                    'lat_degrees': int(r['lat_degrees']),
                    'lat_minutes': int(r['lat_minutes']),
                    'lat_seconds': float(r['lat_seconds']),
                    'lat_direction': r['lat_direction'],
                    'long_degrees': int(r['long_degrees']),
                    'long_minutes': int(r['long_minutes']),
                    'long_seconds': float(r['long_seconds']),
                    'long_direction': r['long_direction'],
                    'altitude': float(r['altitude']),
                    'size': float(r['size']),
                    'precision_horz': float(r['precision_horz']),
                    'precision_vert': float(r['precision_vert']),
                }
            )
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': values,
        }

    def _data_for_MX(self, _type, records):
        values = []
        for r in records:
            values.append(
                {
                    'preference': r['priority'],
                    'exchange': (
                        f'{r["content"]}.' if r['content'] != '.' else '.'
                    ),
                }
            )
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': values,
        }

    def _data_for_NAPTR(self, _type, records):
        values = []
        for r in records:
            data = r['data']
            values.append(
                {
                    'flags': data['flags'],
                    'order': data['order'],
                    'preference': data['preference'],
                    'regexp': data['regex'],
                    'replacement': data['replacement'],
                    'service': data['service'],
                }
            )
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': values,
        }

    def _data_for_NS(self, _type, records):
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': [f'{r["content"]}.' for r in records],
        }

    def _data_for_SRV(self, _type, records):
        values = []
        for r in records:
            target = (
                f'{r["data"]["target"]}.' if r['data']['target'] != "." else "."
            )
            values.append(
                {
                    'priority': r['data']['priority'],
                    'weight': r['data']['weight'],
                    'port': r['data']['port'],
                    'target': target,
                }
            )
        return {
            'type': _type,
            'ttl': self._ttl_data(records[0]['ttl']),
            'values': values,
        }

    def _data_for_SVCB(self, _type, records):
        values = []
        for r in records:
            # it's cleaner/easier to parse the rdata version than CF's broken up
            # `data` which is really only half parsed
            value = SvcbValue.parse_rdata_text(r['content'])
            values.append(value)
        return {
            'type': _type,
            'ttl': self._ttl_data(records[0]['ttl']),
            'values': values,
        }

    def _data_for_HTTPS(self, _type, records):
        values = []
        for r in records:
            # it's cleaner/easier to parse the rdata version than CF's broken up
            # `data` which is really only half parsed
            value = HttpsValue.parse_rdata_text(r['content'])
            values.append(value)
        return {
            'type': _type,
            'ttl': self._ttl_data(records[0]['ttl']),
            'values': values,
        }

    def _data_for_TLSA(self, _type, records):
        values = []
        for r in records:
            data = r['data']
            values.append(
                {
                    'certificate_usage': data['usage'],
                    'selector': data['selector'],
                    'matching_type': data['matching_type'],
                    'certificate_association_data': data['certificate'],
                }
            )
        return {
            'ttl': self._ttl_data(records[0]['ttl']),
            'type': _type,
            'values': values,
        }

    def _data_for_URLFWD(self, _type, records):
        values = []
        for r in records:
            values.append(
                {
                    'path': r['path'],
                    'target': r['url'],
                    'code': r['status_code'],
                    'masking': 2,
                    'query': 0,
                }
            )
        return {
            'type': _type,
            'ttl': 300,  # ttl does not exist for this type, forcing a setting
            'values': values,
        }

    def _data_for_SSHFP(self, _type, records):
        values = []
        for record in records:
            algorithm, fingerprint_type, fingerprint = record['content'].split(
                ' ', 2
            )
            values.append(
                {
                    'algorithm': int(algorithm),
                    'fingerprint_type': int(fingerprint_type),
                    'fingerprint': fingerprint,
                }
            )
        return {
            'type': _type,
            'values': values,
            'ttl': self._ttl_data(records[0]['ttl']),
        }

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            zone_id = self.zones.get(zone.name, {}).get('id', False)
            if not zone_id:
                return []

            records = []
            path = f'/zones/{zone_id}/dns_records'
            page = 1
            while page:
                resp = self._try_request(
                    'GET',
                    path,
                    params={'page': page, 'per_page': self.records_per_page},
                )
                # populate DNS records, ensure only supported types are considered
                records += [
                    record
                    for record in resp['result']
                    if record['type'] in self.SUPPORTS
                ]
                info = resp['result_info']
                if info['count'] > 0 and info['count'] == info['per_page']:
                    page += 1
                else:
                    page = None
            if self.pagerules:
                path = f'/zones/{zone_id}/pagerules'
                resp = self._try_request(
                    'GET', path, params={'status': 'active'}
                )
                for r in resp['result']:
                    # assumption, base on API guide, will only contain 1 action
                    if r['actions'][0]['id'] == 'forwarding_url':
                        records += [r]

            self._zone_records[zone.name] = records

        return self._zone_records[zone.name]

    def _record_for(self, zone, name, _type, records, lenient):
        # rewrite Cloudflare proxied records
        proxied = records[0].get('proxied', False)
        if self.cdn and proxied:
            data = self._data_for_cdn(name, _type, records)
        else:
            # Cloudflare supports ALIAS semantics with root CNAMEs
            if _type == 'CNAME' and name == '':
                _type = 'ALIAS'

            data_for = getattr(self, f'_data_for_{_type}')
            data = data_for(_type, records)

        record = Record.new(zone, name, data, source=self, lenient=lenient)

        proxied = proxied and _type in _PROXIABLE_RECORD_TYPES
        auto_ttl = records[0]['ttl'] == 1
        if proxied:
            self.log.debug('_record_for: proxied=True, auto-ttl=True')
            record._octodns['cloudflare'] = {'proxied': True, 'auto-ttl': True}
        elif auto_ttl:
            # auto-ttl can still be set on any record type, signaled by a ttl=1,
            # even if proxied is false.
            self.log.debug('_record_for: auto-ttl=True')
            record._octodns['cloudflare'] = {'auto-ttl': True}

        # update record comment
        if records[0].get('comment'):
            try:
                record._octodns['cloudflare']['comment'] = records[0]['comment']
            except KeyError:
                record._octodns['cloudflare'] = {
                    'comment': records[0]['comment']
                }

        # update record tags
        if records[0].get('tags'):
            try:
                record._octodns['cloudflare']['tags'] = records[0]['tags']
            except KeyError:
                record._octodns['cloudflare'] = {'tags': records[0]['tags']}

        return record

    def list_zones(self):
        return sorted(self.zones.keys())

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        exists = False
        before = len(zone.records)
        records = self.zone_records(zone)
        if records:
            exists = True
            values = defaultdict(lambda: defaultdict(list))
            for record in records:
                if 'targets' in record:
                    # We shouldn't get in here when pagerules are disabled as
                    # we won't make the call to fetch the details/them
                    #
                    # assumption, targets will always contain 1 target
                    # API documentation only indicates 'url' as the only target
                    # if record['targets'][0]['target'] == 'url':
                    uri = record['targets'][0]['constraint']['value']
                    uri = '//' + uri if not uri.startswith('http') else uri
                    parsed_uri = urlsplit(uri)
                    name = zone.hostname_from_fqdn(parsed_uri.netloc)
                    path = parsed_uri.path
                    _type = 'URLFWD'
                    # assumption, actions will always contain 1 action
                    _values = record['actions'][0]['value']
                    _values['path'] = path
                    # no ttl set by pagerule, creating one
                    _values['ttl'] = 300
                    values[name][_type].append(_values)
                # the dns_records branch
                # elif 'name' in record:
                else:
                    name = zone.hostname_from_fqdn(record['name'])
                    _type = record['type']
                    values[name][record['type']].append(record)

            for name, types in values.items():
                for _type, records in types.items():
                    record = self._record_for(
                        zone, name, _type, records, lenient
                    )

                    # only one rewrite is needed for names where the proxy is
                    # enabled at multiple records with a different type but
                    # the same name
                    if (
                        self.cdn
                        and records[0]['proxied']
                        and record in zone._records[name]
                    ):
                        self.log.info('CDN rewrite %s already in zone', name)
                        continue

                    zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _include_change(self, change):
        if isinstance(change, Create) and change.new._type == 'SPF':
            msg = f'{self.id}: creating new SPF records not supported, use TXT instead'
            raise SupportsException(msg)

        if isinstance(change, Update):
            new = change.new
            new_is_proxied = self._record_is_proxied(new)
            new_is_just_auto_ttl = self._record_is_just_auto_ttl(new)
            new_is_urlfwd = new._type == 'URLFWD'
            new = new.data

            existing = change.existing
            existing_is_proxied = self._record_is_proxied(existing)
            existing_is_just_auto_ttl = self._record_is_just_auto_ttl(existing)
            existing_is_urlfwd = existing._type == 'URLFWD'
            existing = existing.data

            if (
                (new_is_proxied != existing_is_proxied)
                or (new_is_just_auto_ttl != existing_is_just_auto_ttl)
                or (new_is_urlfwd != existing_is_urlfwd)
            ):
                # changes in special flags, definitely need this change
                return True

            # at this point we know that all the special flags match in new and
            # existing so we can focus on the actual record details, so we can
            # ignore octodns.cloudflare
            new.get('octodns', {}).pop('cloudflare', None)
            existing.get('octodns', {}).pop('cloudflare', None)

            # TTLs are ignored for these, best way to do that is to just copy
            # it over so they'll match
            if new_is_proxied or new_is_just_auto_ttl or new_is_urlfwd:
                new['ttl'] = existing['ttl']

            # Cloudflare has a minimum TTL, we need to clamp the TTL values so
            # that we ignore a desired state (new) where we can't support the
            # TTL
            new['ttl'] = max(self.min_ttl, new['ttl'])
            existing['ttl'] = max(self.min_ttl, existing['ttl'])

            if new == existing:
                return False

        # If this is a record to enable Cloudflare CDN don't update as
        # we don't know the original values.
        if change.record._type in (
            'ALIAS',
            'CNAME',
        ) and change.record.value.endswith('.cdn.cloudflare.net.'):
            return False

        return True

    def _process_desired_zone(self, desired):
        dses = {}
        nses = set()
        for record in desired.records:
            if record._type == 'DS':
                dses[record.name] = record
            elif record._type == 'NS':
                nses.add(record.name)

        for name, record in dses.items():
            if name not in nses:
                msg = f'DS record {record.fqdn} does not have coresponding NS record and Cloudflare requires it'
                fallback = 'omitting the record'
                self.supports_warn_or_except(msg, fallback)
                desired.remove_record(record)

        return desired

    def _contents_for_multiple(self, record):
        for value in record.values:
            yield {'content': value}

    _contents_for_A = _contents_for_multiple
    _contents_for_AAAA = _contents_for_multiple
    _contents_for_NS = _contents_for_multiple
    _contents_for_SPF = _contents_for_multiple

    def _contents_for_CAA(self, record):
        for value in record.values:
            yield {
                'data': {
                    'flags': value.flags,
                    'tag': value.tag,
                    'value': value.value,
                }
            }

    def _contents_for_DS(self, record):
        for value in record.values:
            yield {
                'data': {
                    'key_tag': value.key_tag,
                    'algorithm': value.algorithm,
                    'digest_type': value.digest_type,
                    'digest': value.digest,
                }
            }

    def _contents_for_TXT(self, record):
        for value in record.values:
            yield {'content': value.replace('\\;', ';')}

    def _contents_for_CNAME(self, record):
        yield {'content': record.value}

    _contents_for_PTR = _contents_for_CNAME

    def _contents_for_LOC(self, record):
        for value in record.values:
            yield {
                'data': {
                    'lat_degrees': value.lat_degrees,
                    'lat_minutes': value.lat_minutes,
                    'lat_seconds': value.lat_seconds,
                    'lat_direction': value.lat_direction,
                    'long_degrees': value.long_degrees,
                    'long_minutes': value.long_minutes,
                    'long_seconds': value.long_seconds,
                    'long_direction': value.long_direction,
                    'altitude': value.altitude,
                    'size': value.size,
                    'precision_horz': value.precision_horz,
                    'precision_vert': value.precision_vert,
                }
            }

    def _contents_for_MX(self, record):
        for value in record.values:
            yield {'priority': value.preference, 'content': value.exchange}

    def _contents_for_NAPTR(self, record):
        for value in record.values:
            yield {
                'data': {
                    'flags': value.flags,
                    'order': value.order,
                    'preference': value.preference,
                    'regex': value.regexp,
                    'replacement': value.replacement,
                    'service': value.service,
                }
            }

    def _contents_for_SSHFP(self, record):
        for value in record.values:
            yield {
                'data': {
                    'algorithm': value.algorithm,
                    'type': value.fingerprint_type,
                    'fingerprint': value.fingerprint,
                }
            }

    def _contents_for_SRV(self, record):
        try:
            service, proto, subdomain = record.name.split('.', 2)
            # We have a SRV in a sub-zone
        except ValueError:
            # We have a SRV in the zone
            service, proto = record.name.split('.', 1)
            subdomain = None

        name = record.zone.name
        if subdomain:
            name = subdomain

        for value in record.values:
            target = value.target[:-1] if value.target != "." else "."

            yield {
                'data': {
                    'service': service,
                    'proto': proto,
                    'name': name,
                    'priority': value.priority,
                    'weight': value.weight,
                    'port': value.port,
                    'target': target,
                }
            }

    def _contents_for_SVCB(self, record):
        for value in record.values:
            params = StringIO()
            for k, v in value.svcparams.items():
                params.write(' ')
                params.write(k)
                if v is not None:
                    params.write('="')
                    if isinstance(v, list):
                        params.write(','.join(v))
                    else:
                        params.write(v)
                    params.write('"')
            yield {
                'data': {
                    'priority': value.svcpriority,
                    'target': value.targetname,
                    'value': params.getvalue(),
                }
            }

    _contents_for_HTTPS = _contents_for_SVCB

    def _contents_for_TLSA(self, record):
        for value in record.values:
            yield {
                'data': {
                    'usage': value.certificate_usage,
                    'selector': value.selector,
                    'matching_type': value.matching_type,
                    'certificate': value.certificate_association_data,
                }
            }

    def _contents_for_URLFWD(self, record):
        name = record.fqdn[:-1]
        for value in record.values:
            yield {
                'targets': [
                    {
                        'target': 'url',
                        'constraint': {
                            'operator': 'matches',
                            'value': name + value.path,
                        },
                    }
                ],
                'actions': [
                    {
                        'id': 'forwarding_url',
                        'value': {
                            'url': value.target,
                            'status_code': value.code,
                        },
                    }
                ],
                'status': 'active',
            }

    def _record_is_proxied(self, record):
        return not self.cdn and record._octodns.get('cloudflare', {}).get(
            'proxied', False
        )

    def _record_is_just_auto_ttl(self, record):
        'This tests if it is strictly auto-ttl and not proxied'
        return (
            not self._record_is_proxied(record)
            and not self.cdn
            and record._octodns.get('cloudflare', {}).get('auto-ttl', False)
        )

    def _record_comment(self, record):
        'Returns record comment'
        return record._octodns.get('cloudflare', {}).get('comment', '')

    def _record_tags(self, record):
        'Returns nonduplicate record tags'
        return set(record._octodns.get('cloudflare', {}).get('tags', []))

    def _gen_data(self, record):
        name = record.fqdn[:-1]
        _type = record._type
        proxied = self._record_is_proxied(record)
        if proxied or self._record_is_just_auto_ttl(record):
            # proxied implies auto-ttl, and auto-ttl can be enabled on its own,
            # when either is the case we tell Cloudflare with ttl=1
            ttl = 1
        else:
            ttl = max(self.min_ttl, record.ttl)

        # Cloudflare supports ALIAS semantics with a root CNAME
        if _type == 'ALIAS':
            _type = 'CNAME'

        if _type == 'URLFWD':
            contents_for = getattr(self, f'_contents_for_{_type}')
            for content in contents_for(record):
                yield content
        else:
            contents_for = getattr(self, f'_contents_for_{_type}')
            for content in contents_for(record):
                content.update({'name': name, 'type': _type, 'ttl': ttl})

                if _type in _PROXIABLE_RECORD_TYPES:
                    content.update({'proxied': self._record_is_proxied(record)})

                if self._record_comment(record):
                    content.update({'comment': self._record_comment(record)})

                if self._record_tags(record):
                    content.update({'tags': list(self._record_tags(record))})

                yield content

    def _gen_key(self, data):
        # Note that most CF record data has a `content` field the value of
        # which is a unique/hashable string for the record's. It includes all
        # the "value" bits, but not the secondary stuff like TTL's. E.g.  for
        # an A it'll include the value, for a CAA it'll include the flags, tag,
        # and value, ... We'll take advantage of this to try and match up old &
        # new records cleanly. In general when there are multiple records for a
        # name & type each will have a distinct/consistent `content` that can
        # serve as a unique identifier.
        # BUT... there are exceptions. MX, CAA, LOC and SRV don't have a simple
        # content as things are currently implemented so we need to handle
        # those explicitly and create unique/hashable strings for them.
        # AND... for URLFWD/Redirects additional adventures are created.
        _type = data.get('type', 'URLFWD')
        if _type == 'MX':
            priority = data['priority']
            content = data['content']
            return f'{priority} {content}'
        elif _type == 'CAA':
            data = data['data']
            flags = data['flags']
            tag = data['tag']
            value = data['value']
            return f'{flags} {tag} {value}'
        elif _type == 'SRV':
            data = data['data']
            port = data['port']
            priority = data['priority']
            target = data['target']
            weight = data['weight']
            return f'{port} {priority} {target} {weight}'
        elif _type == 'LOC':
            data = data['data']
            lat_degrees = data['lat_degrees']
            lat_minutes = data['lat_minutes']
            lat_seconds = data['lat_seconds']
            lat_direction = data['lat_direction']
            long_degrees = data['long_degrees']
            long_minutes = data['long_minutes']
            long_seconds = data['long_seconds']
            long_direction = data['long_direction']
            altitude = data['altitude']
            size = data['size']
            precision_horz = data['precision_horz']
            precision_vert = data['precision_vert']
            return (
                f'{lat_degrees} {lat_minutes} {lat_seconds} '
                f'{lat_direction} {long_degrees} {long_minutes} '
                f'{long_seconds} {long_direction} {altitude} {size} '
                f'{precision_horz} {precision_vert}'
            )
        elif _type == 'NAPTR':
            data = data['data']
            flags = data['flags']
            order = data['order']
            preference = data['preference']
            regex = data['regex']
            replacement = data['replacement']
            service = data['service']
            return f'{order} {preference} "{flags}" "{service}" "{regex}" {replacement}'
        elif _type == 'SSHFP':
            data = data['data']
            algorithm = data['algorithm']
            fingerprint_type = data['type']
            fingerprint = data['fingerprint']
            return f'{algorithm} {fingerprint_type} {fingerprint}'
        elif _type in ('HTTPS', 'SVCB'):
            data = data['data']
            priority = data['priority']
            target = data['target']
            value = data['value']
            return f'{priority} {target} {value}'
        elif _type == 'TLSA':
            data = data['data']
            usage = data['usage']
            selector = data['selector']
            matching_type = data['matching_type']
            certificate = data['certificate']
            return f'{usage} {selector} {matching_type} {certificate}'
        elif _type == 'URLFWD':
            uri = data['targets'][0]['constraint']['value']
            uri = '//' + uri if not uri.startswith('http') else uri
            parsed_uri = urlsplit(uri)
            url = data['actions'][0]['value']['url']
            status_code = data['actions'][0]['value']['status_code']
            return (
                f'{parsed_uri.netloc} {parsed_uri.path} {url} '
                + f'{status_code}'
            )

        return data['content']

    def _apply_Create(self, change):
        new = change.new
        zone_id = self.zones[new.zone.name]['id']
        if new._type == 'URLFWD':
            path = f'/zones/{zone_id}/pagerules'
        else:
            path = f'/zones/{zone_id}/dns_records'
        for content in self._gen_data(new):
            self._try_request('POST', path, data=content)

    def _apply_Update(self, change):
        zone = change.new.zone
        zone_id = self.zones[zone.name]['id']
        hostname = zone.hostname_from_fqdn(change.new.fqdn[:-1])
        _type = change.new._type

        existing = {}
        # Find all of the existing CF records for this name & type
        for record in self.zone_records(zone):
            if 'targets' in record:
                uri = record['targets'][0]['constraint']['value']
                uri = '//' + uri if not uri.startswith('http') else uri
                parsed_uri = urlsplit(uri)
                name = zone.hostname_from_fqdn(parsed_uri.netloc)
                path = parsed_uri.path
                # assumption, actions will always contain 1 action
                _values = record['actions'][0]['value']
                _values['path'] = path
                _values['ttl'] = 300
                _values['type'] = 'URLFWD'
                record.update(_values)
            else:
                name = zone.hostname_from_fqdn(record['name'])
            # Use the _record_for so that we include all of standard
            # conversion logic
            r = self._record_for(zone, name, record['type'], [record], True)
            if hostname == r.name and _type == r._type:
                # Round trip the single value through a record to contents
                # flow to get a consistent _gen_data result that matches
                # what went in to new_contents
                data = next(self._gen_data(r))

                # Record the record_id and data for this existing record
                key = self._gen_key(data)
                existing[key] = {'record_id': record['id'], 'data': data}

        # Build up a list of new CF records for this Update
        new = {self._gen_key(d): d for d in self._gen_data(change.new)}

        # OK we now have a picture of the old & new CF records, our next step
        # is to figure out which records need to be deleted
        deletes = {}
        for key, info in existing.items():
            if key not in new:
                deletes[key] = info
        # Now we need to figure out which records will need to be created
        creates = {}
        # And which will be updated
        updates = {}
        for key, data in new.items():
            if key in existing:
                # To update we need to combine the new data and existing's
                # record_id. old_data is just for debugging/logging purposes
                old_info = existing[key]
                updates[key] = {
                    'record_id': old_info['record_id'],
                    'data': data,
                    'old_data': old_info['data'],
                }
            else:
                creates[key] = data

        # To do this as safely as possible we'll add new things first, update
        # existing things, and then remove old things. This should (try) and
        # ensure that we have as many value CF records in their system as
        # possible at any given time. Ideally we'd have a "batch" API that
        # would allow create, delete, and upsert style stuff so operations
        # could be done atomically, but that's not available so we made the
        # best of it...

        # However, there are record types like CNAME that can only have a
        # single value. B/c of that our create and then delete approach isn't
        # actually viable. To address this we'll convert as many creates &
        # deletes as we can to updates. This will have a minor upside of
        # resulting in fewer ops and in the case of things like CNAME where
        # there's a single create and delete result in a single update instead.
        create_keys = sorted(creates.keys())
        delete_keys = sorted(deletes.keys())
        for i in range(0, min(len(create_keys), len(delete_keys))):
            create_key = create_keys[i]
            create_data = creates.pop(create_key)
            delete_info = deletes.pop(delete_keys[i])
            updates[create_key] = {
                'record_id': delete_info['record_id'],
                'data': create_data,
                'old_data': delete_info['data'],
            }

        # The sorts ensure a consistent order of operations, they're not
        # otherwise required, just makes things deterministic

        # Creates
        if _type == 'URLFWD':
            path = f'/zones/{zone_id}/pagerules'
        else:
            path = f'/zones/{zone_id}/dns_records'
        for _, data in sorted(creates.items()):
            self.log.debug('_apply_Update: creating %s', data)
            self._try_request('POST', path, data=data)

        # Updates
        for _, info in sorted(updates.items()):
            record_id = info['record_id']
            data = info['data']
            old_data = info['old_data']
            if _type == 'URLFWD':
                path = f'/zones/{zone_id}/pagerules/{record_id}'
            else:
                path = f'/zones/{zone_id}/dns_records/{record_id}'
            self.log.debug(
                '_apply_Update: updating %s, %s -> %s',
                record_id,
                data,
                old_data,
            )
            self._try_request('PUT', path, data=data)

        # Deletes
        for _, info in sorted(deletes.items()):
            record_id = info['record_id']
            old_data = info['data']
            if _type == 'URLFWD':
                path = f'/zones/{zone_id}/pagerules/{record_id}'
            else:
                path = f'/zones/{zone_id}/dns_records/{record_id}'
            self.log.debug(
                '_apply_Update: removing %s, %s', record_id, old_data
            )
            self._try_request('DELETE', path)

    def _apply_Delete(self, change):
        existing = change.existing
        existing_name = existing.fqdn[:-1]
        # Make sure to map ALIAS to CNAME when looking for the target to delete
        existing_type = 'CNAME' if existing._type == 'ALIAS' else existing._type
        zone_id = self.zones[existing.zone.name]['id']
        for record in self.zone_records(existing.zone):
            if 'targets' in record and self.pagerules:
                uri = record['targets'][0]['constraint']['value']
                uri = '//' + uri if not uri.startswith('http') else uri
                parsed_uri = urlsplit(uri)
                record_name = parsed_uri.netloc
                record_type = 'URLFWD'
                if (
                    existing_name == record_name
                    and existing_type == record_type
                ):
                    path = f'/zones/{zone_id}/pagerules/{record["id"]}'
                    self._try_request('DELETE', path)
            else:
                if (
                    existing_name == record['name']
                    and existing_type == record['type']
                ):
                    record_zone_id = record.get('zone_id')
                    if record_zone_id is None:
                        self.log.warning(
                            '_apply_Delete: record "%s", %s is missing "zone_id", falling back to lookup',
                            record['name'],
                            record['type'],
                        )
                        record_zone_id = zone_id
                    path = (
                        f'/zones/{record_zone_id}/dns_records/'
                        f'{record["id"]}'
                    )
                    self._try_request('DELETE', path)

    def _available_plans(self, zone_name):
        zone_id = self.zones.get(zone_name, {}).get('id', None)
        if not zone_id:
            msg = f'{self.id}: zone {zone_name} not found'
            raise SupportsException(msg)
        path = f'/zones/{zone_id}/available_plans'
        resp = self._try_request('GET', path)
        result = resp['result']
        if not isinstance(result, list):
            msg = f'{self.id}: unable to determine supported plans, do you have an Enterprise account?'
            raise SupportsException(msg)
        return {
            plan['legacy_id']: plan['id']
            for plan in result
            if plan['legacy_id'] is not None
        }

    def _resolve_plan_legacy_id(self, zone_name, legacy_id):
        # Get the plan id for the given legacy_id, Cloudflare only supports setting the plan by id
        plan_id = self._available_plans(zone_name).get(legacy_id, None)
        if not plan_id:
            msg = f'{self.id}: {legacy_id} is not supported for {zone_name}'
            raise SupportsException(msg)
        return plan_id

    def _update_plan(self, zone_name, legacy_id):
        plan_id = self._resolve_plan_legacy_id(zone_name, legacy_id)
        zone_id = self.zones[zone_name]['id']
        data = {'plan': {'id': plan_id}}
        resp = self._try_request('PATCH', f'/zones/{zone_id}', data=data)
        # Update the cached plan information
        self.zones[zone_name]['cloudflare_plan'] = resp['result']['plan'][
            'legacy_id'
        ]

    def _plan_meta(self, existing, desired, changes):
        desired_plan = self.plan_type
        if desired_plan is None:
            # No plan type configured leave things unmanaged
            return
        zone_name = desired.name
        current_plan = self.zones.get(zone_name, {}).get(
            'cloudflare_plan', None
        )
        if current_plan == desired_plan:
            return
        return {
            'cloudflare_plan': {
                'current': current_plan,
                'desired': desired_plan,
            }
        }

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        zone_name = desired.name

        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', zone_name, len(changes)
        )

        if zone_name not in self.zones:
            self.log.debug('_apply:   no matching zone, creating')
            data = {'name': zone_name[:-1], 'jump_start': False}
            if self.account_id is not None:
                data['account'] = {'id': self.account_id}
            resp = self._try_request('POST', '/zones', data=data)
            zone = resp['result']
            self.zones[zone_name] = {
                'id': zone['id'],
                'cloudflare_plan': zone.get('plan', {}).get('legacy_id', None),
                'name_servers': zone.get('name_servers', []),
            }
            self._zone_records[zone_name] = {}

        # Handle plan changes if needed
        if self.plan_type is not None:
            if hasattr(plan, 'meta'):
                meta = plan.meta
                if meta:
                    desired_plan = meta.get('cloudflare_plan', {}).get(
                        'desired', None
                    )
                    if desired_plan:
                        self._update_plan(zone_name, desired_plan)
            else:
                # Older versions of octodns don't have meta support.
                self.log.warning(
                    'plan_type is set but meta is not supported by octodns %s, plan changes will not be applied',
                    octodns_version,
                )

        self.log.info(
            'zone %s (id %s) name servers: %s',
            zone_name,
            self.zones[zone_name]['id'],
            self.zones[zone_name]['name_servers'],
        )

        # Force the operation order to be Delete() -> Create() -> Update()
        # This will help avoid problems in updating a CNAME record into an
        # A record and vice-versa
        changes.sort(key=self._change_keyer)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # clear the cache
        self._zone_records.pop(zone_name, None)

    def _extra_changes(self, existing, desired, changes):
        extra_changes = []

        existing_records = {r: r for r in existing.records}
        changed_records = {c.record for c in changes}

        for desired_record in desired.records:
            existing_record = existing_records.get(desired_record, None)
            if not existing_record:  # Will be created
                continue
            elif desired_record in changed_records:  # Already being updated
                continue

            if (
                self._record_is_proxied(existing_record)
                != self._record_is_proxied(desired_record)
            ) or (
                self._record_is_just_auto_ttl(existing_record)
                != self._record_is_just_auto_ttl(desired_record)
            ):
                extra_changes.append(Update(existing_record, desired_record))

            if self._record_comment(existing_record) != self._record_comment(
                desired_record
            ):
                extra_changes.append(Update(existing_record, desired_record))

            if self._record_tags(existing_record) != self._record_tags(
                desired_record
            ):
                extra_changes.append(Update(existing_record, desired_record))

        return extra_changes
