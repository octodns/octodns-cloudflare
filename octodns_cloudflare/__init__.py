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
__version__ = __VERSION__ = '1.2.0'


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
        regional_services=False,
        retry_count=4,
        retry_period=300,
        auth_error_retry_count=0,
        zones_per_page=50,
        records_per_page=100,
        min_ttl=120,
        timeout=TIMEOUT,
        api_url="https://api.cloudflare.com/client/v4",
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
        self.regional_services = regional_services
        self.retry_count = retry_count
        self.retry_period = retry_period
        self.auth_error_retry_count = auth_error_retry_count
        self.zones_per_page = zones_per_page
        self.records_per_page = records_per_page
        self.min_ttl = min_ttl
        self.timeout = timeout
        self._sess = sess
        self.api_url = api_url.rstrip('/')

        self._zones = None
        self._zone_records = {}
        self._zone_regional_hostnames = {}
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

        url = f'{self.api_url}{path}'
        resp = self._sess.request(
            method, url, params=params, json=data, timeout=self.timeout
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

    def _paginated_get(self, path, params=None, per_page=None):
        '''
        Yield results from a paginated Cloudflare GET endpoint. ``page``
        and ``per_page`` in ``params`` are overwritten on each request;
        ``per_page`` is taken from the argument (default
        ``self.zones_per_page``).
        '''
        page = 1
        params = dict(params or {})
        if per_page is None:
            per_page = self.zones_per_page
        while page:
            params['page'] = page
            params['per_page'] = per_page
            resp = self._try_request('GET', path, params=params)
            yield from resp['result']
            info = resp['result_info']
            if info['count'] > 0 and info['count'] == info['per_page']:
                page += 1
            else:
                page = None

    @property
    def zones(self):
        if self._zones is None:
            params = {}
            if self.account_id is not None:
                params['account.id'] = self.account_id
            zones = list(self._paginated_get('/zones', params=params))

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

            # populate DNS records, ensure only supported types are considered
            records = [
                r
                for r in self._paginated_get(
                    f'/zones/{zone_id}/dns_records',
                    per_page=self.records_per_page,
                )
                if r['type'] in self.SUPPORTS
            ]
            if self.pagerules:
                path = f'/zones/{zone_id}/pagerules'
                resp = self._try_request(
                    'GET', path, params={'status': 'active'}
                )
                for r in resp['result']:
                    # assumption, base on API guide, will only contain 1 action
                    if r['actions'][0]['id'] == 'forwarding_url':
                        records += [r]

            # Cloudflare Regional Services (Data Localization) lives on a
            # separate, hostname-keyed API surface — not on the dns_record
            # object — so capture the zone's hostname -> region_key mapping
            # here for _record_for to merge in.
            self._zone_regional_hostnames[zone.name] = self._regional_hostnames(
                zone_id, records
            )

            self._zone_records[zone.name] = records

        return self._zone_records[zone.name]

    def _regional_hostnames(self, zone_id, records):
        '''
        Return a ``{hostname: region_key}`` mapping for the zone's Cloudflare
        Regional Services (Data Localization) configuration.

        Regional hostnames are keyed strictly by FQDN — exactly one entry per
        hostname, shared across all record types on that name — and are managed
        via ``/zones/{zone_id}/addressing/regional_hostnames`` rather than the
        dns_records object.

        Regional Services is an Enterprise add-on, and this endpoint can fail
        with an undocumented status for non-entitled accounts, so the whole
        feature is opt-in via the ``regional_services`` provider flag: the
        request is never issued unless it's enabled. It's additionally skipped
        for zones with no proxiable records, since regions only apply to those.

        Note: this endpoint is not paginated. Cloudflare's own SDK models it as
        a single page (``cloudflare-go`` returns ``SinglePage`` whose
        ``GetNextPage`` is documented as never returning a next page), it
        accepts no ``page``/``per_page`` params, returns a bare ``result`` list
        with no ``result_info`` envelope, and returns ``null`` for zones with
        no regional hostnames. A single request therefore suffices, and
        ``_paginated_get`` (which expects ``result_info``) would in fact raise.
        '''
        if not self.regional_services:
            return {}
        if not any(r.get('type') in _PROXIABLE_RECORD_TYPES for r in records):
            return {}
        resp = self._try_request(
            'GET', f'/zones/{zone_id}/addressing/regional_hostnames'
        )
        result = resp.get('result')
        if not isinstance(result, list):
            # zones with no regional hostnames return result=null
            return {}
        return {rh['hostname']: rh['region_key'] for rh in result}

    def _record_for(self, zone, name, _type, records, lenient):
        # rewrite Cloudflare proxied records
        proxied = records[0].get('proxied', False)
        if self.cdn and proxied:
            data = self._data_for_cdn(name, _type, records)
            # CDN rewrites collapse to a single synthetic CNAME, so there's no
            # per-value metadata to read back; flagged with data_for=None below.
            data_for = None
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
            record.octodns['cloudflare'] = {'proxied': True, 'auto-ttl': True}
        elif auto_ttl:
            # auto-ttl can still be set on any record type, signaled by a ttl=1,
            # even if proxied is false.
            self.log.debug('_record_for: auto-ttl=True')
            record.octodns['cloudflare'] = {'auto-ttl': True}

        # update record comment & tags. Cloudflare keeps these on each
        # individual DNS object (one per value); when every value shares the
        # same metadata we use the record-level octodns.cloudflare shorthand,
        # when they differ we emit a per-value list keyed by value (see
        # _populate_value_metadata). CDN rewrites keep the simple form.
        if data_for is None:
            cloudflare = record.octodns.setdefault('cloudflare', {})
            if records[0].get('comment'):
                cloudflare['comment'] = records[0]['comment']
            if records[0].get('tags'):
                cloudflare['tags'] = records[0]['tags']
        else:
            self._populate_value_metadata(record, _type, records, data_for)

        # update record region (Cloudflare Regional Services / Data
        # Localization). Region is keyed by hostname on a separate API, so it's
        # merged in here from the per-zone mapping captured in zone_records.
        # Reads instance state only — never triggers a fetch — so callers that
        # stub zone_records (and thus never populate the mapping) see no region.
        # The mapping is hostname-keyed and a region applies to every record
        # type at that name, but only attach it to proxiable record types: a
        # co-located TXT/MX would otherwise pick up a region it can't carry and
        # generate a phantom Update on every sync.
        region = self._zone_regional_hostnames.get(zone.name, {}).get(
            records[0].get('name')
        )
        if region and _type in _PROXIABLE_RECORD_TYPES:
            try:
                record.octodns['cloudflare']['region'] = region
            except KeyError:
                record.octodns['cloudflare'] = {'region': region}

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

        if self.regional_services:
            self._validate_regions(desired)

        self._validate_value_metadata(desired)

        return super()._process_desired_zone(desired)

    def _validate_value_metadata(self, desired):
        '''Per-value comment/tags (octodns.cloudflare.values) must reference
        values that actually exist on the record. Catch mismatches at plan
        time, where supports_warn_or_except can surface them, rather than
        letting an entry silently no-op during apply.'''
        for record in desired.records:
            entries = record.octodns.get('cloudflare', {}).get('values')
            if entries is None:
                continue
            if not isinstance(entries, list):
                msg = (
                    f'{record.fqdn} {record._type}: octodns.cloudflare.values '
                    f'must be a list of per-value entries'
                )
                self.supports_warn_or_except(
                    msg, 'ignoring octodns.cloudflare.values'
                )
                continue
            actual = {
                self._meta_value_key(getattr(value, 'data', value))
                for value in self._values_in_content_order(record)
            }
            for entry in entries:
                if not isinstance(entry, dict) or 'value' not in entry:
                    msg = (
                        f'{record.fqdn} {record._type}: each '
                        f'octodns.cloudflare.values entry must be a mapping '
                        f'with a \'value\' key; got {entry!r}'
                    )
                    self.supports_warn_or_except(
                        msg, 'ignoring the malformed entry'
                    )
                    continue
                if self._meta_value_key(entry['value']) not in actual:
                    msg = (
                        f'{record.fqdn} {record._type}: octodns.cloudflare '
                        f'per-value metadata references value '
                        f'{entry["value"]!r} which is not one of the '
                        f'record\'s values'
                    )
                    self.supports_warn_or_except(
                        msg, 'ignoring the unmatched per-value metadata entry'
                    )

    def _validate_regions(self, desired):
        # Validate Cloudflare Regional Services (region) constraints. Region is
        # keyed per-hostname on a separate API and only applies to proxied,
        # proxiable records, so flag any desired state Cloudflare can't honor.
        proxiable_regions = defaultdict(set)
        for record in desired.records:
            region = self._record_region(record)
            if record._type in _PROXIABLE_RECORD_TYPES:
                proxiable_regions[record.name].add(region)
                if region is not None and not self._record_is_proxied(record):
                    msg = f'region is set on non-proxied record {record.fqdn}'
                    fallback = 'applying region anyway; it has no effect until the record is proxied'
                    self.supports_warn_or_except(msg, fallback)
            elif region is not None:
                types = ', '.join(sorted(_PROXIABLE_RECORD_TYPES))
                msg = f'region is set on {record._type} record {record.fqdn}; Cloudflare Regional Services only applies to {types} records'
                fallback = 'ignoring region'
                self.supports_warn_or_except(msg, fallback)

        for name, regions in proxiable_regions.items():
            if len(regions) > 1:
                shown = sorted(r if r is not None else 'none' for r in regions)
                fqdn = f'{name}.{desired.name}' if name else desired.name
                msg = f'conflicting regions {shown} configured for records named {fqdn}; Cloudflare applies a single region per hostname'
                fallback = 'the last record applied determines the region'
                self.supports_warn_or_except(msg, fallback)

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
        for chunked in record.chunked_values:
            yield {'content': chunked.replace('\\;', ';')}

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
        return not self.cdn and record.octodns.get('cloudflare', {}).get(
            'proxied', False
        )

    def _record_is_just_auto_ttl(self, record):
        'This tests if it is strictly auto-ttl and not proxied'
        return (
            not self._record_is_proxied(record)
            and not self.cdn
            and record.octodns.get('cloudflare', {}).get('auto-ttl', False)
        )

    def _values_in_content_order(self, record):
        '''The record's value objects, parallel to _contents_for_<type>()
        output. Single-value (ValueMixin) types expose .value; multi-value
        (ValuesMixin) types expose .values.'''
        values = getattr(record, 'values', None)
        if values is None:
            return [record.value]
        return values

    def _meta_value_key(self, value):
        '''A hashable, comparison-stable key for a value in its native
        (octoDNS data) form. Normalizes str subclasses (e.g. Ipv4Value) to
        plain str and dict/list values (e.g. MX) to nested tuples so that a
        value read from Cloudflare and the same value authored in YAML compare
        equal.'''
        if isinstance(value, dict):
            return tuple(
                sorted((k, self._meta_value_key(v)) for k, v in value.items())
            )
        if isinstance(value, (list, tuple)):
            return tuple(self._meta_value_key(v) for v in value)
        if isinstance(value, str):
            return str(value)
        return value

    @staticmethod
    def _norm_meta(meta):
        '''Order-insensitive form of a (comment, tags) pair for comparison —
        octoDNS treats tags as a set, so [a, b] and [b, a] are equal.'''
        if meta is None:
            return None
        comment, tags = meta
        return (comment, frozenset(tags))

    def _value_metadata(self, record):
        '''Per-value metadata entries (octodns.cloudflare.values) keyed by
        value. Empty when the record uses the record-level shorthand.
        Tolerant of malformed config (which _validate_value_metadata reports
        at plan time) so a lenient run degrades rather than crashing.'''
        entries = record.octodns.get('cloudflare', {}).get('values')
        if not isinstance(entries, list):
            return {}
        return {
            self._meta_value_key(entry.get('value')): entry
            for entry in entries
            if isinstance(entry, dict) and 'value' in entry
        }

    def _populate_value_metadata(self, record, _type, records, data_for):
        '''Read comment/tags off each Cloudflare object and attach them to the
        octoDNS record.

        Cloudflare stores comment/tags on each individual DNS object (one per
        value). When every value carries identical metadata we keep the
        record-level octodns.cloudflare.comment/tags shorthand (backwards
        compatible); when they differ we emit an explicit per-value list keyed
        by value. Two objects sharing a value but differing in metadata can't
        be represented per-value — we keep the first and warn.'''
        # value-key -> (native value, meta) in first-seen order; meta is a
        # (comment, tags-tuple) preserving Cloudflare's tag order, or None when
        # the object has neither. _norm_meta gives an order-insensitive form
        # for comparisons (tags are a set as far as octoDNS is concerned).
        metadata = {}
        order = []
        for r in records:
            comment = r.get('comment') or ''
            tags = tuple(r.get('tags') or [])
            meta = (comment, tags) if (comment or tags) else None
            single = data_for(_type, [r])
            native = (
                single['values'][0]
                if 'values' in single
                else single.get('value')
            )
            key = self._meta_value_key(native)
            if key in metadata:
                if self._norm_meta(metadata[key][1]) != self._norm_meta(meta):
                    self.log.warning(
                        '%s %s: Cloudflare has multiple objects for value %r '
                        'with differing comment/tags; octoDNS cannot represent '
                        'per-object metadata for duplicate values — keeping '
                        'the first',
                        record.fqdn,
                        _type,
                        native,
                    )
                continue
            metadata[key] = (native, meta)
            order.append(key)

        metas = [metadata[key] for key in order]
        if all(meta is None for _native, meta in metas):
            return

        cloudflare = record.octodns.setdefault('cloudflare', {})
        distinct = {self._norm_meta(meta) for _native, meta in metas}
        if len(distinct) == 1:
            # every value shares the same metadata -> record-level shorthand
            comment, tags = metas[0][1]
            if comment:
                cloudflare['comment'] = comment
            if tags:
                cloudflare['tags'] = list(tags)
            return

        # values differ -> explicit per-value list, sorted for determinism
        values_meta = []
        for native, meta in sorted(
            metas, key=lambda m: self._meta_value_key(m[0])
        ):
            if meta is None:
                continue
            comment, tags = meta
            entry = {'value': native}
            if comment:
                entry['comment'] = comment
            if tags:
                entry['tags'] = list(tags)
            values_meta.append(entry)
        cloudflare['values'] = values_meta

    def _record_comment(self, record, value):
        '''Returns the comment for a value: its per-value override if set,
        otherwise the record-level comment.'''
        entry = self._value_metadata(record).get(
            self._meta_value_key(getattr(value, 'data', value))
        )
        if entry is not None and 'comment' in entry:
            return entry['comment']
        return record.octodns.get('cloudflare', {}).get('comment', '')

    def _record_tags(self, record, value):
        '''Returns the nonduplicate tags for a value: its per-value override if
        set, otherwise the record-level tags.'''
        entry = self._value_metadata(record).get(
            self._meta_value_key(getattr(value, 'data', value))
        )
        if entry is not None and 'tags' in entry:
            return set(entry['tags'])
        return set(record.octodns.get('cloudflare', {}).get('tags', []))

    def _metadata_signature(self, record):
        '''Per-value (comment, tags) signature, used to detect metadata-only
        changes that wouldn't otherwise alter the record's values.'''
        signature = {}
        for value in self._values_in_content_order(record):
            key = self._meta_value_key(getattr(value, 'data', value))
            signature[key] = (
                self._record_comment(record, value),
                tuple(sorted(self._record_tags(record, value))),
            )
        return signature

    def _record_region(self, record):
        'Returns the Cloudflare Regional Services region_key, or None'
        return record.octodns.get('cloudflare', {}).get('region', None)

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
            # _contents_for_<type>() yields one content per value in
            # record.values order (single-value types yield one for
            # record.value), so zipping lines each content up with its value
            # for per-value comment/tags resolution. The contents are
            # materialized (rather than zipped lazily) so the generator is
            # fully drained even though zip stops on the values list.
            values = self._values_in_content_order(record)
            for value, content in zip(values, list(contents_for(record))):
                content.update({'name': name, 'type': _type, 'ttl': ttl})

                if _type in _PROXIABLE_RECORD_TYPES:
                    content.update({'proxied': self._record_is_proxied(record)})

                comment = self._record_comment(record, value)
                if comment:
                    content.update({'comment': comment})

                tags = self._record_tags(record, value)
                if tags:
                    content.update({'tags': list(tags)})

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
        elif _type == 'DS' and 'content' not in data:
            data = data['data']
            key_tag = data['key_tag']
            algorithm = data['algorithm']
            digest_type = data['digest_type']
            digest = data['digest']
            return f'{key_tag} {algorithm} {digest_type} {digest}'

        return data['content']

    def _reconcile_regions(self, plan):
        '''
        Reconcile Cloudflare Regional Services (region) for the whole zone in a
        single pass at the end of apply.

        Region is a per-hostname property on a separate, hostname-keyed API
        (``/zones/{id}/addressing/regional_hostnames``), not a per-record one,
        so it can't be reconciled safely record-by-record — deleting one record
        of a shared hostname must not strip a region another record still
        wants. This computes the desired region for every proxiable hostname in
        ``plan.desired`` and diffs it against the zone's current regional
        hostnames (captured during populate), issuing the minimal POST (add) /
        PATCH (change region_key) / DELETE (remove) set. Removals are limited to
        hostnames octoDNS manages (present in existing or desired) so
        unmanaged/orphan regional hostnames in the zone are left untouched.
        '''
        if not self.regional_services:
            return
        zone = plan.desired
        zone_id = self.zones[zone.name]['id']

        # desired region per hostname — one entry per FQDN, contributed only by
        # proxiable, region-bearing records. Sorted so the outcome is
        # deterministic if a hostname has conflicting regions across record
        # types (a misconfig _validate_regions already flags): last one wins,
        # but stably, so apply doesn't flap between syncs.
        desired = {}
        for record in sorted(zone.records, key=lambda r: (r.name, r._type)):
            if record._type not in _PROXIABLE_RECORD_TYPES:
                continue
            region = self._record_region(record)
            if region is not None:
                desired[record.fqdn[:-1]] = region

        # hostnames octoDNS manages, so we never delete orphan/unmanaged
        # regional hostnames that exist in the zone but aren't in our config
        managed = set(desired)
        for source in (plan.existing, zone):
            if source is None:
                continue
            for record in source.records:
                if record._type in _PROXIABLE_RECORD_TYPES:
                    managed.add(record.fqdn[:-1])

        current = self._zone_regional_hostnames.get(zone.name, {})
        base = f'/zones/{zone_id}/addressing/regional_hostnames'

        # additions and region_key changes
        for hostname, region in sorted(desired.items()):
            if current.get(hostname) == region:
                continue
            if hostname in current:
                self._try_request(
                    'PATCH', f'{base}/{hostname}', data={'region_key': region}
                )
            else:
                self._try_request(
                    'POST',
                    base,
                    data={'hostname': hostname, 'region_key': region},
                )

        # removals — managed hostnames that no longer want a region
        for hostname in sorted(current):
            if hostname in managed and hostname not in desired:
                self._try_request('DELETE', f'{base}/{hostname}')

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

    def _ensure_zone(self, plan):
        zone_name = plan.desired.name
        if zone_name in self.zones:
            return
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

    def _apply_plan_type(self, plan):
        if self.plan_type is None:
            return
        if not hasattr(plan, 'meta'):
            # Older versions of octodns don't have meta support.
            self.log.warning(
                'plan_type is set but meta is not supported by octodns %s, plan changes will not be applied',
                octodns_version,
            )
            return
        meta = plan.meta
        if not meta:
            return
        desired_plan = meta.get('cloudflare_plan', {}).get('desired', None)
        if desired_plan:
            self._update_plan(plan.desired.name, desired_plan)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        zone_name = desired.name

        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', zone_name, len(changes)
        )

        self._ensure_zone(plan)
        self._apply_plan_type(plan)

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

        # Region is a per-hostname property on a separate API; reconcile it for
        # the whole zone once, after the per-record changes are applied.
        self._reconcile_regions(plan)

        # clear the cache
        self._zone_records.pop(zone_name, None)
        self._zone_regional_hostnames.pop(zone_name, None)

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

            # Metadata-only changes (comment/tags differing on a value that
            # still exists on both sides). Values present on only one side are
            # value changes, which core's diff already handles — comparing the
            # full signature there would re-introduce changes _include_change
            # intentionally filtered (e.g. unmanageable CDN records).
            existing_sig = self._metadata_signature(existing_record)
            desired_sig = self._metadata_signature(desired_record)
            if any(
                existing_sig[key] != desired_sig[key]
                for key in existing_sig.keys() & desired_sig.keys()
            ):
                extra_changes.append(Update(existing_record, desired_record))

            if self.regional_services and (
                self._record_region(existing_record)
                != self._record_region(desired_record)
            ):
                extra_changes.append(Update(existing_record, desired_record))

        return extra_changes


class CloudflareInternalProviderException(ProviderException):
    pass


class CloudflareInternalProvider(CloudflareProvider):
    '''
    Provider for Cloudflare Internal DNS zones (type=internal).

    Internal zones are account-scoped, grouped into DNS views, and queried
    via Cloudflare Gateway. This provider manages records inside
    pre-existing internal zones; cdn, pagerules, and plan_type do not
    apply and are rejected at init.

    Zone enumeration unions `GET /zones?account.id=...` (filtered to
    type==internal) with a walk of the account's DNS views, so zones
    reachable via either path are picked up. Setting view_id narrows
    enumeration to a single view, needed when two internal zones in the
    account share a name across views.
    '''

    # Fresh copy so runtime mutation of CloudflareProvider.SUPPORTS (which
    # the parent test suite does via `provider.SUPPORTS.add(...)`) can't
    # leak URLFWD into this subclass.
    SUPPORTS = set(CloudflareProvider.SUPPORTS)

    _FORBIDDEN_PARAMS = ('cdn', 'pagerules', 'plan_type', 'regional_services')

    def __init__(self, id, *args, account_id=None, view_id=None, **kwargs):
        if account_id is None:
            raise CloudflareInternalProviderException(
                f'{id}: account_id is required for internal DNS zones '
                '(views are account-scoped)'
            )
        for forbidden in self._FORBIDDEN_PARAMS:
            if forbidden in kwargs:
                raise CloudflareInternalProviderException(
                    f'{id}: {forbidden!r} is not supported — Cloudflare '
                    'internal zones have no proxy, pagerules, plan, or '
                    'regional services'
                )
        # Parent defaults pagerules=True, which would re-add URLFWD to SUPPORTS.
        # regional_services is forced off: internal zones have no edge, so the
        # addressing API never applies. That single switch gates every region
        # code path inherited from CloudflareProvider (fetch, validate,
        # reconcile), so no per-method overrides are needed here.
        super().__init__(
            id,
            *args,
            account_id=account_id,
            cdn=False,
            pagerules=False,
            plan_type=None,
            regional_services=False,
            **kwargs,
        )
        self.view_id = view_id

    def _internal_zone_ids_from_views(self):
        base = f'/accounts/{self.account_id}/dns_settings/views'
        if self.view_id is not None:
            # Narrow to the single configured view; listing all views would re-widen.
            resp = self._try_request('GET', f'{base}/{self.view_id}')
            return set(resp['result'].get('zones') or [])
        # Union zones across all views; a zone may appear in multiple views.
        zone_ids = set()
        for view in self._paginated_get(base):
            zone_ids.update(view.get('zones') or [])
        return zone_ids

    @property
    def zones(self):
        if self._zones is not None:
            return self._zones

        zones_by_id = {}
        # view_id narrows enumeration: listing /zones would re-widen to
        # every internal zone in the account, defeating the narrowing.
        if self.view_id is None:
            for z in self._paginated_get(
                '/zones', params={'account.id': self.account_id}
            ):
                if z.get('type') == 'internal':
                    zones_by_id[z['id']] = z

        for zone_id in self._internal_zone_ids_from_views():
            if zone_id in zones_by_id:
                continue
            z = self._try_request('GET', f'/zones/{zone_id}')['result']
            if z.get('type') == 'internal':
                zones_by_id[z['id']] = z

        name_to_ids = defaultdict(list)
        for zone_id, z in zones_by_id.items():
            name_to_ids[z['name']].append(zone_id)
        duplicates = {
            n: sorted(ids) for n, ids in name_to_ids.items() if len(ids) > 1
        }
        if duplicates:
            details = '; '.join(
                f'{n!r} (zone_ids={ids})'
                for n, ids in sorted(duplicates.items())
            )
            raise CloudflareInternalProviderException(
                f'{self.id}: multiple internal zones with the same name '
                f'found: {details}. Set `view_id` on the provider to '
                'narrow enumeration to a single view.'
            )

        self._zones = IdnaDict(
            {
                f'{z["name"]}.': {
                    'id': z['id'],
                    'cloudflare_plan': None,
                    'name_servers': z.get('name_servers') or [],
                }
                for z in zones_by_id.values()
            }
        )
        return self._zones

    def _process_desired_zone(self, desired):
        # Internal zones have no nameservers (Cloudflare Gateway resolves
        # them directly), so root NS records are never meaningful on this
        # zone type. Strip unconditionally — this is an invariant of the
        # zone type, not a provider limitation gated by strict_supports.
        root_ns = desired.root_ns
        if root_ns is not None:
            self.log.warning(
                'root NS record %s not applicable to internal zone '
                '(internal zones have no nameservers); omitting',
                root_ns.fqdn,
            )
            desired.remove_record(root_ns)
        return super()._process_desired_zone(desired)

    def _ensure_zone(self, plan):
        zone_name = plan.desired.name
        if zone_name in self.zones:
            return
        raise CloudflareInternalProviderException(
            f'{self.id}: internal zone {zone_name!r} not found in account '
            f'{self.account_id!r} (view_id={self.view_id!r}). Create the '
            'zone in Cloudflare first; CloudflareInternalProvider does '
            'not auto-create internal zones.'
        )
