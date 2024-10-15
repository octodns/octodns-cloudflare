#
#
#

from octodns.processor.base import BaseProcessor, ProcessorException

from octodns_cloudflare import CloudflareProvider


class ProxyCNAMEException(ProcessorException):
    pass


class ProxyCNAME(BaseProcessor):
    '''
    Replace Cloudflare proxied values on non Cloudflare providers with the relevant .cdn.cloudflare.net. CNAME / ALIAS value.

    Example usage:

    processors:
        proxy-cname:
            class: octodns_cloudflare.processor.proxycname.ProxyCNAME

    ...

    zones:
        example.com.:
            sources:
                - zones
            processors:
                - proxy-cname
            targets:
                - cloudflare
                - ns1
    '''

    def process_source_and_target_zones(self, desired, existing, target):

        # Check if zone is destined for Cloudflare
        if isinstance(target, CloudflareProvider):
            # If it is then dont bother with any processing just return now
            return desired, existing

        for record in desired.records:
            # Check the record is NOT Cloudflare proxied OR is a non Cloudflare proxyable record type
            # https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/#record-types
            # NOTE: Inclusion of ALIAS as this is generally a CNAME equivalent that can be used at the root
            if not record.octodns.get('cloudflare', {}).get(
                'proxied', False
            ) or record._type not in ['ALIAS', 'A', 'AAAA', 'CNAME']:
                # Not interested in this record.
                continue

            # Remove record
            desired.remove_record(record)

            # Root
            if record.name == "":
                # Replace with ALIAS
                type = "ALIAS"

            # NOT Root
            else:
                # Replace with CNAME
                type = "CNAME"

            # Create new record
            # NOTE: New record created instead of doing a .copy() and update as record requires change of type
            new = record.new(
                desired,
                record.name,
                {
                    'type': type,
                    'ttl': record.ttl,
                    'value': (f"{record.fqdn}cdn.cloudflare.net."),
                },  # Set the value to Cloudflare CDN value e.g www.example.com.cdn.cloudflare.net.
            )

            # Replace the record
            # NOTE: lenient=True is required here even though coexisting CNAMEs should not exist
            desired.add_record(new, replace=True, lenient=True)

        return desired, existing
