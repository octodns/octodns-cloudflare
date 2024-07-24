## v0.0.? - 2024-??-?? - ???

* Create DS records after their sibling NS records to appease Cloudflare's
  validations

## v0.0.6 - 2024-05-22 - Deal with unknowns and make more knowns

* Fix handling of unsupported record types during apply
* DS record type support

## v0.0.5 - 2024-04-15 - Comment on your proxying and ttls

* TtlToProxy processor added to enable the proxied flag based on a sentinel
  ttl value. Useful when the source is not YamlProvider
* Add support for comments & tags via octodns.cloudflare.comment|tags
* ProxyCNAME processor added to aid in supporting Cloudflare prixed values
  with non-Cloudflare DNS providers by directing them to the relevant
  .cdn.cloudflare.net. CNAME / ALIAS value.

## v0.0.4 - 2024-02-08 - Know your zones

* Support for Provider.list_zones to enable dynamic zone config when operating
  as a source
* Support for auto-ttl without proxied as records can be configured that way,
  see auto-ttl in README.md for more info
* Fix bug in handling of empty strings/content on TXT records
* Make the minumum supported TTL configurable.

## v0.0.3 - 2023-09-20 - All the commits fit to release

* SPF records can no longer be created,
  https://github.com/octodns/octodns-cloudflare/issues/28
* NAPTR and SSHFP support added
* All HTTP requests include a meaningful user-agent.
* AccountID filter support
* API token auth method/doc

## v0.0.2 - 2022-12-25 - Holiday Edition

* Added support for TLSA record type
* Switched to pytest and updated everything to latest template setup

## v0.0.1 - 2022-01-05 - Moving

#### Nothworthy Changes

* Initial extraction of CloudflareProvider from octoDNS core

#### Stuff

Nothing
